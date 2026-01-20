#!/usr/bin/env python3
"""
Aqua Image Cleanup Utility
Clean up stale images from Aqua Security Hub inventory

Usage:
    python aqua_image_cleanup.py setup                           # Interactive setup
    python aqua_image_cleanup.py images cleanup --file FILE      # Delete images from CSV file
    python aqua_image_cleanup.py images cleanup --file FILE --apply  # Actually remove images
    python aqua_image_cleanup.py images cleanup                  # Preview cleanup from API (dry-run mode)
    python aqua_image_cleanup.py images cleanup --apply          # Actually remove images from API
    python aqua_image_cleanup.py images cleanup --days 180       # Custom age threshold
    python aqua_image_cleanup.py images cleanup --registry NAME  # Filter by registry name
    python aqua_image_cleanup.py images cleanup --scope NAME     # Filter by scope
"""

import argparse
import csv
import json
import sys
import os

# Import from aquasec library
from aquasec import (
    authenticate,
    load_profile_credentials,
    interactive_setup,
    list_profiles,
    get_profile_info,
    get_all_profiles_info,
    format_profile_info,
    delete_profile_with_result,
    set_default_profile_with_result,
    profile_not_found_response,
    profile_operation_response,
    api_get_inventory_images,
    api_delete_images
)

# Version
__version__ = "0.1.0"


def images_cleanup(server, token, days=90, registry=None, scope=None, apply=False, verbose=False, debug=False):
    """Clean up stale images with safety-first approach using per-page batching"""

    deleted_count = 0
    total_count = 0
    failed_count = 0
    deletions = []
    failures = []

    page = 1
    page_size = 200
    first_found_date = f"over|{days}|days"

    if debug:
        print(f"DEBUG: Starting image cleanup - days={days}, registry={registry}, scope={scope}, apply={apply}")

    # Print header for real-time output in verbose mode
    if verbose:
        header = "Removing images:" if apply else "Images that would be removed:"
        print(f"\n{header}")

    while True:
        if debug:
            print(f"DEBUG: Fetching page {page} with page_size={page_size}")

        res = api_get_inventory_images(
            server, token,
            page=page,
            page_size=page_size,
            scope=scope,
            first_found_date=first_found_date,
            has_workloads=False,
            registry_name=registry,
            verbose=debug
        )

        if res.status_code != 200:
            error_msg = f"API call failed with status {res.status_code}: {res.text}"
            if verbose:
                print(f"Error: {error_msg}")
            else:
                print(json.dumps({"error": error_msg}))
            sys.exit(1)

        data = res.json()
        images = data.get("result", [])

        if not images:
            break

        total_count += len(images)

        if verbose:
            print(f"  Processing page {page} ({len(images)} images)...")

        # Collect UIDs for this batch
        batch_uids = []
        batch_images = []

        for img in images:
            image_uid = img.get("image_uid")
            image_name = img.get("name", "")
            image_registry = img.get("registry", "")
            image_repo = img.get("repository", "")
            image_tag = img.get("tag", "")

            if not image_uid:
                if debug:
                    print(f"DEBUG: Skipping image without UID: {image_name}")
                continue

            img_info = {
                "image_uid": image_uid,
                "registry": image_registry,
                "repository": image_repo,
                "tag": image_tag,
                "name": image_name
            }

            batch_uids.append(image_uid)
            batch_images.append(img_info)

        if apply and batch_uids:
            # Actually delete this batch
            if debug:
                print(f"DEBUG: Calling POST /api/v2/images/actions/delete with {len(batch_uids)} UIDs")

            delete_res = api_delete_images(server, token, batch_uids, verbose=debug)

            if delete_res.status_code in [200, 202, 204]:
                deleted_count += len(batch_uids)
                deletions.extend(batch_images)
                if verbose:
                    for img_info in batch_images:
                        display_name = f"{img_info['registry']}/{img_info['repository']}:{img_info['tag']}"
                        print(f"    ✓ {display_name}")
            else:
                failed_count += len(batch_uids)
                error_text = f"HTTP {delete_res.status_code}: {delete_res.text}"
                for img_info in batch_images:
                    failure_info = img_info.copy()
                    failure_info["error"] = error_text
                    failures.append(failure_info)
                if verbose:
                    for img_info in batch_images:
                        display_name = f"{img_info['registry']}/{img_info['repository']}:{img_info['tag']}"
                        print(f"    ✗ {display_name} - {error_text}")
        else:
            # Dry run mode - just record what would be deleted
            deleted_count += len(batch_uids)
            deletions.extend(batch_images)
            if verbose:
                for img_info in batch_images:
                    display_name = f"{img_info['registry']}/{img_info['repository']}:{img_info['tag']}"
                    print(f"    - {display_name}")

        # In apply mode, stay on page 1 since deletions shift the list
        # In dry-run mode, paginate normally
        if not apply:
            page += 1

    # Prepare output
    result = {
        "mode": "apply" if apply else "dry_run",
        "summary": {
            "images_scanned": total_count,
            "images_deleted" if apply else "images_would_delete": deleted_count,
            "images_failed": failed_count if apply else 0
        },
        "filters": {
            "days": days,
            "registry": registry,
            "scope": scope,
            "has_workloads": False
        },
        "deletions": deletions
    }

    if apply and failures:
        result["failures"] = failures

    if verbose:
        # Show summary
        print(f"\nSummary:")
        print(f"  Images scanned: {total_count}")
        print(f"  Images {'removed' if apply else 'to remove'}: {deleted_count}")
        if apply and failed_count > 0:
            print(f"  Images failed: {failed_count}")

        # Show filters applied
        print(f"\nFilters: age >{days} days, has_workloads=false", end="")
        if registry:
            print(f", registry={registry}", end="")
        if scope:
            print(f", scope={scope}", end="")
        print()

        # Show status
        if apply:
            print(f"\nMode: APPLIED - Images were actually removed!")
        else:
            print(f"\nMode: DRY RUN - No images were actually removed")
            if deleted_count > 0:
                print("Use --apply flag to actually perform the cleanup.")
    else:
        # JSON output
        print(json.dumps(result, indent=2))


def images_cleanup_from_file(server, token, file_path, batch_size=200, apply=False, verbose=False, debug=False):
    """Clean up images from a CSV file with batched deletion

    CSV format expected: image_id,image_name,registry_id,created
    Where image_name is in format: repository:tag
    """

    deleted_count = 0
    total_count = 0
    failed_count = 0
    deletions = []
    failures = []

    if debug:
        print(f"DEBUG: Starting file-based cleanup - file={file_path}, batch_size={batch_size}, apply={apply}")

    # Verify file exists
    if not os.path.exists(file_path):
        error_msg = f"File not found: {file_path}"
        if verbose:
            print(f"Error: {error_msg}")
        else:
            print(json.dumps({"error": error_msg}))
        sys.exit(1)

    # Print header for real-time output in verbose mode
    if verbose:
        header = "Removing images:" if apply else "Images that would be removed:"
        print(f"\n{header}")

    # Read and process CSV file
    batch_ids = []
    batch_images = []

    with open(file_path, 'r', newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)

        for row in reader:
            total_count += 1

            # Extract fields from CSV
            # CSV columns: image_id, image_name, registry_id, created
            image_id_str = row.get('image_id', '').strip()
            image_name = row.get('image_name', '').strip()
            registry_id = row.get('registry_id', '').strip()

            if not image_id_str:
                if debug:
                    print(f"DEBUG: Skipping row without image_id: {row}")
                continue

            # Convert image_id to integer (API expects int64)
            try:
                image_id = int(image_id_str)
            except ValueError:
                if debug:
                    print(f"DEBUG: Skipping row with non-integer image_id: {image_id_str}")
                continue

            # Parse image_name (format: repository:tag)
            if ':' in image_name:
                repo_parts = image_name.rsplit(':', 1)
                repository = repo_parts[0]
                tag = repo_parts[1]
            else:
                repository = image_name
                tag = ''

            img_info = {
                "image_id": image_id,
                "registry": registry_id,
                "repository": repository,
                "tag": tag,
                "name": image_name
            }

            batch_ids.append(image_id)
            batch_images.append(img_info)

            # Process batch when it reaches batch_size
            if len(batch_ids) >= batch_size:
                deleted, failed, del_list, fail_list = _process_batch(
                    server, token, batch_ids, batch_images, apply, verbose, debug
                )
                deleted_count += deleted
                failed_count += failed
                deletions.extend(del_list)
                failures.extend(fail_list)

                batch_ids = []
                batch_images = []

                if debug:
                    print(f"DEBUG: Processed {total_count} images so far...")

    # Process remaining batch
    if batch_ids:
        deleted, failed, del_list, fail_list = _process_batch(
            server, token, batch_ids, batch_images, apply, verbose, debug
        )
        deleted_count += deleted
        failed_count += failed
        deletions.extend(del_list)
        failures.extend(fail_list)

    # Prepare output
    result = {
        "mode": "apply" if apply else "dry_run",
        "source": "file",
        "file": file_path,
        "summary": {
            "images_scanned": total_count,
            "images_deleted" if apply else "images_would_delete": deleted_count,
            "images_failed": failed_count if apply else 0
        },
        "deletions": deletions
    }

    if apply and failures:
        result["failures"] = failures

    if verbose:
        # Show summary
        print(f"\nSummary:")
        print(f"  Images scanned: {total_count}")
        print(f"  Images {'removed' if apply else 'to remove'}: {deleted_count}")
        if apply and failed_count > 0:
            print(f"  Images failed: {failed_count}")

        print(f"\nSource: {file_path}")

        # Show status
        if apply:
            print(f"\nMode: APPLIED - Images were actually removed!")
        else:
            print(f"\nMode: DRY RUN - No images were actually removed")
            if deleted_count > 0:
                print("Use --apply flag to actually perform the cleanup.")
    else:
        # JSON output
        print(json.dumps(result, indent=2))


def _process_batch(server, token, batch_ids, batch_images, apply, verbose, debug):
    """Process a batch of images for deletion"""

    deleted_count = 0
    failed_count = 0
    deletions = []
    failures = []

    if apply and batch_ids:
        # Actually delete this batch
        if debug:
            print(f"DEBUG: Calling POST /api/v2/images/actions/delete with {len(batch_ids)} IDs")

        delete_res = api_delete_images(server, token, batch_ids, verbose=debug)

        if delete_res.status_code in [200, 202, 204]:
            deleted_count = len(batch_ids)
            deletions = batch_images.copy()
            if verbose:
                for img_info in batch_images:
                    display_name = f"{img_info['registry']}/{img_info['repository']}:{img_info['tag']}"
                    print(f"    ✓ {display_name}")
        else:
            failed_count = len(batch_ids)
            error_text = f"HTTP {delete_res.status_code}: {delete_res.text}"
            for img_info in batch_images:
                failure_info = img_info.copy()
                failure_info["error"] = error_text
                failures.append(failure_info)
            if verbose:
                for img_info in batch_images:
                    display_name = f"{img_info['registry']}/{img_info['repository']}:{img_info['tag']}"
                    print(f"    ✗ {display_name} - {error_text}")
    else:
        # Dry run mode - just record what would be deleted
        deleted_count = len(batch_ids)
        deletions = batch_images.copy()
        if verbose:
            for img_info in batch_images:
                display_name = f"{img_info['registry']}/{img_info['repository']}:{img_info['tag']}"
                print(f"    - {display_name}")

    return deleted_count, failed_count, deletions, failures


def main():
    """Main function"""
    # Disable SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Custom argument parsing to support global options anywhere
    raw_args = sys.argv[1:]

    # Extract global arguments regardless of position
    global_args = {'verbose': False, 'debug': False, 'profile': 'default'}
    filtered_args = []
    i = 0

    while i < len(raw_args):
        arg = raw_args[i]
        if arg in ['-v', '--verbose']:
            global_args['verbose'] = True
        elif arg in ['-d', '--debug']:
            global_args['debug'] = True
        elif arg in ['-p', '--profile']:
            if i + 1 < len(raw_args):
                global_args['profile'] = raw_args[i + 1]
                i += 1
        else:
            filtered_args.append(arg)
        i += 1

    # Now parse with the filtered args
    parser = argparse.ArgumentParser(
        description='Aqua Image Cleanup Utility - Clean up stale images from Aqua Security Hub inventory',
        prog='aqua_image_cleanup',
        epilog='Global options can be placed before or after the command:\n'
               '  -v, --verbose        Show human-readable output instead of JSON\n'
               '  -d, --debug          Show debug output including API calls\n'
               '  -p, --profile        Configuration profile to use (default: default)\n'
               '  --version            Show program version',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Add global arguments
    parser.add_argument('-v', '--verbose', action='store_true',
                       default=global_args['verbose'],
                       help='Show human-readable output instead of JSON')
    parser.add_argument('-d', '--debug', action='store_true',
                       default=global_args['debug'],
                       help='Show debug output including API calls')
    parser.add_argument('-p', '--profile', default=global_args['profile'],
                       help='Configuration profile to use (default: default)')
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')

    # Create subparsers for commands
    subparsers = parser.add_subparsers(dest='command', help='Available commands', required=True)

    # Setup command
    setup_parser = subparsers.add_parser('setup', help='Interactive setup for credentials')

    # Profile management commands
    profile_parser = subparsers.add_parser('profile', help='Profile management commands')
    profile_subparsers = profile_parser.add_subparsers(dest='profile_command', help='Profile commands', required=True)

    profile_subparsers.add_parser('list', help='List all profiles')

    profile_info_parser = profile_subparsers.add_parser('info', help='Show profile information')
    profile_info_parser.add_argument('profile_name', nargs='?', help='Profile name (default: show all)')

    profile_delete_parser = profile_subparsers.add_parser('delete', help='Delete a profile')
    profile_delete_parser.add_argument('profile_name', help='Profile name to delete')

    profile_default_parser = profile_subparsers.add_parser('set-default', help='Set default profile')
    profile_default_parser.add_argument('profile_name', help='Profile name to set as default')

    # Images commands
    images_parser = subparsers.add_parser('images', help='Image management commands')
    images_subparsers = images_parser.add_subparsers(dest='images_command', help='Image commands', required=True)

    # Cleanup subcommand
    cleanup_parser = images_subparsers.add_parser('cleanup', help='Clean up stale images (dry-run by default)')
    cleanup_parser.add_argument('--apply', action='store_true',
                              help='Actually perform cleanup (default is dry-run mode)')
    cleanup_parser.add_argument('--file',
                              help='CSV file with image list (columns: image_id,image_name,registry_id,created)')
    cleanup_parser.add_argument('--batch-size', type=int, default=200,
                              help='Batch size for deletion (default: 200, only used with --file)')
    cleanup_parser.add_argument('--days', type=int, default=90,
                              help='Age threshold in days (default: 90, only used without --file)')
    cleanup_parser.add_argument('--registry',
                              help='Filter by registry name (only used without --file)')
    cleanup_parser.add_argument('--scope',
                              help='Filter by scope name (only used without --file)')

    # Parse arguments
    args = parser.parse_args(filtered_args)

    # Handle setup command
    if args.command == 'setup':
        try:
            interactive_setup(debug=args.debug)
        except KeyboardInterrupt:
            if args.verbose:
                print('\nSetup cancelled by user')
            sys.exit(0)
        except Exception as e:
            if args.verbose:
                print(f"Setup failed: {e}")
            else:
                print(json.dumps({"error": f"Setup failed: {str(e)}"}))
            sys.exit(1)
        return

    # Handle profile commands
    if args.command == 'profile':
        try:
            if args.profile_command == 'list':
                result = list_profiles()
                if args.verbose:
                    print(f"Available profiles: {', '.join(result)}")
                else:
                    print(json.dumps({"profiles": result}))

            elif args.profile_command == 'info':
                if args.profile_name:
                    result = get_profile_info(args.profile_name)
                    if result is None:
                        response = profile_not_found_response(args.profile_name)
                    else:
                        response = format_profile_info(args.profile_name, result)
                else:
                    result = get_all_profiles_info()
                    response = format_profile_info(None, result)

                if args.verbose:
                    print(response["message"])
                else:
                    print(json.dumps(response))

            elif args.profile_command == 'delete':
                result = delete_profile_with_result(args.profile_name)
                response = profile_operation_response(result, args.profile_name, "delete")

                if args.verbose:
                    print(response["message"])
                else:
                    print(json.dumps(response))

            elif args.profile_command == 'set-default':
                result = set_default_profile_with_result(args.profile_name)
                response = profile_operation_response(result, args.profile_name, "set-default")

                if args.verbose:
                    print(response["message"])
                else:
                    print(json.dumps(response))

        except KeyboardInterrupt:
            if args.verbose:
                print('\nOperation cancelled by user')
            sys.exit(0)
        except Exception as e:
            if args.verbose:
                print(f"Profile operation failed: {e}")
            else:
                print(json.dumps({"error": f"Profile operation failed: {str(e)}"}))
            sys.exit(1)
        return

    # For other commands, we need authentication
    try:
        # Load profile credentials
        result = load_profile_credentials(args.profile)
        if isinstance(result, tuple):
            profile_loaded, actual_profile = result
        else:
            profile_loaded = result
            actual_profile = args.profile

        if not profile_loaded:
            if args.verbose:
                print(f"Failed to load profile '{args.profile}'. Use 'setup' command to configure credentials.")
            else:
                print(json.dumps({"error": f"Failed to load profile '{args.profile}'"}))
            sys.exit(1)

        if args.debug:
            print(f"DEBUG: Using profile: {actual_profile}")

        # Authenticate
        token = authenticate(verbose=args.debug)
        if not token:
            if args.verbose:
                print("Authentication failed")
            else:
                print(json.dumps({"error": "Authentication failed"}))
            sys.exit(1)

        if args.debug:
            print("DEBUG: Authentication successful!\n")
    except Exception as e:
        if args.verbose:
            print(f"Authentication failed: {e}")
        else:
            print(json.dumps({"error": f"Authentication failed: {str(e)}"}))
        sys.exit(1)

    # Get CSP endpoint from environment
    csp_endpoint = os.environ.get('CSP_ENDPOINT')

    if not csp_endpoint:
        if args.verbose:
            print("Error: CSP_ENDPOINT environment variable not set")
        else:
            print(json.dumps({"error": "CSP_ENDPOINT environment variable not set"}))
        sys.exit(1)

    # Execute commands
    try:
        if args.command == 'images' and args.images_command == 'cleanup':
            if args.debug:
                print(f"DEBUG: Using CSP endpoint: {csp_endpoint}")

            if args.file:
                # File-based cleanup (bypasses API inventory extraction)
                images_cleanup_from_file(csp_endpoint, token,
                                        file_path=args.file,
                                        batch_size=args.batch_size,
                                        apply=args.apply,
                                        verbose=args.verbose,
                                        debug=args.debug)
            else:
                # API-based cleanup (original behavior)
                images_cleanup(csp_endpoint, token,
                              days=args.days,
                              registry=args.registry,
                              scope=args.scope,
                              apply=args.apply,
                              verbose=args.verbose,
                              debug=args.debug)
    except KeyboardInterrupt:
        if args.verbose:
            print('\nExecution interrupted by user')
        sys.exit(0)
    except Exception as e:
        if args.verbose:
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()
        else:
            print(json.dumps({"error": str(e)}))
        sys.exit(1)


if __name__ == '__main__':
    # Check for required dependencies
    try:
        import cryptography  # noqa: F401
    except ImportError:
        print("Missing required dependency: cryptography")
        print("Install with: pip install cryptography")
        sys.exit(1)

    main()
