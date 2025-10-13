#!/usr/bin/env python3
"""
Aqua Repository Delete Utility
A focused tool for bulk deletion of image repositories from Aqua Security platform

Usage:
    python aqua_repo_delete.py setup                           # Interactive setup
    python aqua_repo_delete.py repos delete                    # List what would be deleted (dry-run mode)
    python aqua_repo_delete.py repos delete --apply            # Actually delete repositories
    python aqua_repo_delete.py repos delete --registry NAME    # Filter by registry name
    python aqua_repo_delete.py repos delete --host-images      # Delete Host Images repositories
    python aqua_repo_delete.py repos delete --empty-only       # Delete only empty repositories
"""

import argparse
import json
import sys
import os
from prettytable import PrettyTable

# Import from aquasec library
from aquasec import (
    authenticate,
    load_profile_credentials,
    interactive_setup,
    list_profiles,
    ConfigManager,
    get_profile_info,
    get_all_profiles_info,
    format_profile_info,
    delete_profile_with_result,
    set_default_profile_with_result,
    profile_not_found_response,
    profile_operation_response,
    api_get_repositories,
    api_delete_repo
)

# Version
__version__ = "0.1.2"


def repos_delete(server, token, registry=None, empty_only=False, apply=False, verbose=False, debug=False):
    """Delete repositories with safety-first approach"""

    deleted_count = 0
    total_count = 0
    failed_count = 0
    deletions = []
    failures = []
    verbose_items = []  # Collect items for table display

    page = 1
    page_size = 200

    if debug:
        print(f"DEBUG: Starting repository deletion - registry={registry}, empty_only={empty_only}, apply={apply}")

    while True:
        # Get repositories for this page
        if debug:
            print(f"DEBUG: Fetching page {page} with size {page_size}")

        res = api_get_repositories(server, token, page, page_size, registry=registry, verbose=debug)

        if res.status_code != 200:
            error_msg = f"API call failed with status {res.status_code}: {res.text}"
            if verbose:
                print(f"Error: {error_msg}")
            else:
                print(json.dumps({"error": error_msg}))
            sys.exit(1)

        data = res.json()
        repos = data.get("result", [])

        if not repos:
            break

        total_count += len(repos)

        # Process each repository
        for repo in repos:
            repo_name = repo.get("name", "")
            repo_registry = repo.get("registry", "")
            num_images = repo.get("num_images", 0)

            # Apply empty-only filter if specified
            if empty_only and num_images > 0:
                continue

            # Record what would be/was deleted
            repo_info = {
                "registry": repo_registry,
                "name": repo_name,
                "num_images": num_images
            }

            if apply:
                # Actually delete the repository
                if debug:
                    print(f"DEBUG: Deleting {repo_registry}/{repo_name}")

                delete_res = api_delete_repo(server, token, repo_registry, repo_name, verbose=debug)

                if delete_res.status_code in [200, 202, 204]:  # 202 = Accepted (async delete)
                    deleted_count += 1
                    deletions.append(repo_info)
                    if verbose:
                        verbose_items.append(("✓", f"{repo_registry}/{repo_name}", num_images))
                else:
                    failed_count += 1
                    failure_info = repo_info.copy()
                    failure_info["error"] = f"HTTP {delete_res.status_code}: {delete_res.text}"
                    failures.append(failure_info)
                    if verbose:
                        verbose_items.append(("✗", f"{repo_registry}/{repo_name}", f"Error: {failure_info['error']}"))
            else:
                # Dry run mode - just record what would be deleted
                deleted_count += 1
                deletions.append(repo_info)
                if verbose:
                    verbose_items.append(("", f"{repo_registry}/{repo_name}", num_images))

        # Check for more pages
        total_available = data.get("count", 0)
        if len(repos) < page_size or page * page_size >= total_available:
            break

        page += 1

    # Prepare output
    result = {
        "mode": "apply" if apply else "dry_run",
        "summary": {
            "repositories_scanned": total_count,
            "repositories_deleted" if apply else "repositories_would_delete": deleted_count,
            "repositories_failed": failed_count if apply else 0
        },
        "filters": {
            "registry": registry,
            "empty_only": empty_only
        },
        "deletions": deletions
    }

    if apply and failures:
        result["failures"] = failures

    if verbose:
        # Show repositories table first
        if verbose_items:
            repo_table = PrettyTable(["Status", "Repository", "Images"])
            repo_table.align["Status"] = "c"
            repo_table.align["Repository"] = "l"
            repo_table.align["Images"] = "r"

            header_text = "\nDeleting repositories:" if apply else "\nRepositories that would be deleted:"
            print(header_text)

            for status, repo_name, images in verbose_items:
                if isinstance(images, int):
                    image_text = f"{images}"
                else:
                    image_text = str(images)  # For error messages
                repo_table.add_row([status, repo_name, image_text])

            print(repo_table)

        # Show summary table
        table = PrettyTable(["Metric", "Count"])
        table.align["Metric"] = "l"
        table.align["Count"] = "r"

        table.add_row(["Repositories Scanned", total_count])
        table.add_row(["Repositories " + ("Deleted" if apply else "To Delete"), deleted_count])
        if apply and failed_count > 0:
            table.add_row(["Repositories Failed", failed_count])

        print("\nSummary:")
        print(table)

        # Show filters applied
        if registry or empty_only:
            print("\nFilters Applied:")
            filter_table = PrettyTable(["Filter", "Value"])
            filter_table.align["Filter"] = "l"
            filter_table.align["Value"] = "l"

            if registry:
                filter_table.add_row(["Registry", registry])
            if empty_only:
                filter_table.add_row(["Empty Only", "Yes"])

            print(filter_table)

        # Show status
        mode_status = "APPLIED - Repositories were actually deleted!" if apply else "DRY RUN - No repositories were actually deleted"
        print(f"\nMode: {mode_status}")

        if not apply and deleted_count > 0:
            print("Use --apply flag to actually perform the deletions.")
    else:
        # JSON output
        print(json.dumps(result, indent=2))


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
                i += 1  # Skip the profile value
        else:
            filtered_args.append(arg)
        i += 1

    # Now parse with the filtered args
    parser = argparse.ArgumentParser(
        description='Aqua Repository Delete Utility - Bulk delete image repositories from Aqua Security platform',
        prog='aqua_repo_delete',
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

    # Repository commands
    repos_parser = subparsers.add_parser('repos', help='Repository management commands')
    repos_subparsers = repos_parser.add_subparsers(dest='repos_command', help='Repository commands', required=True)

    # Delete subcommand
    delete_parser = repos_subparsers.add_parser('delete', help='Delete repositories (dry-run by default)')
    delete_parser.add_argument('--apply', action='store_true',
                              help='Actually perform deletions (default is dry-run mode)')
    delete_parser.add_argument('--registry',
                              help='Filter by registry name')
    delete_parser.add_argument('--host-images', action='store_true',
                              help='Filter for Host Images registry (equivalent to --registry "Host Images")')
    delete_parser.add_argument('--empty-only', action='store_true',
                              help='Delete only repositories with 0 images')

    # Parse arguments
    args = parser.parse_args(filtered_args)

    # Handle --host-images flag
    if hasattr(args, 'host_images') and args.host_images:
        if args.registry:
            print("Error: Cannot use both --registry and --host-images flags together")
            sys.exit(1)
        args.registry = "Host Images"

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
        if args.command == 'repos' and args.repos_command == 'delete':
            if args.debug:
                print(f"DEBUG: Using CSP endpoint: {csp_endpoint}")

            repos_delete(csp_endpoint, token,
                        registry=args.registry,
                        empty_only=args.empty_only,
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
        from cryptography.fernet import Fernet
    except ImportError:
        print("Missing required dependency: cryptography")
        print("Install with: pip install cryptography")
        sys.exit(1)

    main()