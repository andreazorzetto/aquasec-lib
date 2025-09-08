#!/usr/bin/env python3
"""
Aqua Repository Breakdown Utility
A focused tool for analyzing repository scope assignments and identifying orphaned repositories

Usage:
    python aqua_repo_breakdown.py setup                  # Interactive setup
    python aqua_repo_breakdown.py repo list              # List all repositories
    python aqua_repo_breakdown.py repo list --orphan     # List orphaned repos only
    python aqua_repo_breakdown.py repo breakdown         # Show scope analysis
"""

import argparse
import json
import sys
import os
from prettytable import PrettyTable

# Import from aquasec library
from aquasec import (
    authenticate,
    api_get_repositories,
    get_all_repositories,
    get_app_scopes,
    write_json_to_file,
    write_content_to_file,
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
    profile_operation_response
)

# Version
__version__ = "0.1.1"


def build_repository_scope_map(server, token, verbose=False, debug=False):
    """Build complete map of repositories and their scopes"""
    repo_map = {}
    
    if verbose:
        print("Building repository scope map...")
        print("Step 1: Fetching all repositories...")
    
    # Step 1: Get all repositories (these all implicitly have Global)
    try:
        all_repos = get_all_repositories(server, token, verbose=debug)
        
        for repo in all_repos:
            # Create unique key from registry and name
            registry = repo.get('registry', 'unknown')
            name = repo.get('name', 'unknown')
            key = f"{registry}/{name}"
            
            repo_map[key] = {
                "data": repo,
                "scopes": ["Global"]  # Start with Global
            }
        
        if verbose:
            print(f"Found {len(all_repos)} total repositories")
            print("Step 2: Fetching application scopes...")
    
    except Exception as e:
        if verbose:
            print(f"Error fetching repositories: {e}")
        raise
    
    # Step 2: Get all application scopes (excluding Global)
    try:
        all_scopes = get_app_scopes(server, token, debug)
        app_scopes = [s for s in all_scopes if s.get("name") != "Global"]
        
        if verbose:
            print(f"Found {len(app_scopes)} application scopes")
            print("Step 3: Checking repositories in each scope...")
    
    except Exception as e:
        if verbose:
            print(f"Error fetching scopes: {e}")
        raise
    
    # Step 3: For each app scope, get repos and add scope
    for i, scope in enumerate(app_scopes):
        scope_name = scope.get("name")
        
        if verbose:
            print(f"  Checking scope {i+1}/{len(app_scopes)}: {scope_name}")
        
        try:
            scope_repos = get_all_repositories(server, token, scope=scope_name, verbose=debug)
            
            for repo in scope_repos:
                registry = repo.get('registry', 'unknown')
                name = repo.get('name', 'unknown')
                key = f"{registry}/{name}"
                
                if key in repo_map:
                    if scope_name not in repo_map[key]["scopes"]:
                        repo_map[key]["scopes"].append(scope_name)
                else:
                    # This shouldn't happen, but handle it gracefully
                    if debug:
                        print(f"WARNING: Repository {key} found in scope {scope_name} but not in all repos list")
            
            if debug:
                print(f"    Found {len(scope_repos)} repositories in {scope_name}")
                
        except Exception as e:
            if verbose:
                print(f"  Error fetching repositories for scope {scope_name}: {e}")
            # Continue with other scopes
    
    if verbose:
        orphaned = sum(1 for v in repo_map.values() if v["scopes"] == ["Global"])
        print(f"\nScope mapping complete:")
        print(f"  Total repositories: {len(repo_map)}")
        print(f"  Orphaned repositories: {orphaned}")
        print(f"  Repositories with app scopes: {len(repo_map) - orphaned}")
    
    return repo_map


def filter_repositories(repo_map, filter_type="all", scope_name=None):
    """Filter repositories based on criteria"""
    if filter_type == "orphaned":
        # Only repos with just Global scope
        return {k: v for k, v in repo_map.items() if v["scopes"] == ["Global"]}
    elif filter_type == "scope" and scope_name:
        # Repos belonging to specific scope
        return {k: v for k, v in repo_map.items() if scope_name in v["scopes"]}
    else:
        # All repos
        return repo_map


def repo_list(server, token, verbose=False, debug=False, scope=None, 
              registry=None, orphan=False, all_scopes=False):
    """List repositories with various filtering options"""
    
    # If we need complete scope mapping (orphan detection or showing all scopes)
    if orphan or all_scopes:
        # Build complete repository map with scope information
        repo_map = build_repository_scope_map(server, token, verbose, debug)
        
        # Apply filters
        if orphan:
            filtered = filter_repositories(repo_map, "orphaned")
        else:
            filtered = repo_map
        
        # Format output
        if verbose:
            # Table format
            table = PrettyTable()
            if all_scopes:
                table.field_names = ["Repository", "Registry", "Scopes", "# Scopes"]
                table.align["Repository"] = "l"
                table.align["Registry"] = "l"
                table.align["Scopes"] = "l"
                table.align["# Scopes"] = "r"
            else:
                table.field_names = ["Repository", "Registry"]
                table.align["Repository"] = "l"
                table.align["Registry"] = "l"
            
            # Sort by repository name for consistent output
            sorted_items = sorted(filtered.items(), key=lambda x: x[1]["data"].get("name", ""))
            
            for key, value in sorted_items:
                repo = value["data"]
                if all_scopes:
                    scopes_str = ", ".join(sorted(value["scopes"]))
                    table.add_row([
                        repo.get('name', 'N/A'),
                        repo.get('registry', 'N/A'),
                        scopes_str,
                        len(value["scopes"])
                    ])
                else:
                    table.add_row([
                        repo.get('name', 'N/A'),
                        repo.get('registry', 'N/A')
                    ])
            
            print(table)
            print(f"\nTotal repositories: {len(filtered)}")
            
            if orphan:
                print("(Showing only orphaned repositories - those without application scope assignments)")
        else:
            # JSON format
            output = {
                "count": len(filtered),
                "repositories": []
            }
            
            # Sort for consistent output
            sorted_items = sorted(filtered.items(), key=lambda x: x[1]["data"].get("name", ""))
            
            for key, value in sorted_items:
                repo_data = value["data"].copy()
                repo_data["scopes"] = value["scopes"]
                output["repositories"].append(repo_data)
            
            print(json.dumps(output, indent=2))
    elif scope and scope != "Global":
        # Efficient path: Direct API call with scope filter
        try:
            if verbose:
                print(f"Fetching repositories in scope: {scope}...")
            
            # Get repositories filtered by scope - much more efficient
            repos = get_all_repositories(server, token, scope=scope, registry=registry, verbose=debug)
            
            if verbose:
                # Human-readable table format
                if repos:
                    table = PrettyTable()
                    table.field_names = ["Repository", "Registry"]
                    table.align["Repository"] = "l"
                    table.align["Registry"] = "l"
                    
                    # Sort by name
                    sorted_repos = sorted(repos, key=lambda x: x.get("name", ""))
                    
                    for repo in sorted_repos:
                        table.add_row([
                            repo.get('name', 'N/A'),
                            repo.get('registry', 'N/A')
                        ])
                    
                    print(table)
                    print(f"\nTotal repositories in scope '{scope}': {len(repos)}")
                else:
                    print(f"No repositories found in scope '{scope}'")
            else:
                # JSON output
                output = {
                    "scope": scope,
                    "count": len(repos),
                    "repositories": sorted(repos, key=lambda x: x.get("name", ""))
                }
                print(json.dumps(output, indent=2))
                
        except Exception as e:
            if verbose:
                print(f"Error fetching repositories for scope {scope}: {e}")
            else:
                print(json.dumps({"error": str(e)}))
    else:
        # Simple listing without scope analysis (default behavior)
        try:
            if verbose:
                print("Fetching repositories...")
            
            # Get all repositories (or filtered by registry)
            repos = get_all_repositories(server, token, registry=registry, verbose=debug)
            
            if verbose:
                # Human-readable table format
                if repos:
                    table = PrettyTable()
                    table.field_names = ["Repository", "Registry"]
                    table.align["Repository"] = "l"
                    table.align["Registry"] = "l"
                    
                    # Sort by name
                    sorted_repos = sorted(repos, key=lambda x: x.get("name", ""))
                    
                    for repo in sorted_repos:
                        table.add_row([
                            repo.get('name', 'N/A'),
                            repo.get('registry', 'N/A')
                        ])
                    
                    print(table)
                    print(f"\nTotal repositories: {len(repos)}")
                else:
                    print("No repositories found")
            else:
                # JSON output
                output = {
                    "count": len(repos),
                    "repositories": sorted(repos, key=lambda x: x.get("name", ""))
                }
                print(json.dumps(output, indent=2))
                
        except Exception as e:
            if verbose:
                print(f"Error fetching repositories: {e}")
            else:
                print(json.dumps({"error": str(e)}))


def write_breakdown_to_csv(breakdown, repo_map, filename):
    """Export breakdown data to CSV file"""
    import csv
    
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        # Write summary section
        writer.writerow(["Summary"])
        writer.writerow(["Metric", "Value"])
        for key, value in breakdown["summary"].items():
            writer.writerow([key.replace("_", " ").title(), value])
        writer.writerow([])
        
        # Write scope counts
        writer.writerow(["Scope Counts"])
        writer.writerow(["Scope", "Repository Count"])
        for scope, count in sorted(breakdown["scope_counts"].items()):
            writer.writerow([scope, count])
        writer.writerow([])
        
        # Write orphaned repositories if any
        orphaned = [k for k, v in repo_map.items() if v["scopes"] == ["Global"]]
        if orphaned:
            writer.writerow(["Orphaned Repositories"])
            writer.writerow(["Registry/Repository"])
            for repo_key in sorted(orphaned):
                writer.writerow([repo_key])
    
    return filename


def repo_breakdown(server, token, verbose=False, debug=False, csv_file=None, json_file=None):
    """Comprehensive breakdown of repositories by scope"""
    
    # Build repository map
    repo_map = build_repository_scope_map(server, token, verbose, debug)
    filtered_map = repo_map
    
    # Calculate statistics
    total_repos = len(filtered_map)
    orphaned_repos = len([v for v in filtered_map.values() if v["scopes"] == ["Global"]])
    scoped_repos = total_repos - orphaned_repos
    
    # Count by individual scope
    scope_counts = {}
    for repo_data in filtered_map.values():
        for repo_scope in repo_data["scopes"]:
            scope_counts[repo_scope] = scope_counts.get(repo_scope, 0) + 1
    
    # Build breakdown data
    breakdown = {
        "summary": {
            "total_repositories": total_repos,
            "orphaned_repositories": orphaned_repos,
            "repositories_with_app_scopes": scoped_repos,
            "orphaned_percentage": round((orphaned_repos / total_repos * 100), 2) if total_repos > 0 else 0
        },
        "scope_counts": scope_counts,
        "scope_details": {}
    }
    
    # Add detailed scope membership for non-Global scopes
    for scope_name in scope_counts:
        if scope_name != "Global":
            breakdown["scope_details"][scope_name] = {
                "count": scope_counts[scope_name],
                "repositories": sorted([k for k, v in filtered_map.items() if scope_name in v["scopes"]])
            }
    
    # Add orphaned repositories list
    breakdown["orphaned_repositories"] = sorted([k for k, v in filtered_map.items() if v["scopes"] == ["Global"]])
    
    # Output handling
    if csv_file:
        # Export to CSV
        write_breakdown_to_csv(breakdown, filtered_map, csv_file)
        if verbose:
            print(f"\nBreakdown exported to CSV: {csv_file}")
    
    if json_file:
        write_json_to_file(json_file, breakdown)
        if verbose:
            print(f"Breakdown exported to JSON: {json_file}")
    
    if verbose:
        # Human-readable output
        print("\n=== Repository Breakdown by Scope ===\n")
        
        table = PrettyTable()
        table.field_names = ["Metric", "Count", "Percentage"]
        table.align["Metric"] = "l"
        table.align["Count"] = "r"
        table.align["Percentage"] = "r"
        
        table.add_row(["Total Repositories", total_repos, "100%"])
        table.add_row(["Orphaned (Global only)", orphaned_repos, f"{breakdown['summary']['orphaned_percentage']:.1f}%"])
        table.add_row(["With App Scopes", scoped_repos, f"{100 - breakdown['summary']['orphaned_percentage']:.1f}%"])
        
        print(table)
        
        print("\n=== Repositories per Scope ===\n")
        
        scope_table = PrettyTable()
        scope_table.field_names = ["Scope", "Repository Count", "Percentage"]
        scope_table.align["Scope"] = "l"
        scope_table.align["Repository Count"] = "r"
        scope_table.align["Percentage"] = "r"
        
        # Sort scopes: Global first, then alphabetically
        sorted_scopes = sorted(scope_counts.items(), key=lambda x: (x[0] != "Global", x[0]))
        
        for scope_name, count in sorted_scopes:
            percentage = (count / total_repos * 100) if total_repos > 0 else 0
            scope_table.add_row([scope_name, count, f"{percentage:.1f}%"])
        
        print(scope_table)
        
        if orphaned_repos > 0:
            print(f"\n⚠️  Alert: {orphaned_repos} repositories ({breakdown['summary']['orphaned_percentage']:.1f}%) are not assigned to any application scope.")
            print("Use 'repo list --orphan' to see them.")
    else:
        # JSON output
        print(json.dumps(breakdown, indent=2))


def main():
    """Main function"""
    # Disable SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Custom argument parsing to support global options anywhere
    # First, let's identify if we have a command and extract global args
    raw_args = sys.argv[1:]
    
    # Extract global arguments regardless of position
    global_args = {
        'verbose': False,
        'debug': False,
        'profile': 'default'
    }
    
    # Check for version first
    if '--version' in raw_args:
        print(f'aqua_repo_breakdown {__version__}')
        sys.exit(0)
    
    # Extract global flags from anywhere in the command line
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
        description='Aqua Repository Breakdown Utility - Analyze repository scope assignments in Aqua Security platform',
        prog='aqua_repo_breakdown',
        epilog='Global options can be placed before or after the command:\n'
               '  -v, --verbose        Show human-readable output instead of JSON\n'
               '  -d, --debug          Show debug output including API calls\n'
               '  -p, --profile        Configuration profile to use (default: default)\n'
               '  --version            Show program version',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Create subparsers for commands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Setup command
    setup_parser = subparsers.add_parser('setup', help='Interactive setup wizard')
    setup_parser.add_argument('profile_name', nargs='?', help='Profile name to create/update (optional)')
    
    # Profile command with subcommands
    profile_parser = subparsers.add_parser('profile', help='Manage configuration profiles')
    profile_subparsers = profile_parser.add_subparsers(dest='profile_command', help='Profile management commands')
    
    # Profile list
    profile_list_parser = profile_subparsers.add_parser('list', help='List available profiles')
    
    # Profile show
    profile_show_parser = profile_subparsers.add_parser('show', help='Show profile details')
    profile_show_parser.add_argument('name', nargs='?', help='Profile name to show (defaults to current default profile)')
    
    # Profile delete
    profile_delete_parser = profile_subparsers.add_parser('delete', help='Delete a profile')
    profile_delete_parser.add_argument('name', help='Profile name to delete')
    
    # Profile set-default
    profile_default_parser = profile_subparsers.add_parser('set-default', help='Set default profile')
    profile_default_parser.add_argument('name', help='Profile name to set as default')
    
    # Repo command with subcommands
    repo_parser = subparsers.add_parser('repo', help='Repository analysis commands')
    repo_subparsers = repo_parser.add_subparsers(dest='repo_command', help='Repository commands')
    
    # Repo list
    repo_list_parser = repo_subparsers.add_parser('list', help='List repositories (all by default, use -v for table)')
    repo_list_parser.add_argument('--scope', help='Filter by application scope')
    repo_list_parser.add_argument('--registry', help='Filter by registry')
    repo_list_parser.add_argument('--orphan', action='store_true',
                                 help='Show only orphaned repositories (no app scope assignments)')
    repo_list_parser.add_argument('--all-scopes', action='store_true',
                                 help='Show all scope assignments for each repository')
    
    # Repo breakdown
    repo_breakdown_parser = repo_subparsers.add_parser('breakdown', 
                                help='Show repository scope analysis (JSON by default, use -v for table)')
    repo_breakdown_parser.add_argument('--csv-file', dest='csv_file', action='store', 
                                help='Export to CSV file')
    repo_breakdown_parser.add_argument('--json-file', dest='json_file', action='store', 
                                help='Export to JSON file')
    
    # Parse the filtered arguments
    args = parser.parse_args(filtered_args)
    
    # Add global args to the namespace
    args.verbose = global_args['verbose']
    args.debug = global_args['debug']
    args.profile = global_args['profile']
    
    # Show help if no command provided
    if args.command is None:
        parser.print_help()
        sys.exit(1)
    
    # Handle setup command
    if args.command == 'setup':
        # Use positional argument if provided, otherwise fall back to -p flag
        if hasattr(args, 'profile_name') and args.profile_name:
            profile_name = args.profile_name
        elif args.profile != 'default':
            profile_name = args.profile
        else:
            profile_name = None
        success = interactive_setup(profile_name, debug=args.debug)
        sys.exit(0 if success else 1)
    
    # Handle profile commands
    if args.command == 'profile':
        config_mgr = ConfigManager()
        
        # Handle profile list
        if args.profile_command == 'list':
            if not args.verbose:
                # JSON output by default
                profile_data = get_all_profiles_info()
                print(json.dumps(profile_data, indent=2))
            else:
                # Verbose mode shows human-readable output
                list_profiles(verbose=True)
            sys.exit(0)
        
        # Handle profile show
        elif args.profile_command == 'show':
            # If no name provided, use the default profile
            if args.name is None:
                config_mgr = ConfigManager()
                profile_name = config_mgr.get_default_profile()
            else:
                profile_name = args.name
            
            profile_info = get_profile_info(profile_name)
            if not profile_info:
                print(profile_not_found_response(profile_name, 'text' if args.verbose else 'json'))
                sys.exit(1)
            
            print(format_profile_info(profile_info, 'text' if args.verbose else 'json'))
            sys.exit(0)
        
        # Handle profile delete
        elif args.profile_command == 'delete':
            result = delete_profile_with_result(args.name)
            print(profile_operation_response(
                result['action'],
                result['profile'],
                result['success'],
                result.get('error'),
                'text' if args.verbose else 'json'
            ))
            sys.exit(0 if result['success'] else 1)
        
        # Handle profile set-default
        elif args.profile_command == 'set-default':
            result = set_default_profile_with_result(args.name)
            print(profile_operation_response(
                result['action'],
                result['profile'],
                result['success'],
                result.get('error'),
                'text' if args.verbose else 'json'
            ))
            sys.exit(0 if result['success'] else 1)
        
        # No subcommand specified
        else:
            print("Error: No profile subcommand specified")
            print("\nAvailable profile commands:")
            print("  profile list              List all profiles")
            print("  profile show <name>       Show profile details")
            print("  profile delete <name>     Delete a profile")
            print("  profile set-default <name> Set default profile")
            print("\nExample: python aqua_repo_breakdown.py profile list")
            sys.exit(1)
    
    # Handle repo commands
    if args.command == 'repo':
        # No subcommand specified
        if not hasattr(args, 'repo_command') or args.repo_command is None:
            print("Error: No repo subcommand specified")
            print("\nAvailable repo commands:")
            print("  repo list              List repositories")
            print("  repo breakdown         Show repository scope analysis")
            print("\nExample: python aqua_repo_breakdown.py repo list")
            sys.exit(1)
    
    # For other commands, we need authentication
    # First try to load from profile
    profile_loaded = False
    actual_profile = args.profile
    if hasattr(args, 'profile'):
        result = load_profile_credentials(args.profile)
        if isinstance(result, tuple):
            profile_loaded, actual_profile = result
        else:
            # Backward compatibility if someone is using old version
            profile_loaded = result
    
    # Check if credentials are available (either from profile or environment)
    has_creds = os.environ.get('AQUA_USER')
    
    if not has_creds:
        if args.verbose:
            print("No credentials found.")
            print("\nYou can:")
            print("1. Run 'python aqua_repo_breakdown.py setup' to configure credentials")
            print("2. Set environment variables (AQUA_KEY, AQUA_SECRET, etc.)")
            print("3. Create an .env file with credentials")
        else:
            # JSON error output
            print(json.dumps({"error": "No credentials found. Run 'setup' command or set environment variables."}))
        sys.exit(1)
    
    # Print version info in debug mode
    if args.debug:
        print(f"DEBUG: Aqua Repository Breakdown Utility version: {__version__}")
        print()
    
    # Authenticate
    try:
        if profile_loaded and args.verbose:
            print(f"Using profile: {actual_profile}")
        if args.verbose:
            print("Authenticating with Aqua Security platform...")
        token = authenticate(verbose=args.debug)
        if args.verbose:
            print("Authentication successful!\n")
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
        if args.command == 'repo' and args.repo_command == 'list':
            # Debug: Show which endpoint we're using
            if args.debug:
                print(f"DEBUG: Using CSP endpoint for repository API: {csp_endpoint}")
                api_endpoint = os.environ.get('AQUA_ENDPOINT')
                if api_endpoint:
                    print(f"DEBUG: API endpoint available: {api_endpoint}")
            
            # Extract optional filters and flags
            scope = getattr(args, 'scope', None)
            registry = getattr(args, 'registry', None)
            orphan = getattr(args, 'orphan', False)
            all_scopes = getattr(args, 'all_scopes', False)
            
            repo_list(csp_endpoint, token, args.verbose, args.debug, 
                     scope=scope, registry=registry, orphan=orphan, all_scopes=all_scopes)
            
        elif args.command == 'repo' and args.repo_command == 'breakdown':
            if args.debug:
                print(f"DEBUG: Using CSP endpoint for repository API: {csp_endpoint}")
            
            repo_breakdown(csp_endpoint, token, args.verbose, args.debug, 
                          args.csv_file, args.json_file)
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
    main()