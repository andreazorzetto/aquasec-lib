#!/usr/bin/env python3
"""
Aqua License Utility
A focused tool for extracting license utilization from Aqua Security platform

Usage:
    python aqua_license_util.py setup                  # Interactive setup
    python aqua_license_util.py license show           # Show license limits (JSON)
    python aqua_license_util.py license count          # Show utilization vs limits (JSON)  
    python aqua_license_util.py license breakdown      # Show per-scope breakdown (JSON)
"""

import argparse
import json
import sys
import os
from prettytable import PrettyTable

# Import from aquasec library
from aquasec import (
    authenticate,
    get_all_licenses,
    get_licences,
    get_app_scopes,
    get_repo_count_by_scope,
    get_enforcer_count_by_scope,
    get_code_repo_count_by_scope,
    get_function_count,
    api_get_dta_license,
    api_post_dta_license_utilization,
    write_json_to_file,
    generate_csv_for_license_breakdown,
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
__version__ = "0.4.0"


def license_show(server, token, verbose=False, debug=False):
    """Show license information"""
    # Get all licenses data
    all_licenses_data = get_all_licenses(server, token, debug)
    if not all_licenses_data:
        return
    
    # Extract totals from resources.active_production
    active_production = all_licenses_data.get('resources', {}).get('active_production', {})
    num_active = all_licenses_data.get('details', {}).get('num_active', 0)
    
    if verbose:
        # Show single table with totals
        if active_production:
            table = PrettyTable(["Product", "Total Limit"])
            table.align["Product"] = "l"
            table.align["Total Limit"] = "r"
            
            fields = [
                ('num_repositories', 'Image Repositories'),
                ('num_microenforcers', 'Micro-enforcers'),
                ('num_vm_enforcers', 'VM Enforcers'),
                ('num_functions', 'Functions'),
                ('num_code_repositories', 'Code Repositories'),
                ('num_advanced_functions', 'Advanced Functions'),
                ('num_protected_kube_nodes', 'Protected K8s Nodes'),
                ('vshield', 'vShield'),
                ('malware_protection', 'Malware Protection')
            ]
            
            for field, display_name in fields:
                value = active_production.get(field, 0)
                if field in ['vshield', 'malware_protection']:
                    display_value = "Yes" if value else "No"
                else:
                    display_value = "Unlimited" if value == -1 else f"{value:,}"
                table.add_row([display_name, display_value])
            
            # Add number of active licenses
            table.add_row(['Active Licenses', num_active])
            
            # Add DTA repos if present
            if 'dta_repos' in active_production:
                table.add_row(['DTA Repositories', f"{active_production['dta_repos']:,}"])
            
            print(table)
        else:
            print("No active production license totals found")
    else:
        # JSON output - return only the totals
        totals = {}
        
        if active_production:
            # Copy all fields from active_production
            for key, value in active_production.items():
                # Convert -1 to "unlimited" for numeric fields
                if isinstance(value, int) and value == -1 and key not in ['dta_repos']:
                    totals[key] = "unlimited"
                else:
                    totals[key] = value
        
        # Add num_active
        totals['num_active'] = num_active
        
        print(json.dumps(totals, indent=2))


def license_count(server, token, verbose=False, debug=False):
    """Show actual license utilization totals across all scopes"""
    # Get license limits
    licenses = get_licences(server, token, debug)
    if not licenses:
        if verbose:
            print("No license information found")
        else:
            print(json.dumps({"error": "No license information found"}))
        return
    
    if debug:
        print("DEBUG: Getting total counts (using Global scope)")
    
    # Get total repository count using library function
    from aquasec import get_repo_count
    total_repos = 0
    try:
        total_repos = get_repo_count(server, token, verbose=debug)
        if debug:
            print(f"DEBUG: Total repositories: {total_repos}")
    except Exception as e:
        if debug:
            print(f"DEBUG: Failed to get repository count: {e}")
    
    # Get code repository count
    total_code_repos = 0
    try:
        from aquasec import get_code_repo_count
        total_code_repos = get_code_repo_count(server, token, verbose=debug)
        if debug:
            print(f"DEBUG: Total code repositories: {total_code_repos}")
    except Exception as e:
        if debug:
            print(f"DEBUG: Code repository counting not available: {e}")
    
    # Get functions count
    total_functions = 0
    try:
        total_functions = get_function_count(server, token, verbose=debug)
        if debug:
            print(f"DEBUG: Total functions: {total_functions}")
    except Exception as e:
        if debug:
            print(f"DEBUG: Functions counting not available: {e}")
    
    # Get enforcer counts - even though unlimited, useful for renewal purposes
    # Use the efficient optimized method that calls direct count APIs
    from aquasec import get_enforcer_count
    
    try:
        # Get total enforcer counts using optimized direct API calls
        total_enforcers = get_enforcer_count(server, token, verbose=debug)
        
        if debug:
            print(f"DEBUG: Total enforcer counts: {total_enforcers}")
    except Exception as e:
        if debug:
            print(f"DEBUG: Failed to get enforcer counts: {e}")
        # Fallback to empty counts
        total_enforcers = {
            'agent': 0,
            'kube_enforcer': 0,
            'host_enforcer': 0,
            'micro_enforcer': 0,
            'nano_enforcer': 0,
            'pod_enforcer': 0
        }
    
    # Calculate utilization - include all resources even if unlimited
    utilization = {
        'limits': licenses,
        'usage': {
            'repositories': total_repos,
            'code_repositories': total_code_repos,
            'functions': total_functions,
            'enforcers': total_enforcers['agent'],
            'kube_enforcers': total_enforcers['kube_enforcer'],
            'host_enforcers': total_enforcers['host_enforcer'],
            'micro_enforcers': total_enforcers['micro_enforcer'],
            'nano_enforcers': total_enforcers['nano_enforcer'],
            'pod_enforcers': total_enforcers['pod_enforcer'],
            'vm_enforcers': total_enforcers['host_enforcer'],  # VM enforcers are counted as host enforcers
            'protected_kube_nodes': total_enforcers['kube_enforcer']  # K8s nodes protected by kube enforcers
        }
    }
    
    if verbose:
        # Show table with limits vs actual usage
        table = PrettyTable(["Resource", "Limit", "Used", "Utilization %"])
        table.align["Resource"] = "l"
        table.align["Limit"] = "r"
        table.align["Used"] = "r"
        table.align["Utilization %"] = "r"
        
        # Define resource mappings - show all resources for renewal/usage tracking
        resources = [
            ('repositories', 'num_repositories', 'Image Repositories'),
            ('code_repositories', 'num_code_repositories', 'Code Repositories'),
            ('enforcers', 'num_protected_kube_nodes', 'Aqua Enforcers'),
            ('kube_enforcers', None, 'Kube Enforcers'),
            ('micro_enforcers', 'num_microenforcers', 'Micro Enforcers'),
            ('vm_enforcers', 'num_vm_enforcers', 'VM Enforcers'),
            ('functions', 'num_functions', 'Functions')
        ]
        
        for usage_key, limit_key, display_name in resources:
            # Handle None license key as unlimited
            if limit_key is None:
                limit = -1
            else:
                limit = licenses.get(limit_key, 0)
            used = utilization['usage'].get(usage_key, 0)
            
            # Format limit
            if limit == -1:
                limit_str = "Unlimited"
                util_pct = "-"
            else:
                limit_str = f"{limit:,}"
                if limit > 0:
                    util_pct = f"{(used / limit * 100):.1f}%"
                else:
                    util_pct = "-"
            
            table.add_row([display_name, limit_str, f"{used:,}", util_pct])
        
        print(table)
        
        # Show total active licenses
        print(f"\nActive Licenses: {licenses.get('num_active', 0)}")
        
        # Note about enforcer data
        if any(utilization['usage'][k] == 0 for k in ['enforcers', 'micro_enforcers', 'vm_enforcers']):
            print("\nNote: For detailed enforcer counts, use 'license breakdown' command")
    else:
        # JSON output
        print(json.dumps(utilization, indent=2))


def license_breakdown(server, token, verbose=False, debug=False, csv_file=None, json_file=None, skip_repos=False):
    """Provide license usage breakdown per application scope"""
    # get the license information
    licenses = get_licences(server, token, debug)
    if debug:
        print("DEBUG: License info:", json.dumps(licenses), "\n")

    # dta
    dta_license = api_get_dta_license(server, token, debug)
    if debug:
        print("DEBUG: DTA License:", dta_license)
    
    dta_license_utilization = None
    if dta_license["enabled"]:
        dta_license_utilization = api_post_dta_license_utilization(server, token, dta_license["token"], dta_license["url"]).json()
        if debug:
            print("DEBUG: DTA License Utilization:", dta_license_utilization, "\n")

    # get all application scopes
    scopes_list = []
    scopes_result = get_app_scopes(server, token, debug)
    for scope in scopes_result:
        scopes_list.append(scope["name"])
    if debug:
        print("DEBUG: Scopes:", scopes_list, "\n")

    # get the count of scopes per repo
    if skip_repos:
        repo_count_by_scope = {scope: 0 for scope in scopes_list}
        if verbose:
            print("Skipping repository counting...")
        if debug:
            print("DEBUG: Repo count by scope: Skipped\n")
    else:
        repo_count_by_scope = get_repo_count_by_scope(server, token, scopes_list, debug)
        if debug:
            print("DEBUG: Repo count by scope:", json.dumps(repo_count_by_scope), "\n")

    # get enforcers count by scope
    enforcer_count_by_scope = get_enforcer_count_by_scope(server, token, scopes_list, debug)
    if debug:
        print("DEBUG: Enforcer count by scope:", json.dumps(enforcer_count_by_scope), "\n")

    # get code repositories count by scope
    if skip_repos:
        code_repo_count_by_scope = {scope: 0 for scope in scopes_list}
        if debug:
            print("DEBUG: Code repo count by scope: Skipped\n")
    elif get_code_repo_count_by_scope is not None:
        code_repo_count_by_scope = get_code_repo_count_by_scope(server, token, scopes_list, debug)
        if debug:
            print("DEBUG: Code repo count by scope:", json.dumps(code_repo_count_by_scope), "\n")
    else:
        code_repo_count_by_scope = {}
        if debug:
            print("DEBUG: Code repo count by scope: Not available in this version\n")

    # put scopes, repos, code repos and enforcers data together
    breakdown_data = {}
    for key, value in repo_count_by_scope.items():
        if key in enforcer_count_by_scope:
            breakdown_data[key] = {
                "scope name": key, 
                "repos": value,
                "code_repos": code_repo_count_by_scope.get(key, 0),
                **enforcer_count_by_scope[key]
            }

    # write csv - silent unless verbose
    if csv_file:
        generate_csv_for_license_breakdown(breakdown_data, csv_file)
        if verbose:
            print(f"License breakdown exported to CSV: {csv_file}")

    # write json - silent unless verbose
    if json_file:
        write_json_to_file(json_file, breakdown_data)
        if verbose:
            print(f"License breakdown exported to JSON: {json_file}")

    if verbose:
        # Human-readable table format
        table = PrettyTable()
        table.field_names = ["Scope", "Images", "Code", "Agents",
                            "Kube", "Host", "Micro", "Nano", "Pod"]
        
        for scope, details in breakdown_data.items():
            row = [details["scope name"],
                    details["repos"],
                    details.get("code_repos", 0),
                    details["agent"],
                    details["kube_enforcer"],
                    details["host_enforcer"],
                    details["micro_enforcer"],
                    details["nano_enforcer"],
                    details["pod_enforcer"]]
            table.add_row(row)
        
        print(table)
    else:
        # JSON output by default
        print(json.dumps(breakdown_data, indent=2))


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
        print(f'aqua_license_util {__version__}')
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
        description='Aqua License Utility - Extract license utilization from Aqua Security platform',
        prog='aqua_license_util',
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
    
    # License command with subcommands
    license_parser = subparsers.add_parser('license', help='License management commands')
    license_subparsers = license_parser.add_subparsers(dest='license_command', help='License commands')
    
    # License show
    license_show_parser = license_subparsers.add_parser('show', help='Show license information (JSON by default, use -v for table)')
    
    # License count
    license_count_parser = license_subparsers.add_parser('count', help='Show actual license utilization vs limits (JSON by default, use -v for table)')
    
    # License breakdown
    license_breakdown_parser = license_subparsers.add_parser('breakdown', help='Show license breakdown by application scope (JSON by default, use -v for table)')
    license_breakdown_parser.add_argument('--csv-file', dest='csv_file', action='store', 
                                help='Export to CSV file')
    license_breakdown_parser.add_argument('--json-file', dest='json_file', action='store', 
                                help='Export to JSON file')
    license_breakdown_parser.add_argument('--skip-repos', dest='skip_repos', action='store_true',
                                help='Skip image and code repository counting (faster, enforcers only)')
    
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
            print("\nExample: python aqua_license_util.py profile list")
            sys.exit(1)
    
    # Handle license commands
    if args.command == 'license':
        # No subcommand specified
        if not hasattr(args, 'license_command') or args.license_command is None:
            print("Error: No license subcommand specified")
            print("\nAvailable license commands:")
            print("  license show              Show license information")
            print("  license breakdown         Show license breakdown by scope")
            print("\nExample: python aqua_license_util.py license show")
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
            print("1. Run 'python aqua_license_util.py setup' to configure credentials")
            print("2. Set environment variables (AQUA_KEY, AQUA_SECRET, etc.)")
            print("3. Create an .env file with credentials")
        else:
            # JSON error output
            print(json.dumps({"error": "No credentials found. Run 'setup' command or set environment variables."}))
        sys.exit(1)
    
    # Print version info in debug mode
    if args.debug:
        print(f"DEBUG: Aqua License Utility version: {__version__}")
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
        if args.command == 'license' and args.license_command == 'show':
            # Debug: Show which endpoint we're using
            if args.debug:
                print(f"DEBUG: Using CSP endpoint for license API: {csp_endpoint}")
                api_endpoint = os.environ.get('AQUA_ENDPOINT')
                if api_endpoint:
                    print(f"DEBUG: API endpoint available: {api_endpoint}")
            
            license_show(csp_endpoint, token, args.verbose, args.debug)
        elif args.command == 'license' and args.license_command == 'count':
            # Debug: Show which endpoint we're using
            if args.debug:
                print(f"DEBUG: Using CSP endpoint for license API: {csp_endpoint}")
            
            license_count(csp_endpoint, token, args.verbose, args.debug)
        elif args.command == 'license' and args.license_command == 'breakdown':
            if args.debug:
                print(f"DEBUG: Using CSP endpoint for license API: {csp_endpoint}")
            
            license_breakdown(csp_endpoint, token, args.verbose, args.debug, 
                            args.csv_file, args.json_file, args.skip_repos)
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