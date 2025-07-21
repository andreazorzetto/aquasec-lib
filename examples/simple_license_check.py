#!/usr/bin/env python3
"""
Simple example script demonstrating how easy it is to use aquasec library
with the new profile management functions.
"""

import sys
import json
from aquasec import (
    load_profile_credentials,
    authenticate,
    get_licences,
    get_all_profiles_info,
    format_profile_info,
    profile_not_found_response,
    ConfigManager
)


def main():
    # Check if a profile name was provided as argument
    profile_name = sys.argv[1] if len(sys.argv) > 1 else None
    
    # If no profile specified, use the default
    if not profile_name:
        config_mgr = ConfigManager()
        profile_name = config_mgr.get_default_profile()
        print(f"No profile specified, using default: {profile_name}")
    
    # Load the profile
    success, actual_profile = load_profile_credentials(profile_name)
    
    if not success:
        print(profile_not_found_response(profile_name, 'text'))
        print("\nAvailable profiles:")
        for profile in get_all_profiles_info():
            print(f"  - {profile['name']} {'(default)' if profile['is_default'] else ''}")
        sys.exit(1)
    
    print(f"Using profile: {actual_profile}")
    
    try:
        # Authenticate
        token = authenticate()
        
        # Get license information
        import os
        csp_endpoint = os.environ.get('CSP_ENDPOINT')
        licenses = get_licences(csp_endpoint, token)
        
        # Display license summary
        print("\nLicense Summary:")
        print(f"  Repositories: {licenses['num_repositories']}")
        print(f"  Enforcers: {licenses['num_enforcers']}")
        print(f"  Code Repositories: {licenses['num_code_repositories']}")
        print(f"  Active Licenses: {licenses['num_active']}")
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()