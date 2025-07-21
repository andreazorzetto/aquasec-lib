#!/usr/bin/env python3
"""
Example script showing how to use the new profile management functions
from the aquasec library.
"""

import json
from aquasec import (
    get_all_profiles_info,
    get_profile_info,
    format_profile_info,
    delete_profile_with_result,
    set_default_profile_with_result,
    profile_not_found_response,
    profile_operation_response,
    ConfigManager
)


def main():
    # Example 1: List all profiles as JSON
    print("=== All Profiles (JSON) ===")
    profiles = get_all_profiles_info()
    print(json.dumps(profiles, indent=2))
    print()
    
    # Example 2: Show a specific profile in text format
    print("=== Profile Details (Text) ===")
    profile_info = get_profile_info('default')
    if profile_info:
        print(format_profile_info(profile_info, 'text'))
    else:
        print(profile_not_found_response('default', 'text'))
    print()
    
    # Example 3: Get the default profile
    print("=== Default Profile ===")
    config_mgr = ConfigManager()
    default_profile = config_mgr.get_default_profile()
    print(f"Current default profile: {default_profile}")
    print()
    
    # Example 4: Set a new default profile (if it exists)
    print("=== Set Default Profile ===")
    if 'production' in config_mgr.list_profiles():
        result = set_default_profile_with_result('production')
        print(profile_operation_response(
            result['action'],
            result['profile'],
            result['success'],
            result.get('error'),
            'text'
        ))
    else:
        print("Profile 'production' not found - skipping set default example")
    print()
    
    # Example 5: Show how error handling works
    print("=== Error Handling Example ===")
    result = delete_profile_with_result('non-existent-profile')
    print("JSON response:", profile_operation_response(
        result['action'],
        result['profile'],
        result['success'],
        result.get('error'),
        'json'
    ))
    print("Text response:", profile_operation_response(
        result['action'],
        result['profile'],
        result['success'],
        result.get('error'),
        'text'
    ))


if __name__ == '__main__':
    main()