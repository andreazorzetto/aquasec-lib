# Aqua Security Library

A Python library providing a clean API interface for interacting with Aqua Security platform.

## Overview

The `aquasec` library provides reusable components for building Aqua Security utilities. It includes modules for authentication, API calls, and configuration management with secure credential storage.

## Installation

```bash
pip install aquasec
```

### Dependencies

- requests>=2.28.0
- prettytable>=3.5.0
- cryptography>=41.0.0
- inquirer>=3.1.0

## Features

- **Authentication**: Support for API keys and username/password authentication
- **Configuration Management**: Secure credential storage with profile support
- **API Modules**: Organized by domain (licenses, enforcers, repositories, etc.)
- **Utilities**: Common functions for data export and processing

## Quick Start

```python
from aquasec import authenticate, get_licences, get_all_licenses, interactive_setup

# Setup credentials interactively
interactive_setup()

# Or use environment variables
import os
os.environ['AQUA_KEY'] = 'your-api-key'
os.environ['AQUA_SECRET'] = 'your-api-secret'
os.environ['CSP_ENDPOINT'] = 'https://xyz.cloud.aquasec.com'

# Authenticate
token = authenticate()

# Get license information (consolidated totals)
licenses = get_licences(os.environ['CSP_ENDPOINT'], token)
print(licenses)

# Get full license details
all_licenses = get_all_licenses(os.environ['CSP_ENDPOINT'], token)
print(all_licenses)
```

## Library Structure

```
aquasec/
├── __init__.py          # Main exports
├── auth.py             # Authentication functions
├── config.py           # Configuration management
├── licenses.py         # License-related API calls
├── scopes.py          # Application scope functions
├── enforcers.py       # Enforcer-related functions
├── repositories.py    # Repository API calls
├── code_repositories.py # Code repository API calls
└── common.py          # Utility functions
```

## Configuration Management

The library includes a comprehensive configuration management system that stores credentials securely:

### Basic Profile Management

```python
from aquasec import ConfigManager, load_profile_credentials, get_profile_info

# Create configuration manager
config_mgr = ConfigManager()

# Save a profile
config = {
    'auth_method': 'api_keys',
    'api_endpoint': 'https://api.cloudsploit.com',
    'csp_endpoint': 'https://xyz.cloud.aquasec.com',
    'api_role': 'Administrator',
    'api_methods': 'ANY'
}
creds = {
    'api_key': 'your-key',
    'api_secret': 'your-secret'
}
config_mgr.save_config('production', config)
config_mgr.encrypt_credentials(creds)

# Load profile (returns tuple: success, actual_profile_name)
success, profile_name = load_profile_credentials('production')

# Set default profile
config_mgr.set_default_profile('production')

# Get profile information (includes credentials_ref hash)
profile_info = get_profile_info('production')
print(profile_info)
```

### Advanced Profile Functions

```python
from aquasec import (
    get_all_profiles_info,
    format_profile_info,
    delete_profile_with_result,
    set_default_profile_with_result,
    profile_operation_response
)

# Get all profiles information
all_profiles = get_all_profiles_info()

# Format profile info for display
profile_info = get_profile_info('default')
print(format_profile_info(profile_info, 'text'))  # Human readable
print(format_profile_info(profile_info, 'json'))  # JSON format

# Delete profile with structured result
result = delete_profile_with_result('old-profile')
print(profile_operation_response(
    result['action'], 
    result['profile'], 
    result['success'],
    result.get('error'),
    'json'
))

# Set default profile with result
result = set_default_profile_with_result('production')
if result['success']:
    print("Default profile updated")
```

## API Examples

### License Management

```python
from aquasec import get_licences, get_all_licenses, get_app_scopes, get_repo_count_by_scope

# Get consolidated license info (uses API-provided totals)
licenses = get_licences(server, token)

# Get raw license API response (all license details)
all_licenses = get_all_licenses(server, token)

# Get application scopes
scopes = get_app_scopes(server, token)

# Get repository count by scope (with optional verbose parameter for debug output)
repo_counts = get_repo_count_by_scope(server, token, [s['name'] for s in scopes], verbose=True)
```

### Enforcer Management

```python
from aquasec import get_enforcer_count, get_enforcer_groups, get_enforcer_count_by_scope

# Get enforcer count
count = get_enforcer_count(server, token)

# Get enforcer count by scope (with optional verbose parameter)
scope_counts = get_enforcer_count_by_scope(server, token, scope_names, verbose=True)

# Get enforcer groups
groups = get_enforcer_groups(server, token)
```

## Building Custom Utilities

The library makes it easy to create focused utilities:

```python
#!/usr/bin/env python3
import json
import os
from aquasec import authenticate, load_profile_credentials, get_licences, get_all_licenses

# Load saved credentials
success, profile_name = load_profile_credentials('default')

# Authenticate
token = authenticate()

# Get consolidated license totals
licenses = get_licences(os.environ['CSP_ENDPOINT'], token)

# Or get full license details
all_licenses = get_all_licenses(os.environ['CSP_ENDPOINT'], token)

# Output as JSON
print(json.dumps(licenses, indent=2))
```

## Contributing

Issues and pull requests are welcome at [github.com/andreazorzetto/aquasec-lib](https://github.com/andreazorzetto/aquasec-lib)

## License

MIT License