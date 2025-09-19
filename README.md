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
├── enforcers.py       # Enforcer-related functions (optimized in v0.4.0)
├── repositories.py    # Repository API calls
├── code_repositories.py # Code repository API calls
├── functions.py       # Serverless functions API calls (NEW in v0.4.0)
├── vms.py             # VM inventory API calls (NEW in v0.5.0)
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

### VM Inventory

```python
from aquasec import get_all_vms, get_vm_count, filter_vms_by_coverage, filter_vms_by_cloud_provider

# Get all VMs
vms = get_all_vms(server, token)

# Get VM count  
count = get_vm_count(server, token)

# Filter VMs without enforcer coverage
vms_without_enforcer = filter_vms_by_coverage(
    vms, 
    excluded_types=['vm_enforcer', 'host_enforcer', 'aqua_enforcer']
)

# Filter by cloud provider
aws_vms = filter_vms_by_cloud_provider(vms, ['AWS'])

# Filter by risk level
high_risk_vms = filter_vms_by_risk_level(vms, ['critical', 'high'])
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

### Serverless Functions (NEW in v0.4.0)

```python
from aquasec import get_function_count, api_get_functions

# Get total functions count across all scopes
total_functions = get_function_count(server, token, verbose=True)

# Get functions with pagination (for detailed data)
functions_response = api_get_functions(server, token, page=1, page_size=50, verbose=True)
functions_data = functions_response.json() if functions_response.status_code == 200 else {}
```

### Repository Management

```python
from aquasec import get_repo_count, get_all_repositories, get_repo_count_by_scope, api_delete_repo

# Get total repository count
total_repos = get_repo_count(server, token, verbose=True)

# Get repository count for specific scope
scoped_repos = get_repo_count(server, token, scope='production', verbose=True)

# Get all repositories with optional filtering
all_repos = get_all_repositories(server, token, registry='myregistry', verbose=True)

# Get repository count by multiple scopes
repo_counts = get_repo_count_by_scope(server, token, ['prod', 'staging'], verbose=True)

# Delete a specific repository
response = api_delete_repo(server, token, 'myregistry', 'myrepo', verbose=True)
if response.status_code in [200, 202, 204]:
    print("Repository deleted successfully")
```

## Production-Ready Examples

The `examples/` directory contains production-ready implementations demonstrating how to use the aquasec library effectively:

### 🔧 [License Utility](examples/license-utility/)
Command-line tool for analyzing license utilization and generating reports.
- License utilization analysis across scopes
- Multiple output formats (table, JSON, CSV)
- 50%+ performance improvement with optimized API calls

### 📊 [Repository Breakdown](examples/repo-breakdown/)
CLI tool for analyzing repository scope assignments and identifying orphaned repositories.
- List repositories with scope assignments
- Identify orphaned repositories (Global scope only)
- Export results to CSV or JSON

### 💻 [VM Extract](examples/vm-extract/)
Utility for extracting VM inventory data with advanced filtering capabilities.
- Comprehensive VM inventory extraction
- Filter by coverage, cloud provider, region, risk level
- Memory-efficient streaming for large datasets

### 🗑️ [Repository Delete Utility](examples/repo-delete-utility/)
Safety-first tool for bulk deletion of image repositories.
- Dry-run mode by default, requires `--apply` flag for actual deletions
- Multiple filtering options (registry, host-images, empty-only)
- Clean table output with status indicators and progress tracking
- Comprehensive safety features and error handling

**Getting Started with Examples:**
```bash
cd examples/license-utility
pip install -r requirements.txt
python aqua_license_util.py setup
python aqua_license_util.py --all-results
```

See [examples/README.md](examples/README.md) for detailed documentation.

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