# Aqua Library

A Python library providing a clean API interface for interacting with Aqua Security platform.

## Overview

The `aqua-lib` library is extracted from the andreactl tool to provide reusable components for building Aqua Security utilities. It includes modules for authentication, API calls, and configuration management.

## Installation

```bash
pip install aqua-lib
```

## Features

- **Authentication**: Support for API keys and username/password authentication
- **Configuration Management**: Secure credential storage with profile support
- **API Modules**: Organized by domain (licenses, enforcers, repositories, etc.)
- **Utilities**: Common functions for data export and processing

## Quick Start

```python
from aqua import authenticate, get_licences, interactive_setup

# Setup credentials interactively
interactive_setup()

# Or use environment variables
import os
os.environ['AQUA_KEY'] = 'your-api-key'
os.environ['AQUA_SECRET'] = 'your-api-secret'
os.environ['CSP_ENDPOINT'] = 'https://xyz.cloud.aquasec.com'

# Authenticate
token = authenticate()

# Get license information
licenses = get_licences(os.environ['CSP_ENDPOINT'], token)
print(licenses)
```

## Library Structure

```
aqua/
├── __init__.py          # Main exports
├── auth.py             # Authentication functions
├── config.py           # Configuration management
├── licenses.py         # License-related API calls
├── scopes.py          # Application scope functions
├── enforcers.py       # Enforcer-related functions
├── repositories.py    # Repository API calls
└── common.py          # Utility functions
```

## Configuration Management

The library includes a configuration management system that stores credentials securely:

```python
from aqua import ConfigManager, load_profile_credentials

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

# Load profile
load_profile_credentials('production')
```

## API Examples

### License Management

```python
from aqua import get_licences, get_app_scopes, get_repo_count_by_scope

# Get license info
licenses = get_licences(server, token)

# Get application scopes
scopes = get_app_scopes(server, token)

# Get repository count by scope
repo_counts = get_repo_count_by_scope(server, token, [s['name'] for s in scopes])
```

### Enforcer Management

```python
from aqua import get_enforcer_count, get_enforcer_groups

# Get enforcer count
count = get_enforcer_count(server, token)

# Get enforcer groups
groups = get_enforcer_groups(server, token)
```

## Building Custom Utilities

The library makes it easy to create focused utilities:

```python
#!/usr/bin/env python3
import json
from aqua import authenticate, load_profile_credentials, get_licences

# Load saved credentials
load_profile_credentials('default')

# Authenticate
token = authenticate()

# Get data
licenses = get_licences(os.environ['CSP_ENDPOINT'], token)

# Output as JSON
print(json.dumps(licenses, indent=2))
```

## Contributing

Issues and pull requests are welcome at [github.com/andreazorzetto/aqua-lib](https://github.com/andreazorzetto/aqua-lib)

## License

MIT License