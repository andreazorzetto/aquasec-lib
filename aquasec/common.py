"""
Common utility functions for Aqua library
"""

import csv
import json
import requests
from os.path import exists

# Module-level token cache for re-authentication
_cached_token = None


def _request_with_retry(method, url, token, headers=None, verbose=False, **kwargs):
    """
    Make HTTP request with automatic re-authentication on 401.

    All API functions should use this instead of calling requests directly.
    This ensures automatic token refresh on 401 responses.

    Args:
        method: HTTP method ('GET', 'POST', 'DELETE', etc.)
        url: Full API URL
        token: Authentication token
        headers: Optional additional headers (Authorization is added automatically)
        verbose: Print debug info on re-auth
        **kwargs: Passed to requests (params, json, data, etc.)

    Returns:
        Response object from the API call
    """
    global _cached_token

    # Use cached token if available (from a previous re-auth)
    effective_token = _cached_token if _cached_token else token

    # Build headers
    if headers is None:
        headers = {}
    headers['Authorization'] = f'Bearer {effective_token}'

    # Ensure verify=False is set (can be overridden in kwargs)
    kwargs.setdefault('verify', False)

    # Make the request
    res = requests.request(method, url, headers=headers, **kwargs)

    # Handle 401 - token expired
    if res.status_code == 401:
        if verbose:
            print("Token expired. Re-authenticating...")

        from .auth import authenticate
        new_token = authenticate(verbose=verbose)
        _cached_token = new_token

        # Update header and retry
        headers['Authorization'] = f'Bearer {new_token}'
        res = requests.request(method, url, headers=headers, **kwargs)

        if verbose and res.status_code == 200:
            print("Re-authentication successful.")

    return res


def clear_token_cache():
    """Clear the cached token. Useful for testing or forcing re-auth."""
    global _cached_token
    _cached_token = None


def write_content_to_file(file, content):
    """Write content to file"""
    with open(file, 'w') as f:
        f.write(content)


def write_json_to_file(file, content):
    """Write JSON content to file, appending if exists"""
    if exists(file):
        with open(file, "a") as file:
            json.dump(content, file)
            file.write('\n')
    else:
        with open(file, "w") as file:
            json.dump(content, file)
            file.write('\n')


def generate_csv_for_license_breakdown(license_breakdown, filename):
    """Generate CSV file for license breakdown data"""
    columns = ['scope', 'images', 'code', 'agents', 'kube', 'host', 'micro', 'nano', 'pod']

    with open(filename, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=columns)
        writer.writeheader()

        for key, value in license_breakdown.items():
            row = {
                'scope': value['scope name'],
                'images': value['repos'],
                'code': value.get('code_repos', 0),
                'agents': value['agent']['connected'],
                'kube': value['kube_enforcer']['connected'],
                'host': value['host_enforcer']['connected'],
                'micro': value['micro_enforcer']['connected'],
                'nano': value['nano_enforcer']['connected'],
                'pod': value['pod_enforcer']['connected']
            }
            writer.writerow(row)