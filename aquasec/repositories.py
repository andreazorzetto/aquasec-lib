"""
Repository-related API functions for Andrea library
"""

import requests


def api_get_repositories(server, token, page, page_size, registry=None, scope=None, verbose=False):
    """Get repositories from the server"""
    if registry:
        api_url = "{server}/api/v2/repositories?registry={registry}&page={page}&pagesize={page_size}&include_totals=true&order_by=name".format(
            server=server,
            registry=registry,
            page=page,
            page_size=page_size)
    elif scope:
        api_url = "{server}/api/v2/repositories?scope={scope}&page={page}&pagesize={page_size}&include_totals=true&order_by=name".format(
            server=server,
            scope=scope,
            page=page,
            page_size=page_size)
    else:
        api_url = "{server}/api/v2/repositories?page={page}&pagesize={page_size}&include_totals=true&order_by=name".format(
            server=server,
            page=page,
            page_size=page_size)

    headers = {'Authorization': f'Bearer {token}'}
    if verbose:
        print(api_url)
    res = requests.get(url=api_url, headers=headers, verify=False)

    return res


def get_all_repositories(server, token, registry=None, scope=None, verbose=False):
    """
    Get all repositories with pagination support
    
    Args:
        server: The server URL
        token: Authentication token
        registry: Optional registry filter
        scope: Optional scope filter
        verbose: Print debug information
        
    Returns:
        List of all repositories
    """
    all_repos = []
    page = 1
    page_size = 100  # Larger page size for efficiency
    
    while True:
        res = api_get_repositories(server, token, page, page_size, registry, scope, verbose)
        
        if res.status_code != 200:
            raise Exception(f"API call failed with status {res.status_code}: {res.text}")
        
        data = res.json()
        repos = data.get("result", [])
        
        if not repos:
            break
            
        all_repos.extend(repos)
        
        # Check if there are more pages
        total = data.get("count", 0)
        if len(all_repos) >= total or len(repos) < page_size:
            break
            
        page += 1
        
        if verbose:
            print(f"Fetched {len(all_repos)} of {total} repositories...")
    
    return all_repos