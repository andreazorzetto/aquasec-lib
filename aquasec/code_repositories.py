"""
Code repository-related API functions for Andrea library
"""

import requests


def api_get_code_repositories(server, token, page=1, page_size=50, scope=None, use_estimated_count=False, skip_count=True, verbose=False):
    """
    Get code repositories from the server
    
    Args:
        server: The server URL
        token: Authentication token
        page: Page number (default: 1)
        page_size: Number of results per page (default: 50)
        scope: Optional scope filter
        use_estimated_count: Use estimated count (default: False)
        skip_count: Skip count calculation (default: True)
        verbose: Print debug information
        
    Returns:
        Response object from the API call
    """
    api_url = f"{server}/api/v2/hub/inventory/assets/code_repositories/list"
    
    params = {
        "page": page,
        "pagesize": page_size,
        "use_estimated_count": str(use_estimated_count).lower(),
        "skip_count": str(skip_count).lower()
    }
    
    if scope:
        params["scope"] = scope
    else:
        params["scope"] = ""
    
    headers = {'Authorization': f'Bearer {token}'}
    
    if verbose:
        print(f"API URL: {api_url}")
        print(f"Params: {params}")
    
    res = requests.get(url=api_url, headers=headers, params=params, verify=False)
    return res


def get_all_code_repositories(server, token, scope=None, verbose=False):
    """
    Get all code repositories, handling pagination
    
    Args:
        server: The server URL
        token: Authentication token
        scope: Optional scope filter
        verbose: Print debug information
        
    Returns:
        List of all code repositories
    """
    all_repos = []
    page = 1
    page_size = 100  # Larger page size for efficiency
    
    while True:
        res = api_get_code_repositories(server, token, page, page_size, scope, 
                                       use_estimated_count=False, skip_count=False, verbose=verbose)
        
        if res.status_code != 200:
            raise Exception(f"API call failed with status {res.status_code}: {res.text}")
        
        data = res.json()
        repos = data.get("data", [])
        
        if not repos:
            break
            
        all_repos.extend(repos)
        
        # Check if there are more pages
        total = data.get("count", 0)
        if len(all_repos) >= total or len(repos) < page_size:
            break
            
        page += 1
    
    return all_repos


def get_code_repo_count(server, token, scope=None, verbose=False):
    """
    Get count of code repositories
    
    Args:
        server: The server URL
        token: Authentication token
        scope: Optional scope filter
        verbose: Print debug information
        
    Returns:
        Number of code repositories
    """
    res = api_get_code_repositories(server, token, page=1, page_size=1, scope=scope, 
                                   use_estimated_count=False, skip_count=False, verbose=verbose)
    
    if res.status_code != 200:
        raise Exception(f"API call failed with status {res.status_code}: {res.text}")
    
    return res.json().get("count", 0)


def get_code_repo_count_by_scope(server, token, scopes_list, verbose=False):
    """
    Get code repository count by scope
    
    Args:
        server: The server URL
        token: Authentication token
        scopes_list: List of scope names
        verbose: Print debug information
        
    Returns:
        Dictionary mapping scope names to repository counts
    """
    code_repos_by_scope = {}
    
    for scope in scopes_list:
        try:
            count = get_code_repo_count(server, token, scope, verbose)
            code_repos_by_scope[scope] = count
        except Exception as e:
            if verbose:
                print(f"Error getting code repos for scope {scope}: {e}")
            code_repos_by_scope[scope] = 0
    
    return code_repos_by_scope