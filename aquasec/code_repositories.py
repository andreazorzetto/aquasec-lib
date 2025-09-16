"""
Code repository-related API functions for Andrea library
"""

import requests
import re


def _get_supply_chain_url(server):
    """
    Derive the Supply Chain API URL from the server/CSP endpoint

    Args:
        server: The CSP server URL (e.g., https://xxx.eu-1.cloud.aquasec.com)

    Returns:
        The Supply Chain API base URL
    """
    import os

    # Extract the domain from the server URL
    match = re.match(r'https?://([^/]+)', server)
    if not match:
        raise ValueError(f"Invalid server URL: {server}")

    domain = match.group(1)

    # Check if there's a region in the domain (e.g., eu-1, asia-1, etc.)
    # Pattern: xxx.REGION.cloud.aquasec.com or just xxx.cloud.aquasec.com
    region_match = re.search(r'\.(\w+-\d+)\.cloud\.aquasec\.com', domain)

    if region_match:
        # Regional endpoint - extract region from CSP endpoint
        region = region_match.group(1)
        supply_chain_url = f"https://api.{region}.supply-chain.cloud.aquasec.com"
    else:
        # CSP endpoint doesn't contain region, check auth endpoint
        auth_endpoint = os.environ.get('AQUA_ENDPOINT', '')
        auth_region_match = re.search(r'https?://(\w+-\d+)\.api\.cloudsploit\.com', auth_endpoint)

        if auth_region_match:
            # Found region in auth endpoint (e.g., eu-1.api.cloudsploit.com)
            region = auth_region_match.group(1)
            supply_chain_url = f"https://api.{region}.supply-chain.cloud.aquasec.com"
        else:
            # US endpoint (no region specified in either endpoint)
            supply_chain_url = "https://api.supply-chain.cloud.aquasec.com"

    return supply_chain_url


def api_get_code_repositories(server, token, page=1, page_size=50, scope=None, use_estimated_count=False, skip_count=True, verbose=False):
    """
    Get code repositories from the server

    Args:
        server: The server URL (CSP endpoint)
        token: Authentication token
        page: Page number (default: 1)
        page_size: Number of results per page (default: 50)
        scope: Optional scope filter (currently not supported by Supply Chain API)
        use_estimated_count: Not used (kept for compatibility)
        skip_count: Not used (kept for compatibility)
        verbose: Print debug information

    Returns:
        Response object from the API call
    """
    # Get the Supply Chain API base URL
    supply_chain_url = _get_supply_chain_url(server)

    # Build the API URL with the new endpoint
    api_url = f"{supply_chain_url}/v2/build/repositories"

    params = {
        "page": page,
        "page_size": page_size,
        "order_by": "-scan_date",
        "no_scan_repositories": "true"
    }

    # Note: The Supply Chain API doesn't support scope filtering in the same way
    # This is kept for compatibility but won't filter by scope
    if scope and verbose:
        print(f"Warning: Scope filtering is not supported by the Supply Chain API")
    
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

        # Check if there are more pages using the Supply Chain API response structure
        next_page = data.get("next_page")
        total = data.get("total_count", 0)

        # Stop if no next page or we've collected all repos
        if not next_page or len(all_repos) >= total or len(repos) < page_size:
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
    
    # The Supply Chain API returns total_count instead of count
    return res.json().get("total_count", 0)


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