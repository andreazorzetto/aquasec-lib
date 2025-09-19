"""
Repository-related API functions for Andrea library
"""

import requests


def api_delete_repo(server, token, registry, name, verbose=False):
    """
    Delete a single repository

    Args:
        server: The server URL
        token: Authentication token
        registry: Registry name
        name: Repository name
        verbose: Print debug information

    Returns:
        Response object from the API call
    """
    api_url = f"{server}/api/v2/repositories/{registry}/{name}"
    headers = {'Authorization': f'Bearer {token}'}

    if verbose:
        print(f"DELETE {api_url}")

    res = requests.delete(url=api_url, headers=headers, verify=False)
    return res


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


def get_repo_count(server, token, scope=None, verbose=False):
    """
    Get count of image repositories
    
    Args:
        server: The server URL
        token: Authentication token
        scope: Optional scope filter
        verbose: Print debug information
        
    Returns:
        Number of repositories
    """
    try:
        # Get first page with minimal size to just get the count
        response = api_get_repositories(server, token, page=1, page_size=1, scope=scope, verbose=verbose)
        
        if response.status_code == 200:
            response_json = response.json()
            count = response_json.get("count", 0)
            if verbose:
                print(f"Total repositories count: {count}")
            return count
        else:
            if verbose:
                print(f"Failed to get repositories count: {response.status_code}")
            return 0
    except Exception as e:
        if verbose:
            print(f"Error getting repositories count: {e}")
        return 0


def get_repo_count_by_scope(server, token, scopes_list, verbose=False):
    """Get repository count by scope"""
    repos_by_scope = {}

    for scope in scopes_list:
        response = api_get_repositories(server, token, 1, 20, None, scope, verbose)
        if response.status_code != 200:
            if verbose:
                print(f"DEBUG: API call failed for scope '{scope}' with status {response.status_code}")
            repos_by_scope[scope] = 0
            continue
            
        try:
            response_json = response.json()
            # Since include_totals=true is always used, count field should always be present
            repos_by_scope[scope] = response_json["count"]
        except KeyError:
            if verbose:
                print(f"DEBUG: Missing 'count' field for scope '{scope}' - API response: {response_json}")
            raise Exception(f"API response missing 'count' field for scope '{scope}'")
        except Exception as e:
            if verbose:
                print(f"DEBUG: Failed to parse JSON for scope '{scope}': {e}")
            raise Exception(f"Failed to parse API response for scope '{scope}': {e}")

    return repos_by_scope
