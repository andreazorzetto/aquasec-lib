"""
Functions-related API functions for Andrea library
"""

import requests


def api_get_functions(server, token, page=1, page_size=50, verbose=False):
    """Get serverless functions from the server
    
    This API call works similar to the image repos one, and returns the count by default
    for totals.
    """
    api_url = f"{server}/api/v2/serverless/functions?page={page}&pagesize={page_size}&order_by=name"
    headers = {'Authorization': f'Bearer {token}'}

    if verbose:
        print(f"API URL: {api_url}")

    try:
        res = requests.get(url=api_url, headers=headers, verify=False)
        if verbose:
            print(f"Response status: {res.status_code}")
        
        if not res.ok:
            print(f"API Error: {res.status_code} - {res.reason}")
            if verbose:
                print(f"Response body: {res.text}")
        
        return res
    except Exception as e:
        print(f"Request failed: {str(e)}")
        raise


def get_function_count(server, token, verbose=False):
    """Get total count of serverless functions
    
    Returns the total count of functions across all scopes.
    """
    try:
        # Get first page with minimal size to just get the count
        response = api_get_functions(server, token, page=1, page_size=1, verbose=verbose)
        
        if response.status_code == 200:
            response_json = response.json()
            count = response_json.get("count", 0)
            if verbose:
                print(f"Total functions count: {count}")
            return count
        else:
            if verbose:
                print(f"Failed to get functions count: {response.status_code}")
            return 0
    except Exception as e:
        if verbose:
            print(f"Error getting functions count: {e}")
        return 0