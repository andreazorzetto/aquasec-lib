"""
License-related API functions for Andrea library
"""

import requests
import sys


def api_get_licenses(server, token, verbose=False):
    """Get license information from the server"""
    api_url = server + "/api/v2/licenses?page=1&pagesize=25&order_by=-status"
    headers = {'Authorization': f'Bearer {token}'}

    if verbose:
        print(f"API URL: {api_url}")

    try:
        res = requests.get(url=api_url, headers=headers, verify=False)
        if verbose:
            print(f"Response status: {res.status_code}")
            print(f"Request headers: {headers}")
        
        if not res.ok:
            print(f"API Error: {res.status_code} - {res.reason}")
            if verbose:
                print(f"Response body: {res.text}")
                print(f"Response headers: {dict(res.headers)}")
        
        return res
    except Exception as e:
        print(f"Request failed: {str(e)}")
        raise


def api_get_dta_license(server, token, verbose=False):
    """Get DTA license information"""
    api_url = server + "/api/v1/settings/system/system"
    headers = {'Authorization': f'Bearer {token}'}

    if verbose:
        print(api_url)

    res = requests.get(url=api_url, headers=headers, verify=False)
    return res.json()["dta"]


def api_post_dta_license_utilization(server, token, dta_token, dta_url):
    """Get DTA license utilization"""
    api_url = server + "/api/v2/dta/license_status"

    payload = {"url": f"{dta_url}", "token": f"{dta_token}"}
    headers = {'Authorization': f'Bearer {token}'}

    res = requests.post(url=api_url, headers=headers, json=payload, verify=False)
    return res


def get_all_licenses(csp_endpoint, token, verbose=False):
    """
    Get all licenses information (raw API response)
    Returns the complete API response with all licenses
    """
    res = api_get_licenses(csp_endpoint, token, verbose)
    
    # Check if the request was successful
    if not res.ok:
        print(f"Failed to fetch licenses: {res.status_code} - {res.reason}")
        if res.status_code == 401:
            print("Authentication failed. Please check your credentials.")
        elif res.status_code == 403:
            print("Access denied. Please check your permissions.")
        return None
    
    # Parse and return JSON response
    try:
        return res.json()
    except ValueError as e:
        print(f"Failed to parse JSON response: {str(e)}")
        if verbose:
            print(f"Response text: {res.text}")
        return None


def get_licences(csp_endpoint, token, verbose=False):
    """
    Get consolidated license information
    Returns a dict with license details from API's calculated totals
    """
    # Get the full API response
    response_data = get_all_licenses(csp_endpoint, token, verbose)
    
    if not response_data:
        # Return empty license data if API call failed
        return {
            'num_repositories': 0,
            'num_enforcers': 0,
            'num_microenforcers': 0,
            'num_vm_enforcers': 0,
            'num_functions': 0,
            'num_code_repositories': 0,
            'num_advanced_functions': 0,
            'vshield': False,
            'num_protected_kube_nodes': 0,
            'malware_protection': False,
            'num_active': 0
        }
    
    # Extract the totals from resources.active_production
    active_production = response_data.get('resources', {}).get('active_production', {})
    
    # Build the licenses dict from the API-provided totals
    licenses = {
        'num_repositories': active_production.get('num_repositories', 0),
        'num_enforcers': active_production.get('num_enforcers', 0),
        'num_microenforcers': active_production.get('num_microenforcers', 0),
        'num_vm_enforcers': active_production.get('num_vm_enforcers', 0),
        'num_functions': active_production.get('num_functions', 0),
        'num_code_repositories': active_production.get('num_code_repositories', 0),
        'num_advanced_functions': active_production.get('num_advanced_functions', 0),
        'vshield': active_production.get('vshield', False),
        'num_protected_kube_nodes': active_production.get('num_protected_kube_nodes', 0),
        'malware_protection': active_production.get('malware_protection', False),
        'num_active': response_data.get('details', {}).get('num_active', 0)
    }
    
    if verbose:
        print(f"Extracted license totals from API response")
        print(f"Active licenses: {licenses['num_active']}")
    
    return licenses




def get_enforcer_count_by_scope(server, token, scopes_list, verbose=False):
    """Get enforcer count by scope"""
    from .enforcers import get_enforcer_count
    
    enforcers_by_scope = {}

    for scope in scopes_list:
        enforcers_by_scope[scope] = get_enforcer_count(server, token, None, scope, verbose)

    return enforcers_by_scope