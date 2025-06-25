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


def get_licences(csp_endpoint, token, verbose=False):
    """
    Get consolidated license information
    Returns a dict with license details
    """
    licenses = {
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

    res = api_get_licenses(csp_endpoint, token, verbose)
    
    # Check if the request was successful
    if not res.ok:
        print(f"Failed to fetch licenses: {res.status_code} - {res.reason}")
        if res.status_code == 401:
            print("Authentication failed. Please check your credentials.")
        elif res.status_code == 403:
            print("Access denied. Please check your permissions.")
        return licenses
    
    # Parse JSON response
    try:
        response_data = res.json()
    except ValueError as e:
        print(f"Failed to parse JSON response: {str(e)}")
        if verbose:
            print(f"Response text: {res.text}")
        return licenses
    
    # Extract license details
    if "details" in response_data and "num_active" in response_data["details"]:
        licenses["num_active"] = response_data["details"]["num_active"]
    else:
        if verbose:
            print("Warning: 'details' or 'num_active' not found in response")
            print(f"Response structure: {list(response_data.keys())}")

    # Extract license data
    if "data" not in response_data:
        print("Warning: 'data' field not found in response")
        if verbose:
            print(f"Available fields: {list(response_data.keys())}")
        return licenses
    
    licenses_data = response_data["data"]
    if verbose:
        print(f"Found {len(licenses_data)} license(s)")
        print(licenses_data)

    for license in licenses_data:
        try:
            if license.get("status") == "Active":
                products = license.get("products", {})
                # Add values only if they exist and are not -1 (unlimited)
                for key in ["num_repositories", "num_enforcers", "num_microenforcers", 
                           "num_vm_enforcers", "num_functions", "num_code_repositories",
                           "num_advanced_functions", "num_protected_kube_nodes"]:
                    value = products.get(key, 0)
                    if value > 0:  # Only add positive values (-1 means unlimited)
                        licenses[key] += value
                
                # Boolean flags
                licenses["vshield"] = products.get("vshield", False) or licenses["vshield"]
                licenses["malware_protection"] = products.get("malware_protection", False) or licenses["malware_protection"]
        except Exception as e:
            if verbose:
                print(f"Error processing license data: {str(e)}")
                print(f"License data: {license}")

    return licenses


def get_repo_count_by_scope(server, token, scopes_list):
    """Get repository count by scope"""
    from .repositories import api_get_repositories
    
    repos_by_scope = {}

    for scope in scopes_list:
        repos_by_scope[scope] = api_get_repositories(server, token, 1, 20, None, scope).json()["count"]

    return repos_by_scope


def get_enforcer_count_by_scope(server, token, scopes_list):
    """Get enforcer count by scope"""
    from .enforcers import get_enforcer_count
    
    enforcers_by_scope = {}

    for scope in scopes_list:
        enforcers_by_scope[scope] = get_enforcer_count(server, token, None, scope)

    return enforcers_by_scope