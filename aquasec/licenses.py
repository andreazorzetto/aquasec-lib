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
        print(api_url)

    res = requests.get(url=api_url, headers=headers, verify=False)
    return res


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
        'malware_protection': False
    }

    res = api_get_licenses(csp_endpoint, token, verbose)

    licenses["num_active"] = res.json()["details"]["num_active"]

    licenses_data = res.json()["data"]
    if verbose:
        print(licenses_data)

    for license in licenses_data:
        if license["status"] == "Active":
            licenses["num_repositories"] += license["products"]["num_repositories"]
            licenses["num_enforcers"] += license["products"]["num_enforcers"]
            licenses["num_microenforcers"] += license["products"]["num_microenforcers"]
            licenses["num_vm_enforcers"] += license["products"]["num_vm_enforcers"]
            licenses["num_functions"] += license["products"]["num_functions"]
            licenses["num_code_repositories"] += license["products"]["num_code_repositories"]
            licenses["num_advanced_functions"] += license["products"]["num_advanced_functions"]
            licenses["vshield"] = license["products"]["vshield"]
            licenses["num_protected_kube_nodes"] += license["products"]["num_protected_kube_nodes"]
            licenses["malware_protection"] = license["products"]["malware_protection"]

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