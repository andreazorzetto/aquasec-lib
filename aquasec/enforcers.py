"""
Enforcer-related API functions for Andrea library
"""

import requests
import sys


def api_get_enforcer_groups(server, token, enforcer_group=None, scope=None, page_index=1, page_size=100, verbose=False):
    """Get enforcer groups and enforcers"""
    if enforcer_group:
        api_url = server + "/api/v1/hosts?batch_name=" + enforcer_group + "&page=" + str(
            page_index) + "&pagesize=" + str(page_size) + "&type=enforcer"
    elif scope:
        api_url = server + "/api/v1/hostsbatch?orderby=id asc&scope=" + scope + "&page=" + str(
            page_index) + "&pagesize=" + str(page_size)
    else:
        api_url = server + "/api/v1/hostsbatch?orderby=id asc&page=" + str(page_index) + "&pagesize=" + str(page_size)

    headers = {'Authorization': f'Bearer {token}'}

    if verbose:
        print(api_url)

    res = requests.get(url=api_url, headers=headers, verify=False)

    return res


def get_enforcers_from_group(server, token, group=None, page_index=1, page_size=100, verbose=False):
    """Get all enforcers from a specific group"""
    enforcers = {
        "count": 0,
        "result": []
    }

    while True:
        res = api_get_enforcer_groups(server, token, group, None, page_index, page_size, verbose)

        if res.status_code == 200:
            if res.json()["result"]:
                # save count
                enforcers["count"] = res.json()["count"]

                # add enforcers to list
                enforcers["result"] += res.json()["result"]

                # increase page number
                page_index += 1

            # found all enforcers
            else:
                break
        else:
            print("Requested terminated with error %d" % res.status_code)
            if verbose: 
                print(res.json())
            sys.exit(1)

    return enforcers


def get_enforcer_groups(server, token, scope=None, page_index=1, page_size=100, verbose=False):
    """Get all enforcer groups, optionally filtered by scope"""
    enforcer_groups = {
        "count": 0,
        "result": []
    }

    while True:
        res = api_get_enforcer_groups(server, token, None, scope, page_index, page_size, verbose)

        if res.status_code == 200:
            if res.json()["result"]:
                # save count
                enforcer_groups["count"] = res.json()["count"]

                # add enforcer groups to list
                enforcer_groups["result"] += res.json()["result"]

                # increase page number
                page_index += 1

            # found all enforcers
            else:
                break
        else:
            print("Requested terminated with error %d" % res.status_code)
            if verbose: 
                print(res.json())
            sys.exit(1)

    return enforcer_groups


def get_enforcer_count(server, token, group=None, scope=None, verbose=False):
    """Get enforcer count using efficient direct API calls"""
    enforcer_counter = {
        "agent": 0,
        "kube_enforcer": 0,
        "host_enforcer": 0,
        "micro_enforcer": 0,
        "nano_enforcer": 0,
        "pod_enforcer": 0
    }

    # If specific group is requested, fall back to original method for accuracy
    if group:
        enforcers = get_enforcers_from_group(server, token, group, verbose=verbose)
        
        # iterate through enforcers
        for enforcer in enforcers["result"]:
            # Only count connected enforcers
            if enforcer["status"] == "disconnect":
                continue
                
            # extract type from enforcer
            enforcer_type = enforcer["type"]

            # map to enforcer counter
            if enforcer_type in ["agent", "host", "audit"]:
                key = "agent"
            elif enforcer_type == "kube_enforcer":
                key = "kube_enforcer"
            elif enforcer_type == "vm_enforcer":
                key = "host_enforcer"
            elif enforcer_type == "micro_enforcer":
                key = "micro_enforcer"
            elif enforcer_type == "nano_enforcer":
                key = "nano_enforcer"
            elif enforcer_type == "pod_enforcer":
                key = "pod_enforcer"
            else:
                if verbose:
                    print("Enforcer_type not supported in enforcer counter for %s, type: %s" % (
                        enforcer["logicalname"], enforcer_type))
                continue

            # add to correct counter (only connected)
            enforcer_counter[key] += 1

    # Use efficient direct API calls for total counts (with optional scope)
    else:
        # Define enforcer type mappings to API types
        api_type_mappings = [
            ("agent", "agent"),
            ("kube_enforcer", "kube_enforcer"),
            ("micro_enforcer", "micro_enforcer"),
            ("host_enforcer", "host_enforcer")
        ]
        
        if verbose:
            if scope:
                print(f"Getting enforcer counts for scope: {scope}")
            else:
                print("Getting total enforcer counts using direct API calls")

        for counter_key, api_type in api_type_mappings:
            try:
                count = _get_enforcer_count_by_type(server, token, api_type, "connect", scope, verbose)
                enforcer_counter[counter_key] = count
            except Exception as e:
                if verbose:
                    print(f"Error getting {api_type} count: {e}")
                enforcer_counter[counter_key] = 0

        if verbose:
            total_count = sum(enforcer_counter.values())
            print(f"Total enforcers: {total_count}")

    return enforcer_counter


def _get_enforcer_count_by_type(server, token, enforcer_type, status, scope=None, verbose=False):
    """Helper function to get enforcer count by type and status using efficient API"""
    # Build API URL - use direct count endpoint
    api_url = f"{server}/api/v1/hosts?type={enforcer_type}&status={status}&page=1&pagesize=1"
    
    # Add scope filter if provided
    if scope:
        api_url += f"&scope={scope}"

    headers = {'Authorization': f'Bearer {token}'}

    if verbose:
        print(f"API call: {api_url}")

    try:
        res = requests.get(url=api_url, headers=headers, verify=False)
        
        if res.status_code == 200:
            response_json = res.json()
            count = response_json.get("count", 0)
            if verbose:
                print(f"  {enforcer_type} {status}: {count}")
            return count
        else:
            if verbose:
                print(f"  API error {res.status_code} for {enforcer_type} {status}")
            return 0
            
    except Exception as e:
        if verbose:
            print(f"  Request failed for {enforcer_type} {status}: {e}")
        return 0
