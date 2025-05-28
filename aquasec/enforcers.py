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
    """Get enforcer count, optionally filtered by group or scope"""
    page_index = 1
    page_size = 100
    enforcer_counter = {
        "agent": {"connected": 0, "disconnected": 0},
        "kube_enforcer": {"connected": 0, "disconnected": 0},
        "host_enforcer": {"connected": 0, "disconnected": 0},
        "micro_enforcer": {"connected": 0, "disconnected": 0},
        "nano_enforcer": {"connected": 0, "disconnected": 0},
        "pod_enforcer": {"connected": 0, "disconnected": 0}
    }

    # Get count for specific enforcer group
    if group:
        enforcers = get_enforcers_from_group(server, token, group)
        
        # iterate through enforcers
        for enforcer in enforcers["result"]:
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

            # add to correct counter
            if enforcer["status"] == "disconnect":
                enforcer_counter[key]["disconnected"] += 1
            else:
                enforcer_counter[key]["connected"] += 1

    # Get count for all enforcers groups (optionally filtered by scope)
    else:
        enforcer_groups = get_enforcer_groups(server, token, scope)

        # iterate through enforcer groups
        for group in enforcer_groups["result"]:
            # get single enforcer group counts
            group_counts = get_enforcer_count(server, token, group["id"], None, verbose)

            # merge counts
            for enforcer_type, counts in group_counts.items():
                enforcer_counter[enforcer_type]["connected"] += counts["connected"]
                enforcer_counter[enforcer_type]["disconnected"] += counts["disconnected"]

    return enforcer_counter