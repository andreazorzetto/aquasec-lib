"""
Enforcer-related API functions for Aqua library
"""

import sys

from .common import _request_with_retry


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

    if verbose:
        print(api_url)

    res = _request_with_retry('GET', api_url, token, verbose=verbose)

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

    if verbose:
        print(f"API call: {api_url}")

    try:
        res = _request_with_retry('GET', api_url, token, verbose=verbose)

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


# --------------------------------------------------------------------------- #
# Enforcer group capabilities
#
# /api/v1/hostsbatch returns the full capability/settings block on every enforcer
# group, not just the counts used above. These helpers read that block so licence
# questions ("how many enforcers actually run feature X?") can be answered with a
# single paged sweep instead of per-scope fan-out.
# --------------------------------------------------------------------------- #

# Enforcer types that can act on the Advanced Malware Protection flags.
#
# A KubeEnforcer is an admission controller and a MicroEnforcer is an injected
# sidecar; neither runs malware protection. Both still carry the flags in their
# stored group settings, where they move in lockstep with other inapplicable
# settings (host_protection is set on KubeEnforcer groups, which have no host).
# Counting those groups overstates AMP usage, so they are excluded by type.
AMP_CAPABLE_TYPES = frozenset(["agent", "host_enforcer"])

# Capabilities this module can report on. Deliberately limited to AMP: the
# applicable-type matrix for the other group settings has not been verified, and
# guessing it produces silently wrong totals. Add entries only once the types a
# flag actually applies to are confirmed.
CAPABILITIES = {
    "amp": {
        "label": "Advanced Malware Protection",
        # A group counts as using AMP if EITHER control is on; both draw on the
        # same licence.
        "fields": ("antivirus_protection", "container_antivirus_protection"),
        "types": AMP_CAPABLE_TYPES,
    },
    "antivirus_protection": {
        "label": "AMP - host runtime policies",
        "fields": ("antivirus_protection",),
        "types": AMP_CAPABLE_TYPES,
    },
    "container_antivirus_protection": {
        "label": "AMP - container runtime policies",
        "fields": ("container_antivirus_protection",),
        "types": AMP_CAPABLE_TYPES,
    },
}

# Fields on a group object that carry the enforcer registration token, directly
# or embedded in a ready-to-run install command. Never export these.
SENSITIVE_GROUP_FIELDS = ("token", "install_command", "command", "pas_deployment_link")

# Group fields that are safe to export and useful for licence analysis.
GROUP_EXPORT_FIELDS = (
    "id",
    "logicalname",
    "description",
    "type",
    "enforce",
    "connected_count",
    "disconnected_count",
    "hosts_count",
    "aqua_version",
    "last_update",
)


def resolve_capability(capability):
    """Look up a capability definition, raising on anything unverified.

    Unknown capabilities are rejected rather than probed generically: a flag whose
    applicable enforcer types are unknown cannot be counted correctly, and a
    plausible-looking wrong total is worse than an error.
    """
    try:
        return CAPABILITIES[capability]
    except KeyError:
        raise ValueError(
            "Unsupported capability '%s'. Supported: %s. Other enforcer group "
            "settings are not reportable until the enforcer types they apply to "
            "have been verified." % (capability, ", ".join(sorted(CAPABILITIES)))
        )


def group_supports_capability(group, capability):
    """Whether this group's enforcer type can act on the capability at all."""
    return group.get("type") in resolve_capability(capability)["types"]


def group_has_capability(group, capability):
    """Whether the capability is actually in effect for this group.

    Requires both that a flag is set and that the group's enforcer type can act
    on it, so inert stored settings are not counted as usage.
    """
    spec = resolve_capability(capability)
    if group.get("type") not in spec["types"]:
        return False
    return any(group.get(field) is True for field in spec["fields"])


def redact_enforcer_group(group):
    """Strip registration tokens from a group object so it is safe to export."""
    return {k: v for k, v in group.items() if k not in SENSITIVE_GROUP_FIELDS}


def get_all_enforcer_groups(server, token, verbose=False):
    """Fetch every enforcer group as a list (one paged sweep of /hostsbatch).

    Raises on a non-200 instead of exiting the process, so a caller that emits
    structured output can report the failure in its own format. ``get_enforcer_groups``
    predates that convention and calls ``sys.exit()`` directly, which a caller cannot
    intercept with ``except Exception``.
    """
    groups = []
    page = 1

    while True:
        res = api_get_enforcer_groups(server, token, None, None, page, 100, verbose)

        if res.status_code != 200:
            raise Exception(
                "Failed to list enforcer groups: HTTP %d - %s" % (res.status_code, res.text)
            )

        result = res.json().get("result")
        if not result:
            break

        groups += result
        page += 1

    if verbose:
        print("Total enforcer groups retrieved: %d" % len(groups))

    return groups


def get_enforcer_groups_with_capability(server, token, capability="amp", enabled=True,
                                        groups=None, verbose=False):
    """Enforcer groups where the capability is (or is not) in effect.

    Only groups whose enforcer type can act on the capability are returned, in
    either direction: a KubeEnforcer group is neither "using AMP" nor "not using
    AMP", it is out of scope for the question.

    Pass ``groups`` to reuse an already-fetched list instead of re-querying.
    """
    if groups is None:
        groups = get_all_enforcer_groups(server, token, verbose=verbose)

    return [
        g for g in groups
        if group_supports_capability(g, capability)
        and group_has_capability(g, capability) == bool(enabled)
    ]


def _blank_counts():
    return {
        "groups_enabled": 0, "groups_disabled": 0,
        "connected_enabled": 0, "connected_disabled": 0,
        "disconnected_enabled": 0, "disconnected_disabled": 0,
        "registered_enabled": 0, "registered_disabled": 0,
    }


def get_capability_rollup(server, token, capability="amp", groups=None, verbose=False):
    """Summarise capability usage per enforcer type.

    Counts are taken from each group's own ``connected_count`` /
    ``disconnected_count`` / ``hosts_count``; summing ``connected_count`` by type
    reconciles with the per-type totals from ``get_enforcer_count``, so it is a
    sound basis for licence questions.

    Enforcer types that cannot act on the capability are reported separately under
    ``excluded_types`` rather than being folded into the totals.

    Pass ``groups`` to reuse an already-fetched list instead of re-querying.
    """
    spec = resolve_capability(capability)

    if groups is None:
        groups = get_all_enforcer_groups(server, token, verbose=verbose)

    by_type = {}
    excluded = {}

    for group in groups:
        group_type = group.get("type") or "unknown"
        connected = group.get("connected_count") or 0
        disconnected = group.get("disconnected_count") or 0
        registered = group.get("hosts_count") or 0

        if group_type not in spec["types"]:
            bucket = excluded.setdefault(group_type, {"groups": 0, "connected": 0})
            bucket["groups"] += 1
            bucket["connected"] += connected
            continue

        counts = by_type.setdefault(group_type, _blank_counts())
        suffix = "enabled" if group_has_capability(group, capability) else "disabled"
        counts["groups_" + suffix] += 1
        counts["connected_" + suffix] += connected
        counts["disconnected_" + suffix] += disconnected
        counts["registered_" + suffix] += registered

    totals = _blank_counts()
    for counts in by_type.values():
        for key in totals:
            totals[key] += counts[key]

    capable_connected = totals["connected_enabled"] + totals["connected_disabled"]
    utilization = None
    if capable_connected:
        utilization = round(100.0 * totals["connected_enabled"] / capable_connected, 1)

    if verbose:
        print("%s: %d of %d connected enforcers (%s)" % (
            spec["label"], totals["connected_enabled"], capable_connected,
            "n/a" if utilization is None else "%s%%" % utilization))

    return {
        "capability": capability,
        "label": spec["label"],
        "fields": list(spec["fields"]),
        "capable_types": sorted(spec["types"]),
        "by_type": by_type,
        "totals": totals,
        "excluded_types": excluded,
        "utilization_pct": utilization,
    }
