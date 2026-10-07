"""
Enforcer-related API functions for Aqua library
"""


import json

from .exceptions import ApiError
from .common import (
    _request_with_retry,
    get_show_secrets,
    path_segment,
    resolve_timeout,
    response_json,
)


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
            raise ApiError("Request terminated with error %d" % res.status_code,
                           status_code=res.status_code, response_text=res.text)

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
            raise ApiError("Request terminated with error %d" % res.status_code,
                           status_code=res.status_code, response_text=res.text)

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
    structured output can report the failure in its own format.
    """
    groups = []
    page = 1

    while True:
        res = api_get_enforcer_groups(server, token, None, None, page, 100, verbose)

        if res.status_code != 200:
            raise ApiError(
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


# --------------------------------------------------------------------------- #
# Enforcer group CRUD
#
# Groups are addressed by ``id`` -- a string the creator chooses, which is NOT
# the same field as ``logicalname`` (that one may be empty).
#
# Secrets: every read of a group returns its registration token, both on its own
# and embedded in ``install_command`` / ``command``. That is true of the list and
# of a single get, not only of create. So:
#
#   * verbose output and error messages are redacted unless the caller has
#     opted in with common.set_show_secrets(True);
#   * split_enforcer_group_secrets() separates settings from secrets for callers
#     that want to log, diff or store the settings.
# --------------------------------------------------------------------------- #

ENFORCER_GROUPS_PATH = "/api/v1/hostsbatch"

_JSON = {"Content-Type": "application/json"}
_REDACTED = "***REDACTED***"


def split_enforcer_group_secrets(group):
    """Separate a group's settings from its credential-bearing fields.

    Returns:
        (settings, secrets): two new dicts. ``settings`` is safe to log, diff and
        store; ``secrets`` holds whichever of SENSITIVE_GROUP_FIELDS were present.
    """
    settings = {k: v for k, v in group.items() if k not in SENSITIVE_GROUP_FIELDS}
    secrets = {k: group[k] for k in SENSITIVE_GROUP_FIELDS if k in group}
    return settings, secrets


def _redact(value):
    if isinstance(value, dict):
        return {k: (_REDACTED if k in SENSITIVE_GROUP_FIELDS and v else _redact(v))
                for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(v) for v in value]
    return value


def _secret_values(value, found=None):
    """Every non-empty string held in a sensitive field, anywhere in a body."""
    found = set() if found is None else found
    if isinstance(value, dict):
        for k, v in value.items():
            if k in SENSITIVE_GROUP_FIELDS and v:
                if isinstance(v, str):
                    found.add(v)
                else:
                    _all_strings(v, found)
            else:
                _secret_values(v, found)
    elif isinstance(value, list):
        for v in value:
            _secret_values(v, found)
    return found


def _all_strings(value, found):
    if isinstance(value, str) and value:
        found.add(value)
    elif isinstance(value, dict):
        for v in value.values():
            _all_strings(v, found)
    elif isinstance(value, list):
        for v in value:
            _all_strings(v, found)


def _mask(text, secrets):
    # Longest first, so a token embedded in an install command is masked whole.
    for secret in sorted(secrets, key=len, reverse=True):
        if len(secret) >= 8:
            text = text.replace(secret, _REDACTED)
    return text


def _redacted_text(res):
    """The response body with secrets masked, for use in errors.

    A non-JSON body cannot be redacted field by field, so it is not echoed at
    all -- only its length. Losing a little diagnostic detail is the right trade
    against a registration token appearing in a CI log.
    """
    body = response_json(res)
    if body is None:
        return f"<{len(res.text or '')} bytes, not shown>" if res.text else ""
    return json.dumps(_redact(body))[:500]


def _for_output(body):
    """A body as the library may print it: redacted unless secrets are shown."""
    if body is None:
        return "<empty>"
    return json.dumps(body if get_show_secrets() else _redact(body))[:4000]


def _raise_group(res, action):
    if get_show_secrets():
        raise ApiError(f"{action}: HTTP {res.status_code} - {(res.text or '').strip()[:500]}",
                       status_code=res.status_code, response_text=res.text)
    body = response_json(res)
    secrets = _secret_values(body) if body is not None else set()
    text = _mask(_redacted_text(res), secrets)
    message = text
    if isinstance(body, dict) and body.get("message"):
        # The field-level redaction cannot see a token repeated inside free
        # text, so mask every secret value found elsewhere in the body as well.
        message = _mask(str(_redact(body)["message"]), secrets)
    raise ApiError(f"{action}: HTTP {res.status_code} - {message}",
                   status_code=res.status_code, response_text=text)


def _group_url(server, group_id):
    return f"{server}{ENFORCER_GROUPS_PATH}/{path_segment(group_id)}"


def api_get_enforcer_group(server, token, group_id, timeout=None, verbose=False):
    """Get one enforcer group by id (raw call). Missing is HTTP 404.

    The response contains the group's registration token.
    """
    api_url = _group_url(server, group_id)
    if verbose:
        print(f"GET {api_url}")
    return _request_with_retry('GET', api_url, token,
                               timeout=resolve_timeout(timeout), verbose=verbose)


def api_create_enforcer_group(server, token, group, timeout=None, verbose=False):
    """Create an enforcer group (raw call). ``group`` must include ``id``.

    Gateways need not be given: Aqua assigns one. The response contains the
    registration token.
    """
    api_url = server + ENFORCER_GROUPS_PATH
    if verbose:
        print(f"POST {api_url} id={group.get('id')!r}")
    return _request_with_retry('POST', api_url, token, headers=dict(_JSON), json=group,
                               timeout=resolve_timeout(timeout), verbose=verbose)


def api_update_enforcer_group(server, token, group, update_enforcers=True, timeout=None,
                              verbose=False):
    """Replace an enforcer group (raw call). ``group`` must include ``id``.

    Aqua identifies the group from ``id`` in the body; there is no id in the
    URL. ``update_enforcers`` pushes the new settings to the group's existing
    enforcers as well as to future ones.
    """
    api_url = server + ENFORCER_GROUPS_PATH
    if verbose:
        print(f"PUT {api_url} id={group.get('id')!r} update_enforcers={update_enforcers}")
    return _request_with_retry('PUT', api_url, token, headers=dict(_JSON), json=group,
                               params={'update_enforcers': 'true' if update_enforcers else 'false'},
                               timeout=resolve_timeout(timeout), verbose=verbose)


def api_delete_enforcer_group(server, token, group_id, delete_related=False, timeout=None,
                              verbose=False):
    """Delete an enforcer group by id (raw call).

    ``delete_related`` also removes the group's enforcers, per Aqua's docs
    ("Delete an Enforcer group and its related Enforcers"). It defaults to off
    so that removing a group never silently takes its enforcers with it.
    """
    api_url = _group_url(server, group_id)
    if verbose:
        print(f"DELETE {api_url} delete_related={delete_related}")
    params = {'delete_related': 'true'} if delete_related else None
    return _request_with_retry('DELETE', api_url, token, params=params,
                               timeout=resolve_timeout(timeout), verbose=verbose)


def get_enforcer_group(server, token, group_id, timeout=None, verbose=False):
    """The complete enforcer group, or None if no group has that id.

    The result includes the registration token; see split_enforcer_group_secrets.
    """
    res = api_get_enforcer_group(server, token, group_id, timeout=timeout, verbose=verbose)
    if res.status_code == 404:
        return None
    if res.status_code != 200:
        _raise_group(res, f"Failed to get enforcer group {group_id!r}")
    group = res.json()
    if verbose:
        print(f"  response: {_for_output(group)}")
    return group


def create_enforcer_group(server, token, group, timeout=None, verbose=False):
    """Create an enforcer group.

    Returns:
        The response body (which carries the registration token) or None if
        Aqua sent none -- in which case read the group back to get the token.

    Raises:
        ValueError: if ``group`` has no id.
        ApiError: on any non-2xx response, with secrets redacted.
    """
    if not group.get("id"):
        raise ValueError("an enforcer group needs an id")
    res = api_create_enforcer_group(server, token, group, timeout=timeout, verbose=verbose)
    if not 200 <= res.status_code < 300:
        _raise_group(res, f"Failed to create enforcer group {group['id']!r}")
    created = response_json(res)
    if verbose:
        print(f"  response: {_for_output(created)}")
    return created


def update_enforcer_group(server, token, group, update_enforcers=True, strip_secrets=True,
                          timeout=None, verbose=False):
    """Replace an enforcer group with ``group`` (the complete object, with ``id``).

    ``strip_secrets`` (the default) removes the credential-bearing fields from
    the body before sending: they are server-generated, and leaving them out
    keeps the token out of any request logging along the way. Verified live: an
    update without them is accepted and the registration token is unchanged.
    """
    if not group.get("id"):
        raise ValueError("an enforcer group needs an id")
    body = split_enforcer_group_secrets(group)[0] if strip_secrets else group
    if verbose:
        print(f"  request: {_for_output(body)}")
    res = api_update_enforcer_group(server, token, body, update_enforcers=update_enforcers,
                                    timeout=timeout, verbose=verbose)
    if not 200 <= res.status_code < 300:
        _raise_group(res, f"Failed to update enforcer group {group['id']!r}")
    return response_json(res)


def delete_enforcer_group(server, token, group_id, delete_related=False, missing_ok=False,
                          timeout=None, verbose=False):
    """Delete an enforcer group. True if deleted, False if missing and ``missing_ok``."""
    res = api_delete_enforcer_group(server, token, group_id, delete_related=delete_related,
                                    timeout=timeout, verbose=verbose)
    if res.status_code == 404 and missing_ok:
        return False
    if not 200 <= res.status_code < 300:
        _raise_group(res, f"Failed to delete enforcer group {group_id!r}")
    return True
