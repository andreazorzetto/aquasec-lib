"""
Scheduled export API functions for Aqua Security library

Aqua can push inventory and findings to a destination you own -- an S3 bucket
reached through an IAM role -- on a schedule, rather than making you pull the
data through a paginated API. This is the CNAPP export service, and it is a
*different* service from the tenant console:

    https://{region}.edge.cloud.aquasec.com/cnapp/export

It authenticates with the same bearer token, but nothing under the console's
``/api/v2/...`` namespace serves it, which is why probing the console for these
routes only ever returns 404.

Why this matters
----------------
For a nightly "give me everything" job this is the right shape. The server does
the work and writes the result to your bucket, so there is no pagination, no
session to keep alive, no request timeout to dodge, and no partial file to
resume. Compare :mod:`aquasec.vulnerabilities`, which is the right tool when you
need *filtered* or *incremental* data, or a per-image breakdown, and want it now
rather than on the next scheduled run.

What it is not
--------------
This is a **push to a destination**, not a download. Three constraints follow,
and all three are worth knowing before designing around it:

- An export needs a ``integration_id`` -- a destination integration that must
  already exist and have tested successfully. Creating one is a separate flow.
- Exports are **recurring** (``frequency``), not one-shot. Each carries a
  ``next_run``.
- Filtering is by **saved filter name**, chosen from the set the server offers
  per entity type (see :func:`get_export_entities`), not by arbitrary query
  parameters. Do not assume a filter you can express in the console UI is
  available here.

There is also a hard cap on concurrently active exports -- 5 on the tenant this
was verified against, which was already at the limit. Creating another returns
HTTP 429. :func:`get_export_capacity` reads the cap so a caller can check first
rather than discover it from a failed create.

Two things to check before relying on this for findings
-------------------------------------------------------
Verified live, and both are unresolved:

1. ``entities-data`` advertises ``vms``, ``images``, ``containers``,
   ``code_repositories``, ``functions`` and ``kubernetes_resources`` -- it does
   **not** list ``vulnerabilities``. Yet exports of ``type: "vulnerabilities"``
   and ``vm_vulnerabilities`` exist and were created somehow. So the discovery
   endpoint does not describe every type the service accepts, and a caller
   cannot rely on it to validate ``entity_type``.
2. The columns advertised for ``images`` are asset-level summaries -- "Count of
   vulnerabilities by severity", "Malware count" -- not one row per CVE. If the
   ``vulnerabilities`` type behaves the same way, this service delivers a
   findings *summary* rather than the per-finding rows that
   :mod:`aquasec.vulnerabilities` produces, and is not a substitute for it.

Neither could be settled here: creating an export needs a free slot and a
working destination integration, and the tenant used for verification was at
5/5 with every integration in a failed state. Confirm the delivered file's shape
against a real destination before designing an ingestion pipeline around it.
"""

import os

from .auth import decode_token_claims
from .common import _request_with_retry

# Aqua's regional API prefixes map to AWS-style region names, which is what the
# export service uses in its hostname. The US region carries no prefix.
PREFIX_TO_REGION = {
    'eu-1': 'eu-central-1',
    'asia-1': 'ap-southeast-1',
    'ap-2': 'ap-southeast-2',
}

DEFAULT_REGION = 'us-east-1'

EXPORT_HOST_TEMPLATE = "https://{region}.edge.cloud.aquasec.com/cnapp/export"


def _region_from_url(url):
    """Pull an Aqua regional prefix out of a URL and map it to a region name."""
    if not url:
        return None
    host = str(url).split('://')[-1].split('/')[0].lower()
    prefix = host.split('.')[0]
    if prefix in PREFIX_TO_REGION:
        return PREFIX_TO_REGION[prefix]
    # A US tenant's hostname has no regional prefix at all.
    if host.endswith('cloud.aquasec.com') or host.endswith('api.cloudsploit.com'):
        return DEFAULT_REGION
    return None


def resolve_region(token=None, verbose=False):
    """
    Work out which Aqua region this tenant lives in.

    ``AQUA_REGION`` wins when set, so an operator can always override. Otherwise
    the region is read from the token's ``cspm_url`` claim, falling back to
    ``AQUA_ENDPOINT``. Both carry the regional prefix (``eu-1``, ``asia-1``,
    ``ap-2``, or none for the US), which maps to the region name the export
    service uses in its hostname.

    Args:
        token: A bearer token, used to read the ``cspm_url`` claim
        verbose: Print which source the region came from

    Returns:
        The region name (e.g. "eu-central-1"), or None if it cannot be determined
    """
    explicit = os.environ.get('AQUA_REGION', '').strip()
    if explicit:
        if verbose:
            print(f"Region from AQUA_REGION: {explicit}")
        return explicit

    if token:
        try:
            claims = decode_token_claims(token) or {}
        except Exception:          # an on-prem or malformed token has no claims
            claims = {}
        region = _region_from_url(claims.get('cspm_url'))
        if region:
            if verbose:
                print(f"Region detected from token: {region}")
            return region

    region = _region_from_url(os.environ.get('AQUA_ENDPOINT'))
    if region and verbose:
        print(f"Region detected from AQUA_ENDPOINT: {region}")
    return region


def get_export_base_url(region=None, token=None, verbose=False):
    """
    Build the base URL of the export service for this tenant.

    Args:
        region: Region name; resolved from the token/environment when omitted
        token: A bearer token, used to resolve the region
        verbose: Print debug information

    Returns:
        The export service base URL

    Raises:
        ValueError: If the region cannot be determined
    """
    region = region or resolve_region(token, verbose=verbose)
    if not region:
        raise ValueError(
            "Could not determine the Aqua region for the export service. "
            "Set AQUA_REGION (e.g. eu-central-1) or supply region explicitly."
        )
    url = EXPORT_HOST_TEMPLATE.format(region=region)
    if verbose:
        print(f"Export service: {url}")
    return url


def api_list_exports(base_url, token, verbose=False):
    """
    List the configured exports.

    Args:
        base_url: Export service base URL (see :func:`get_export_base_url`)
        token: Authentication token
        verbose: Print debug information

    Returns:
        Response object from the API call
    """
    api_url = f"{base_url}/api/v1/exports"
    if verbose:
        print(f"GET {api_url}")
    return _request_with_retry('GET', api_url, token, verbose=verbose)


def api_get_export(base_url, token, export_id, verbose=False):
    """
    Retrieve a single export by ID.

    Args:
        base_url: Export service base URL
        token: Authentication token
        export_id: The export's ID
        verbose: Print debug information

    Returns:
        Response object from the API call
    """
    api_url = f"{base_url}/api/v1/exports/{export_id}"
    if verbose:
        print(f"GET {api_url}")
    return _request_with_retry('GET', api_url, token, verbose=verbose)


def api_create_export(base_url, token, name, integration_id, entity_type,
                      filter_name="All", frequency="weekly", export_format="csv",
                      description="", verbose=False):
    """
    Create an export.

    Args:
        base_url: Export service base URL
        token: Authentication token
        name: Export name -- must be unique (HTTP 409 if it already exists)
        integration_id: ID of an existing destination integration
        entity_type: What to export (e.g. "vulnerabilities", "images",
            "containers", "vms") -- see :func:`get_export_entities`
        filter_name: Saved filter name offered for that entity (default "All")
        frequency: How often the export runs (default "weekly")
        export_format: "csv" or "json" (default "csv")
        description: Optional free-text description
        verbose: Print debug information

    Returns:
        Response object from the API call. On success (201) the body carries
        ``export_id``. Notable failures: 404 if the destination integration does
        not exist, 409 if the name is taken, 429 if the tenant is already at its
        active-export limit.
    """
    api_url = f"{base_url}/api/v1/exports"
    payload = {
        'name': name,
        'description': description,
        'integration_id': integration_id,
        'entity_type': entity_type,
        'filter_name': filter_name,
        'frequency': frequency,
        'format': export_format,
    }

    if verbose:
        print(f"POST {api_url}")
        print(f"Payload: {payload}")

    return _request_with_retry('POST', api_url, token,
                               headers={'Content-Type': 'application/json'},
                               json=payload, verbose=verbose)


def api_delete_exports(base_url, token, export_ids, verbose=False):
    """
    Delete one or more exports.

    Args:
        base_url: Export service base URL
        token: Authentication token
        export_ids: List of export IDs to delete
        verbose: Print debug information

    Returns:
        Response object from the API call
    """
    api_url = f"{base_url}/api/v1/exports/delete"
    if verbose:
        print(f"POST {api_url} ({len(export_ids)} export(s))")

    return _request_with_retry('POST', api_url, token,
                               headers={'Content-Type': 'application/json'},
                               json={'ids': list(export_ids)}, verbose=verbose)


def api_set_export_active(base_url, token, export_id, is_active, verbose=False):
    """
    Activate or deactivate an export.

    Deactivating frees a slot against the active-export limit without deleting
    the configuration.

    Args:
        base_url: Export service base URL
        token: Authentication token
        export_id: The export's ID
        is_active: True to activate, False to deactivate
        verbose: Print debug information

    Returns:
        Response object from the API call
    """
    api_url = f"{base_url}/api/v1/exports/{export_id}/activity-status"
    if verbose:
        print(f"PUT {api_url} (is_active={is_active})")

    return _request_with_retry('PUT', api_url, token,
                               headers={'Content-Type': 'application/json'},
                               json={'is_active': bool(is_active)}, verbose=verbose)


def api_get_export_metadata(base_url, token, verbose=False):
    """
    Retrieve export metadata -- how many exports are active and the cap.

    Args:
        base_url: Export service base URL
        token: Authentication token
        verbose: Print debug information

    Returns:
        Response object from the API call
    """
    api_url = f"{base_url}/api/v1/exports/metadata"
    if verbose:
        print(f"GET {api_url}")
    return _request_with_retry('GET', api_url, token, verbose=verbose)


def api_get_export_entities(base_url, token, verbose=False):
    """
    Retrieve the entity types available for export, with their saved filters.

    Args:
        base_url: Export service base URL
        token: Authentication token
        verbose: Print debug information

    Returns:
        Response object from the API call
    """
    api_url = f"{base_url}/api/v1/exports/entities-data"
    if verbose:
        print(f"GET {api_url}")
    return _request_with_retry('GET', api_url, token, verbose=verbose)


def api_list_integrations(base_url, token, verbose=False):
    """
    List the destination integrations an export can be pointed at.

    Args:
        base_url: Export service base URL
        token: Authentication token
        verbose: Print debug information

    Returns:
        Response object from the API call
    """
    api_url = f"{base_url}/api/v1/exports/integrations"
    if verbose:
        print(f"GET {api_url}")
    return _request_with_retry('GET', api_url, token, verbose=verbose)


def get_exports(base_url, token, verbose=False):
    """
    Get the configured exports as a list.

    Args:
        base_url: Export service base URL
        token: Authentication token
        verbose: Print debug information

    Returns:
        List of export objects

    Raises:
        Exception: If the call fails
    """
    res = api_list_exports(base_url, token, verbose=verbose)
    if res.status_code != 200:
        raise Exception(f"Failed to list exports ({res.status_code}): {res.text[:200]}")
    return res.json().get("data") or []


def get_export_capacity(base_url, token, verbose=False):
    """
    Get how many exports are active and how many the tenant is allowed.

    Worth calling before creating one: the limit is low (5 on the tenant this was
    verified against) and exceeding it fails the create with HTTP 429 rather than
    queuing.

    Args:
        base_url: Export service base URL
        token: Authentication token
        verbose: Print debug information

    Returns:
        (active, limit) tuple. Either element is None if not reported.
    """
    res = api_get_export_metadata(base_url, token, verbose=verbose)
    if res.status_code != 200:
        raise Exception(f"Failed to read export metadata ({res.status_code}): "
                        f"{res.text[:200]}")
    data = res.json().get("data") or {}
    return data.get("exports_active_amount"), data.get("exports_active_limit")


def get_export_entities(base_url, token, verbose=False):
    """
    Get the exportable entity types, keyed by label.

    Use this rather than hard-coding an entity type or filter name: the set of
    saved filters is decided by the server, and is narrower than what the console
    UI lets you express interactively.

    Args:
        base_url: Export service base URL
        token: Authentication token
        verbose: Print debug information

    Returns:
        Dict mapping entity label (e.g. "vulnerabilities") -> dict with ``name``,
        ``data_columns`` and ``saved_filters`` (a list of filter names)
    """
    res = api_get_export_entities(base_url, token, verbose=verbose)
    if res.status_code != 200:
        raise Exception(f"Failed to read export entities ({res.status_code}): "
                        f"{res.text[:200]}")

    entities = {}
    for resource in (res.json().get("data") or {}).get("resources") or []:
        label = resource.get("label")
        if not label:
            continue
        entities[label] = {
            "name": resource.get("name"),
            "data_columns": resource.get("data_columns") or [],
            "saved_filters": [f.get("name") for f in (resource.get("saved_filters") or [])
                              if f.get("name")],
        }
    return entities


def get_integrations(base_url, token, only_working=False, verbose=False):
    """
    Get the destination integrations as a list.

    An integration whose ``status`` is not "succeeded" will not deliver: the
    export is created happily and then fails on every run, reporting the
    connection error rather than the data. Pass ``only_working=True`` to filter
    those out up front.

    Args:
        base_url: Export service base URL
        token: Authentication token
        only_working: Return only integrations whose status is "succeeded"
        verbose: Print debug information

    Returns:
        List of integration objects
    """
    res = api_list_integrations(base_url, token, verbose=verbose)
    if res.status_code != 200:
        raise Exception(f"Failed to list integrations ({res.status_code}): "
                        f"{res.text[:200]}")

    integrations = res.json().get("data") or []
    if only_working:
        integrations = [i for i in integrations if i.get("status") == "succeeded"]
    return integrations


def create_export(base_url, token, name, integration_id, entity_type="vulnerabilities",
                  filter_name="All", frequency="weekly", export_format="csv",
                  description="", check_capacity=True, verbose=False):
    """
    Create an export, returning its ID.

    Args:
        base_url: Export service base URL
        token: Authentication token
        name: Export name -- must be unique across the tenant
        integration_id: ID of an existing, working destination integration
        entity_type: What to export (default "vulnerabilities")
        filter_name: Saved filter name (default "All")
        frequency: How often it runs (default "weekly")
        export_format: "csv" or "json" (default "csv")
        description: Optional free-text description
        check_capacity: Check the active-export limit first and raise a clear
            error rather than letting the create fail with a bare 429
        verbose: Print debug information

    Returns:
        The new export's ID (str)

    Raises:
        Exception: If the tenant is at its export limit, or the create fails
    """
    if check_capacity:
        active, limit = get_export_capacity(base_url, token, verbose=verbose)
        if active is not None and limit is not None and active >= limit:
            raise Exception(
                f"Tenant is at its active-export limit ({active}/{limit}). "
                f"Delete or deactivate an export before creating another."
            )

    res = api_create_export(base_url, token, name=name, integration_id=integration_id,
                            entity_type=entity_type, filter_name=filter_name,
                            frequency=frequency, export_format=export_format,
                            description=description, verbose=verbose)

    if res.status_code in (200, 201):
        return res.json().get("export_id")

    hints = {
        404: "the destination integration was not found",
        409: "an export with that name already exists",
        429: "the tenant is at its active-export limit",
    }
    hint = hints.get(res.status_code)
    raise Exception(f"Failed to create export ({res.status_code}"
                    f"{': ' + hint if hint else ''}): {res.text[:200]}")
