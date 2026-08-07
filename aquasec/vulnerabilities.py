"""
Vulnerability API functions for Aqua Security library

Vulnerabilities are exposed at ``/api/v2/risks/vulnerabilities``. The endpoint
supports offset pagination (``page`` / ``pagesize``), which makes the obvious
implementation of a full export -- walk page 1..N until the pages run out -- the
one that does not scale.

Why walking the pages does not work
-----------------------------------
Offset pagination asks the database to produce and then discard every row before
the requested window. Reading page *p* costs roughly *p* pages of work, so a full
walk of *N* pages costs on the order of *N²/2* page-reads to return *N* pages of
data. At 400+ pages that is tens of millions of rows generated and thrown away
to return a few hundred thousand -- a two-order-of-magnitude amplification. Two
things follow, and both are observed in the wild:

- Response time climbs with page depth, so the run gets slower as it proceeds.
- Total runtime grows *quadratically* with the vulnerability count, so a tenant
  whose data grows 2x sees its export take 4x longer.

There is a third failure mode. A long-running paged read on a replica eventually
collides with replication, returning
``canceling statement due to conflict with recovery (SQLSTATE 40001)`` -- and a
failure deep into the walk is expensive to retry, because resuming means paying
the offset cost all over again.

The approach that does scale
----------------------------
Every vulnerability belongs to an image, and the same endpoint accepts an image
filter. So instead of one deep walk over the whole estate, enumerate the images
first and run one shallow, filtered query per image:

1. List images (optionally ``scope``- and ``has_workloads``-filtered) -- thousands
   of rows, tens of pages.
2. For each image, read its vulnerabilities filtered by digest (or by
   registry + exact image name). Each image has tens to hundreds of findings, so
   page depth stays in single digits and every query is selective.

The work becomes linear in the number of findings, the queries stay cheap, the
extract parallelises across images, and a failure retries one image rather than
restarting a multi-hour walk. Filtering to images that actually have running
workloads (``has_workloads=True``) usually shrinks the job by another order of
magnitude, and is applied server-side.

Better still for a bulk pull: let the server do it
---------------------------------------------------
There is a documented server-side export that avoids the read path entirely:

    POST /api/v2/risks/vulnerabilities/exporters/{entity_type}/export  -> token
    POST /api/v2/risks/vulnerabilities/exporters/{entity_type}/stream  -> ZIP

The server builds the archive and streams it back, so there is no pagination, no
session to hold open and nothing to resume. It accepts the same filters
(``severities``, ``has_workloads``, ``cluster``, ``namespace_names``,
``registry_name``, ``exploit_availability``) and lets you choose from ~118
columns, including fields the console's CSV omits.

Note this is *not* the endpoint the console's Export button uses -- that one is
under ``/api/v2/hub/findings/...`` and assembles the file in the browser, which
is why the UI warns that it depends on session timeout and browser IndexedDB and
recommends the REST API above 5M records.

Which to use:

- **Bulk "give me everything"** -> :func:`export_vulnerabilities`. One call,
  server-side, filtered.
- **Incremental, per-image, or reconciled** -> :func:`iter_all_vulnerabilities`.
  Streams results as it goes, reports which image each finding came from, and can
  be checked against the endpoint's own count.
- **Direct queries** -> :func:`api_get_vulnerabilities`.
"""

import csv
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from os.path import exists

from .common import _request_with_retry
from .inventory import get_all_inventory_images

# Transient server-side failures worth retrying. 500 covers the replication
# conflict (SQLSTATE 40001) that long reads provoke; 502/503/504 cover the
# gateway timeouts seen when a single query outlives the proxy's patience.
RETRYABLE_STATUS = (500, 502, 503, 504)


def api_get_vulnerabilities(server, token, page=1, page_size=1000, scope=None,
                            image_name=None, exact_match=True, registry_name=None,
                            digest=None, severities=None, cluster=None,
                            namespaces=None, text_search=None, has_workloads=None,
                            acknowledged=None, show_negligible=True,
                            include_vpatch_info=False, hide_base_image=False,
                            skip_count=True, verbose=False):
    """
    Query ``/api/v2/risks/vulnerabilities`` with optional filters.

    Every filter is applied server-side. Prefer narrowing by ``digest`` or by
    ``registry_name`` + ``image_name`` (with ``exact_match``) over paging deeply
    through an unfiltered result set -- see the module docstring for why.

    ``skip_count`` defaults to True: computing the total count is a separate and
    often expensive aggregate over the whole filtered set, and a paginating caller
    does not need it. Use :func:`get_vulnerability_count` when you do.

    Args:
        server: The server URL
        token: Authentication token
        page: Page number (1-based)
        page_size: Number of results per page (default 1000)
        scope: Optional application scope name to filter by
        image_name: Optional image name to filter by
        exact_match: Treat ``image_name`` as an exact match rather than a substring
        registry_name: Optional registry name filter
        digest: Optional image digest filter (the most selective image filter)
        severities: Optional severity filter (comma-separated string or list)
        cluster: Optional cluster name filter
        namespaces: Optional namespace filter (comma-separated string or list)
        text_search: Optional free-text search (e.g. a CVE identifier)
        has_workloads: Only findings on images with running workloads (True/False/None)
        acknowledged: Only acknowledged/suppressed findings (True/False/None)
        show_negligible: Include negligible-severity findings (default True)
        include_vpatch_info: Include vShield/vPatch status (default False)
        hide_base_image: Exclude findings inherited from the base image (default False)
        skip_count: Skip computing the total count (default True)
        verbose: Print debug information

    Returns:
        Response object from the API call
    """
    params = {
        'page': page,
        'pagesize': page_size,
        'skip_count': str(bool(skip_count)).lower(),
        'show_negligible': str(bool(show_negligible)).lower(),
        'include_vpatch_info': str(bool(include_vpatch_info)).lower(),
        'hide_base_image': str(bool(hide_base_image)).lower(),
    }

    if scope is not None:
        params['scope'] = scope
    if image_name is not None:
        params['image_name'] = image_name
        params['image_name_exact_match'] = str(bool(exact_match)).lower()
    if registry_name is not None:
        params['registry_name'] = registry_name
    if digest is not None:
        params['digest'] = digest
    if severities:
        params['severities'] = _as_csv(severities)
    if cluster is not None:
        params['cluster'] = cluster
    if namespaces:
        params['namespace_names'] = _as_csv(namespaces)
    if text_search is not None:
        params['text_search'] = text_search
    if has_workloads is not None:
        params['has_workloads'] = str(bool(has_workloads)).lower()
    if acknowledged is not None:
        params['acknowledge_status'] = str(bool(acknowledged)).lower()

    api_url = f"{server}/api/v2/risks/vulnerabilities"

    if verbose:
        print(f"GET {api_url}")
        print(f"Params: {params}")

    return _request_with_retry('GET', api_url, token, params=params, verbose=verbose)


def _as_csv(value):
    """Normalise a filter that may be given as a list or an already-joined string."""
    if isinstance(value, (list, tuple, set)):
        return ",".join(str(v) for v in value)
    return str(value)


def get_vulnerability_count(server, token, verbose=False, **filters):
    """
    Get the total number of vulnerabilities matching the given filters.

    Costs one aggregate query, so call it once to size a job rather than on every
    page. Accepts the same keyword filters as :func:`api_get_vulnerabilities`.

    Args:
        server: The server URL
        token: Authentication token
        verbose: Print debug information
        **filters: Any filter accepted by :func:`api_get_vulnerabilities`

    Returns:
        Number of matching vulnerabilities (int), or 0 if the call fails
    """
    filters.pop('skip_count', None)
    filters.pop('page', None)
    filters.pop('page_size', None)

    try:
        res = api_get_vulnerabilities(server, token, page=1, page_size=1,
                                      skip_count=False, verbose=verbose, **filters)
        if res.status_code == 200:
            count = res.json().get("count", 0)
            if verbose:
                print(f"Vulnerability count: {count}")
            return count
        if verbose:
            print(f"Failed to get vulnerability count: {res.status_code}")
        return 0
    except Exception as e:
        if verbose:
            print(f"Error getting vulnerability count: {e}")
        return 0


def image_ref(image):
    """
    Build the most selective vulnerability filter available for an image object.

    Image objects differ between the inventory, repository and host-image
    endpoints, so this reads whichever identity fields are present and returns the
    narrowest filter it can. A digest identifies exactly one image and is
    preferred; registry + exact name is the fallback.

    Args:
        image: An image object (dict) from any of the image-listing endpoints

    Returns:
        Dict of filter kwargs for :func:`api_get_vulnerabilities`, plus a
        ``label`` key for logging. Empty dict if the object carries no usable
        identity.
    """
    digest = image.get("digest") or image.get("image_digest")
    registry = image.get("registry") or image.get("registry_name")
    name = (image.get("name") or image.get("image_name")
            or image.get("image_repository_name") or image.get("repository"))

    # The inventory returns repository and tag separately on some versions.
    tag = image.get("tag")
    if name and tag and ":" not in name:
        name = f"{name}:{tag}"

    ref = {}
    label = None

    if registry:
        ref["registry_name"] = registry
    if name:
        ref["image_name"] = name
        ref["exact_match"] = True
        label = f"{registry}/{name}" if registry else name

    # A digest alone is enough, and stays correct even if the tag moves.
    if digest:
        ref["digest"] = digest
        label = label or digest

    if not ref:
        return {}

    ref["label"] = label
    return ref


def get_image_vulnerabilities(server, token, page_size=500, max_retries=3,
                              retry_backoff=5, verbose=False, **filters):
    """
    Get every vulnerability for a single image, paginating until complete.

    Because the query is pinned to one image, page depth stays shallow and each
    request is selective. Transient server errors are retried with a linear
    backoff -- retrying one image is cheap, which is the point of the per-image
    strategy.

    Args:
        server: The server URL
        token: Authentication token
        page_size: Number of results per page (default 500)
        max_retries: Attempts per page on a retryable error (default 3)
        retry_backoff: Seconds to wait before the first retry, scaled by attempt
        verbose: Print debug information
        **filters: Image filter, normally from :func:`image_ref` (``digest`` or
            ``registry_name`` + ``image_name``), plus any other filter accepted
            by :func:`api_get_vulnerabilities`

    Returns:
        List of vulnerability objects for the image

    Raises:
        Exception: If a page still fails after ``max_retries`` attempts
    """
    filters.pop('label', None)
    vulns = []
    page = 1

    while True:
        res = None
        last_error = None

        for attempt in range(1, max_retries + 1):
            res = api_get_vulnerabilities(server, token, page=page, page_size=page_size,
                                          verbose=verbose, **filters)
            if res.status_code == 200:
                break

            last_error = f"status {res.status_code}: {res.text[:200]}"
            if res.status_code not in RETRYABLE_STATUS or attempt == max_retries:
                break

            if verbose:
                print(f"  page {page} failed ({last_error}); retry {attempt}/{max_retries - 1}")
            time.sleep(retry_backoff * attempt)

        if res is None or res.status_code != 200:
            raise Exception(f"Vulnerability query failed after {max_retries} attempts "
                            f"({last_error})")

        results = res.json().get("result") or []
        if not results:
            break

        vulns.extend(results)

        # Loop until an empty page rather than stopping on the first short one:
        # some filters are applied after pagination, so a short page does not
        # reliably mean the last page, and stopping early would silently drop
        # findings. The extra request is cheap precisely because the query is
        # pinned to a single image.
        page += 1

    return vulns


def iter_all_vulnerabilities(server, token, scope=None, has_workloads=None,
                             registry_name=None, severities=None, images=None,
                             page_size=500, max_workers=8, max_retries=3,
                             skip_errors=True, progress=None, verbose=False,
                             **filters):
    """
    Extract every vulnerability in the estate, one image at a time.

    The scalable alternative to walking ``/api/v2/risks/vulnerabilities`` page by
    page (see the module docstring). Images are enumerated once, then queried
    concurrently, and results are yielded per image so a caller can stream them to
    disk instead of holding the whole estate in memory.

    Args:
        server: The server URL
        token: Authentication token
        scope: Optional application scope to restrict the extract to
        has_workloads: Only images with running workloads (True/False/None).
            Setting True is the single biggest reduction available when the
            question is "what is running", and is applied server-side.
        registry_name: Optional registry filter for image enumeration
        severities: Optional severity filter applied to each image's findings
        images: Pre-enumerated image objects; skips the enumeration step
        page_size: Vulnerability page size per image (default 500)
        max_workers: Images queried concurrently (default 8)
        max_retries: Attempts per page on a retryable error (default 3)
        skip_errors: Log and continue when one image fails, rather than aborting
        progress: Optional callable ``(done, total, label, count)`` invoked after
            each image completes
        verbose: Print debug information
        **filters: Any other filter accepted by :func:`api_get_vulnerabilities`,
            applied to every image's query (e.g. ``cluster``, ``namespaces``,
            ``acknowledged``, ``show_negligible``, ``include_vpatch_info``,
            ``hide_base_image``)

    Yields:
        ``(image, vulnerabilities)`` tuples -- the image object and its findings.
        Images with no findings are yielded with an empty list.

    Raises:
        Exception: If an image fails and ``skip_errors`` is False
    """
    if images is None:
        if verbose:
            print(f"Enumerating images (scope={scope}, has_workloads={has_workloads})...")
        images = get_all_inventory_images(
            server, token,
            scope=scope,
            has_workloads=has_workloads,
            registry_name=registry_name,
            verbose=verbose
        )
        if verbose:
            print(f"Found {len(images)} images to query.")

    # An image reachable through two enumeration paths would otherwise have its
    # findings emitted twice, which is the one way this walk could inflate the
    # result set relative to a full walk of the endpoint.
    #
    # The key is the *full* identity (registry + name + digest), not the digest
    # alone. Identical content is commonly registered under several names -- on a
    # real tenant 3,369 inventory entries covered only 2,041 distinct digests --
    # and the endpoint reports those as separate findings, once per image entry.
    # Keying on digest would silently drop ~15% of the result set.
    seen = set()
    deduped = []
    for image in images:
        ref = image_ref(image)
        key = (ref.get("registry_name"), ref.get("image_name"), ref.get("digest"))
        if any(part is not None for part in key):
            if key in seen:
                continue
            seen.add(key)
        deduped.append(image)

    if verbose and len(deduped) != len(images):
        print(f"Skipping {len(images) - len(deduped)} duplicate image(s).")
    images = deduped

    total = len(images)
    done = 0

    def fetch(image):
        ref = image_ref(image)
        if not ref:
            return image, [], None
        ref.pop("label", None)
        # The image's own identity always wins over a caller-supplied filter of
        # the same name; passing both would otherwise raise "multiple values for
        # keyword argument" and, with skip_errors on, silently skip every image.
        query = dict(filters)
        query.update(ref)
        try:
            vulns = get_image_vulnerabilities(
                server, token, page_size=page_size, max_retries=max_retries,
                scope=scope, severities=severities, verbose=verbose, **query
            )
            return image, vulns, None
        except Exception as e:
            return image, [], e

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(fetch, img): img for img in images}

        for future in as_completed(futures):
            image, vulns, error = future.result()
            done += 1

            if error is not None:
                if not skip_errors:
                    raise error
                label = (image_ref(image) or {}).get("label", "<unknown image>")
                print(f"WARNING: skipped {label}: {error}")
                continue

            if progress:
                progress(done, total, (image_ref(image) or {}).get("label"), len(vulns))

            yield image, vulns


def get_all_vulnerabilities(server, token, **kwargs):
    """
    Collect every vulnerability in the estate into a single list.

    Convenience wrapper over :func:`iter_all_vulnerabilities`. On a large estate
    this holds the full result set in memory -- prefer the iterator and stream to
    disk when the count runs into the hundreds of thousands.

    Args:
        server: The server URL
        token: Authentication token
        **kwargs: Any argument accepted by :func:`iter_all_vulnerabilities`

    Returns:
        Flat list of vulnerability objects
    """
    all_vulns = []
    for _image, vulns in iter_all_vulnerabilities(server, token, **kwargs):
        all_vulns.extend(vulns)
    return all_vulns


# Column order matches the console's own vulnerability CSV export, so downstream
# consumers of that file can switch to this extract without remapping fields.
CSV_COLUMNS = [
    "Registry", "Image Name", "Image Digest", "OS", "Resource", "Resource Type",
    "Resource Path", "Installed Version", "Vulnerability Name", "Publish Date",
    "Vendor Severity", "Vendor CVSS v2 Score", "Vendor CVSS v2 Vectors",
    "Vendor CVSS v3 Severity", "Vendor CVSS v3 Score", "Vendor CVSS v3 Vectors",
    "Vendor URL", "NVD CVSS v2 Severity", "NVD CVSS v2 Score",
    "NVD CVSS v2 Vectors", "NVD CVSS v3 Severity", "NVD CVSS v3 Score",
    "NVD CVSS v3 Vectors", "NVD URL", "Fix Version", "Solution", "Description",
    "vShield Status", "Acknowledged Date", "Base Image Name", "Aqua score",
    "Aqua severity", "Aqua Vectors", "Aqua custom severity", "Aqua custom notes",
    "First Found on Image", "Last Image Scan", "Exploit Availability",
    "Temporal Vector", "Exploit Type", "Namespace", "Docker Labels",
    # Appended after the console-export columns so a consumer of that file keeps
    # working unchanged while gaining the fields the console CSV does not carry.
    # Verified present on a live tenant; percentages are coverage across findings.
    # Scan Resource ID and Image UID are what actually make a row unique: without
    # them 2.1% of a real 2.1M-row extract looked like duplicates when the rows
    # were genuinely distinct detections.
    "Scan Resource ID",
    "Vulnerability ID", "CWE Info",                                  # 100%
    "EPSS Score", "EPSS Percentile",                                 # ~98%
    "Running Workloads", "Has Running Workloads", "Cluster",         # 100%
    "Image UID", "OS Version", "Architecture", "Image Build Date",
    "Aqua Scoring System", "Aqua Score Classification",
    "NVD CVSS v4 Severity", "NVD CVSS v4 Score", "NVD CVSS v4 Vectors",
    "Package CPE", "Package PURL", "Package Arch", "Package Licenses",
    "Ancestor Package",
]

# API field -> CSV column. Nested resource fields use dotted paths.
CSV_FIELD_MAP = {
    "registry": "Registry",
    "image_repository_name": "Image Name",
    "image_digest": "Image Digest",
    "os": "OS",
    "resource.name": "Resource",
    "resource.type": "Resource Type",
    "resource.path": "Resource Path",
    "resource.version": "Installed Version",
    "name": "Vulnerability Name",
    "publish_date": "Publish Date",
    "vendor_severity": "Vendor Severity",
    "vendor_cvss2_score": "Vendor CVSS v2 Score",
    "vendor_cvss2_vectors": "Vendor CVSS v2 Vectors",
    "vendor_cvss3_severity": "Vendor CVSS v3 Severity",
    "vendor_cvss3_score": "Vendor CVSS v3 Score",
    "vendor_cvss3_vectors": "Vendor CVSS v3 Vectors",
    "vendor_url": "Vendor URL",
    "nvd_cvss2_severity": "NVD CVSS v2 Severity",
    "nvd_cvss2_score": "NVD CVSS v2 Score",
    "nvd_cvss2_vectors": "NVD CVSS v2 Vectors",
    "nvd_cvss3_severity": "NVD CVSS v3 Severity",
    "nvd_cvss3_score": "NVD CVSS v3 Score",
    "nvd_cvss3_vectors": "NVD CVSS v3 Vectors",
    "nvd_url": "NVD URL",
    "fix_version": "Fix Version",
    "solution": "Solution",
    "description": "Description",
    "v_patch_status": "vShield Status",
    "acknowledged_date": "Acknowledged Date",
    "base_image_name": "Base Image Name",
    "aqua_score": "Aqua score",
    "aqua_severity": "Aqua severity",
    "aqua_vectors": "Aqua Vectors",
    "aqua_custom_severity": "Aqua custom severity",
    "aqua_custom_notes": "Aqua custom notes",
    "first_found_date": "First Found on Image",
    "last_found_date": "Last Image Scan",
    "exploit_availability": "Exploit Availability",
    "temporal_vector": "Temporal Vector",
    "exploit_type": "Exploit Type",
    "name_space": "Namespace",
    "docker_labels": "Docker Labels",

    # Fields the API returns that the console CSV does not. EPSS and the running
    # workload counts are the two that most change what you can do with the
    # export: EPSS for risk-based prioritisation, the workload counts for
    # answering "is this actually running" without a second API call.
    "scan_resource_id": "Scan Resource ID",
    "vulnerability_id": "Vulnerability ID",
    "cwe_info": "CWE Info",
    "epss_score": "EPSS Score",
    "epss_percentile": "EPSS Percentile",
    "num_running_workloads": "Running Workloads",
    "has_running_workloads": "Has Running Workloads",
    "cluster": "Cluster",
    "image_uid": "Image UID",
    "os_version": "OS Version",
    "architecture": "Architecture",
    "image_build_date": "Image Build Date",
    "aqua_scoring_system": "Aqua Scoring System",
    "aqua_score_classification": "Aqua Score Classification",
    "nvd_cvss4_severity": "NVD CVSS v4 Severity",
    "nvd_cvss4_score": "NVD CVSS v4 Score",
    "nvd_cvss4_vectors": "NVD CVSS v4 Vectors",
    "resource.cpe": "Package CPE",
    "resource.purl": "Package PURL",
    "resource.arch": "Package Arch",
    "resource.licenses": "Package Licenses",
    "ancestor_pkg": "Ancestor Package",
}


def finding_key(vuln):
    """
    Return the identity of a *finding* -- one CVE on one package in one image.

    This is the granularity the API returns: the same CVE appears once per
    affected image (and once per affected package within it), which is why an
    estate-wide export runs to hundreds of thousands of rows while the number of
    distinct CVEs is orders of magnitude smaller.

    Used to de-duplicate when the same image is reachable through more than one
    enumeration path.

    Args:
        vuln: A vulnerability object (dict) from the API

    Returns:
        Tuple identifying the finding
    """
    resource = vuln.get("resource") or {}

    # The scan resource and image UIDs are the row's real identity. The same CVE
    # on the same package at the same path is legitimately reported more than
    # once per image, and without these a real 2.1M-row extract showed 2.1%
    # false duplicates -- rows that a naive de-duplication would have destroyed.
    scan_resource_id = vuln.get("scan_resource_id")
    if scan_resource_id is not None:
        return ("scan_resource", scan_resource_id, vuln.get("name"))

    return (
        vuln.get("name"),
        vuln.get("registry"),
        vuln.get("image_uid"),
        # Both the name and the digest: identical content is routinely registered
        # under several names, and the endpoint reports each as its own finding.
        # Keying on the digest alone would collapse genuinely distinct images --
        # on a real tenant one digest was shared by six separately-registered
        # images, each with its own 92 findings.
        vuln.get("image_repository_name") or vuln.get("image_name"),
        vuln.get("image_digest"),
        resource.get("name"),
        resource.get("version"),
        resource.get("path"),
    )


def unique_cves(vulns):
    """
    Collapse findings to one entry per distinct CVE, counting where each appears.

    The per-image walk and a full walk of the endpoint return the same findings,
    so both need this step to answer "which distinct CVEs do we have". Doing it
    while streaming a per-image extract is cheaper than doing it afterwards.

    Args:
        vulns: Iterable of vulnerability objects

    Returns:
        Dict mapping CVE name -> summary dict with ``severity``, ``occurrences``,
        ``image_count`` and a sorted ``images`` list
    """
    summary = {}

    for vuln in vulns:
        cve = vuln.get("name")
        if not cve:
            continue

        image = (vuln.get("image_repository_name") or vuln.get("image_name")
                 or vuln.get("image_digest"))

        entry = summary.get(cve)
        if entry is None:
            entry = summary[cve] = {
                "cve": cve,
                "severity": vuln.get("aqua_severity") or vuln.get("vendor_severity") or "",
                "occurrences": 0,
                "images": set(),
            }
        entry["occurrences"] += 1
        if image:
            entry["images"].add(image)

    for entry in summary.values():
        entry["images"] = sorted(entry["images"])
        entry["image_count"] = len(entry["images"])

    return summary


def summarise_by_image(image, vulns):
    """
    Summarise one image's findings, for a per-image breakdown alongside the export.

    Args:
        image: The image object the findings came from
        vulns: That image's vulnerability objects

    Returns:
        Dict with the image's identity, total findings, distinct CVE count and a
        per-severity breakdown
    """
    ref = image_ref(image) or {}
    severities = {}
    cves = set()

    for vuln in vulns:
        severity = (vuln.get("aqua_severity") or vuln.get("vendor_severity") or "unknown").lower()
        severities[severity] = severities.get(severity, 0) + 1
        if vuln.get("name"):
            cves.add(vuln["name"])

    return {
        "image": ref.get("label") or "",
        "registry": image.get("registry") or image.get("registry_name") or "",
        "digest": image.get("digest") or image.get("image_digest") or "",
        "findings": len(vulns),
        "distinct_cves": len(cves),
        "critical": severities.get("critical", 0),
        "high": severities.get("high", 0),
        "medium": severities.get("medium", 0),
        "low": severities.get("low", 0),
        "negligible": severities.get("negligible", 0),
    }


IMAGE_SUMMARY_COLUMNS = [
    "image", "registry", "digest", "findings", "distinct_cves",
    "critical", "high", "medium", "low", "negligible",
]


def write_image_summary_csv(rows, filename):
    """
    Write the per-image breakdown to CSV.

    Args:
        rows: Iterable of dicts from :func:`summarise_by_image`
        filename: Destination CSV path

    Returns:
        Number of rows written
    """
    written = 0
    with open(filename, mode="w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=IMAGE_SUMMARY_COLUMNS)
        writer.writeheader()
        for row in rows:
            writer.writerow({column: row.get(column, "") for column in IMAGE_SUMMARY_COLUMNS})
            written += 1
    return written


UNIQUE_CVE_COLUMNS = ["cve", "severity", "occurrences", "image_count"]


def write_unique_cves_csv(summary, filename):
    """
    Write the distinct-CVE rollup to CSV, most widespread first.

    Args:
        summary: Dict from :func:`unique_cves`
        filename: Destination CSV path

    Returns:
        Number of rows written
    """
    rows = sorted(summary.values(), key=lambda e: (-e["image_count"], e["cve"]))

    with open(filename, mode="w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=UNIQUE_CVE_COLUMNS)
        writer.writeheader()
        for row in rows:
            writer.writerow({column: row.get(column, "") for column in UNIQUE_CVE_COLUMNS})

    return len(rows)


def _get_path(obj, path):
    """Read a possibly dotted key path out of a nested dict."""
    value = obj
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def vulnerability_to_row(vuln):
    """
    Flatten one vulnerability object into a CSV row keyed by :data:`CSV_COLUMNS`.

    Args:
        vuln: A vulnerability object (dict) from the API

    Returns:
        Dict mapping CSV column name -> value (missing fields become "")
    """
    row = {column: "" for column in CSV_COLUMNS}

    for field, column in CSV_FIELD_MAP.items():
        value = _get_path(vuln, field)
        if value is None:
            continue
        if isinstance(value, (list, dict)):
            value = str(value)
        row[column] = value

    return row


def write_vulnerabilities_csv(vulns, filename, append=False):
    """
    Write vulnerabilities to CSV, writing the header only for a new file.

    Safe to call repeatedly with ``append=True`` while streaming an extract, so a
    long run never has to hold every finding in memory.

    Args:
        vulns: Iterable of vulnerability objects
        filename: Destination CSV path
        append: Append to an existing file rather than replacing it

    Returns:
        Number of rows written
    """
    write_header = not (append and exists(filename))
    mode = "a" if append else "w"
    written = 0

    with open(filename, mode=mode, newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS)
        if write_header:
            writer.writeheader()
        for vuln in vulns:
            writer.writerow(vulnerability_to_row(vuln))
            written += 1

    return written


# ---------------------------------------------------------------------------
# Server-side export (the documented REST path)
#
# The console's own Export button drives
# /api/v2/hub/findings/vulnerabilities/images/exporters/export, which assembles
# the file in the browser -- hence the UI's own warning that it is bounded by
# session timeout and browser IndexedDB, and is only recommended under 5M
# records. The documented REST endpoints below are a different route to the same
# data: the server builds the archive and streams it back, so there is no
# session to keep alive and no client-side assembly.
#
# Prefer this over :func:`iter_all_vulnerabilities` for a bulk "give me
# everything" pull. Prefer the per-image walk when you need results as a stream
# you can process incrementally, a per-image breakdown, or reconciliation
# against the endpoint's own count.
# ---------------------------------------------------------------------------

EXPORT_ENTITY_TYPES = ("images", "hosts", "functions", "containers")

# Column sets the built-in exporters ship with. "aqua_recommended" is what the
# console's default "Compressed CSV" exporter uses.
DEFAULT_COLUMNS_NAME = "aqua_recommended"
DEFAULT_EXPORTER_NAME = "Compressed CSV"


def api_get_available_columns(server, token, entity_type="images", verbose=False):
    """
    List the columns an export can select, grouped by category.

    Worth calling before choosing columns: the set is far wider than the default
    exporter emits, and includes fields the console CSV omits entirely (EPSS,
    running-workload counts, CISA dates, package PURL, scan resource ID).

    Args:
        server: The server URL
        token: Authentication token
        entity_type: One of :data:`EXPORT_ENTITY_TYPES` (default "images")
        verbose: Print debug information

    Returns:
        Response object from the API call
    """
    api_url = f"{server}/api/v2/risks/vulnerabilities/{entity_type}/columns/available"
    if verbose:
        print(f"GET {api_url}")
    return _request_with_retry('GET', api_url, token, verbose=verbose)


def get_available_columns(server, token, entity_type="images", verbose=False):
    """
    Get selectable export columns as a flat ``name -> display name`` mapping.

    Args:
        server: The server URL
        token: Authentication token
        entity_type: One of :data:`EXPORT_ENTITY_TYPES` (default "images")
        verbose: Print debug information

    Returns:
        Dict mapping column name -> display name
    """
    res = api_get_available_columns(server, token, entity_type, verbose=verbose)
    if res.status_code != 200:
        raise Exception(f"Failed to list export columns ({res.status_code}): "
                        f"{res.text[:200]}")

    columns = {}
    for group in res.json() or []:
        for name, meta in (group.get("attributes") or {}).items():
            columns[name] = (meta or {}).get("display_name") or name
    return columns


def api_trigger_export(server, token, entity_type="images", name=DEFAULT_EXPORTER_NAME,
                       columns_name=DEFAULT_COLUMNS_NAME, columns=None, filters=None,
                       application_scope=None, order_by=None, description="",
                       split_files_by=None, split_size=None, verbose=False):
    """
    Trigger a server-side export and get a job token back.

    ``name`` must match an exporter that already exists on the tenant (the
    built-in one is "Compressed CSV"); it is not a free-text label, and an
    unknown value fails with HTTP 500 "Exporter ... not found". Either
    ``columns_name`` or ``columns`` is required -- omitting both fails with
    "Exporter columns_name or columns must be provided".

    Args:
        server: The server URL
        token: Authentication token
        entity_type: One of :data:`EXPORT_ENTITY_TYPES` (default "images")
        name: Name of an existing exporter (default "Compressed CSV")
        columns_name: Named column set (default "aqua_recommended")
        columns: Explicit comma-separated column names; overrides columns_name
        filters: Dict of server-side filters -- ``severities``, ``has_workloads``,
            ``cluster``, ``namespace_names``, ``registry_name``,
            ``exploit_availability``, ``exploit_type``, ``network_attack``,
            ``show_negligible``, ``use_estimated_count``
        application_scope: Optional application scope name
        order_by: Optional ordering field
        description: Optional free-text description
        split_files_by: Optional split strategy (e.g. "num_of_lines")
        split_size: Optional split size
        verbose: Print debug information

    Returns:
        Response object from the API call. On success the body carries ``token``.
    """
    api_url = f"{server}/api/v2/risks/vulnerabilities/exporters/{entity_type}/export"

    payload = {'name': name, 'description': description}
    if columns:
        payload['columns'] = columns if isinstance(columns, str) else ",".join(columns)
    else:
        payload['columns_name'] = columns_name
    if filters:
        payload['filter'] = filters
    if application_scope is not None:
        payload['application_scope'] = application_scope
    if order_by is not None:
        payload['order_by'] = order_by
    if split_files_by is not None:
        payload['split_files_by'] = split_files_by
    if split_size is not None:
        payload['split_size'] = split_size

    if verbose:
        print(f"POST {api_url}")
        print(f"Payload: {payload}")

    return _request_with_retry('POST', api_url, token,
                               headers={'Content-Type': 'application/json'},
                               json=payload, verbose=verbose)


def api_list_exporters(server, token, entity_type="images", verbose=False):
    """
    List the exporters defined on the tenant for an entity type.

    ``name`` on :func:`api_trigger_export` must be one of these.

    Args:
        server: The server URL
        token: Authentication token
        entity_type: One of :data:`EXPORT_ENTITY_TYPES` (default "images")
        verbose: Print debug information

    Returns:
        Response object from the API call
    """
    api_url = f"{server}/api/v2/hub/findings/vulnerabilities/{entity_type}/exporters"
    if verbose:
        print(f"GET {api_url}")
    return _request_with_retry('GET', api_url, token, verbose=verbose)


def get_exporter_names(server, token, entity_type="images", verbose=False):
    """
    Get the names of the exporters available for an entity type.

    Args:
        server: The server URL
        token: Authentication token
        entity_type: One of :data:`EXPORT_ENTITY_TYPES` (default "images")
        verbose: Print debug information

    Returns:
        List of exporter names, or an empty list if they cannot be read
    """
    try:
        res = api_list_exporters(server, token, entity_type, verbose=verbose)
        if res.status_code != 200:
            return []
        return [e.get("name") for e in (res.json().get("result") or []) if e.get("name")]
    except Exception:
        return []


def api_get_export_job(server, token, job_token, entity_type="images", verbose=False):
    """
    Get the status of an export job.

    Args:
        server: The server URL
        token: Authentication token
        job_token: The token returned by :func:`api_trigger_export`
        entity_type: One of :data:`EXPORT_ENTITY_TYPES` (default "images")
        verbose: Print debug information

    Returns:
        Response object from the API call
    """
    api_url = f"{server}/api/v2/risks/vulnerabilities/exporters/{entity_type}/jobs/{job_token}"
    if verbose:
        print(f"GET {api_url}")
    return _request_with_retry('GET', api_url, token, verbose=verbose)


def api_stream_export(server, token, job_token, entity_type="images", timeout=1800,
                      verbose=False):
    """
    Stream a triggered export back as a ZIP archive.

    This call blocks server-side until the archive is complete, so give it a
    generous timeout on a large estate.

    Args:
        server: The server URL
        token: Authentication token
        job_token: The token returned by :func:`api_trigger_export`
        entity_type: One of :data:`EXPORT_ENTITY_TYPES` (default "images")
        timeout: Seconds to wait for the archive (default 1800)
        verbose: Print debug information

    Returns:
        Response object from the API call; ``content`` is the ZIP archive
    """
    api_url = f"{server}/api/v2/risks/vulnerabilities/exporters/{entity_type}/stream"
    if verbose:
        print(f"POST {api_url} (blocking until the archive is built)")
    return _request_with_retry('POST', api_url, token,
                               headers={'Content-Type': 'application/json'},
                               json={'token': job_token}, timeout=timeout,
                               verbose=verbose)


def export_vulnerabilities(server, token, entity_type="images", filters=None,
                           name=DEFAULT_EXPORTER_NAME, columns_name=DEFAULT_COLUMNS_NAME,
                           columns=None, application_scope=None, output_file=None,
                           timeout=1800, verbose=False, **trigger_kwargs):
    """
    Run a server-side export end to end and return the ZIP archive.

    Triggers the export, then streams the archive back. The whole job runs on the
    server, so unlike a paged read there is nothing to resume and no session to
    keep alive.

    Args:
        server: The server URL
        token: Authentication token
        entity_type: One of :data:`EXPORT_ENTITY_TYPES` (default "images")
        filters: Dict of server-side filters (see :func:`api_trigger_export`)
        name: Name of an existing exporter (default "Compressed CSV")
        columns_name: Named column set (default "aqua_recommended")
        columns: Explicit column names; overrides columns_name
        application_scope: Optional application scope name
        output_file: Optional path to write the archive to
        timeout: Seconds to wait for the archive (default 1800)
        verbose: Print debug information
        **trigger_kwargs: Passed through to :func:`api_trigger_export`

    Returns:
        The ZIP archive as bytes

    Raises:
        Exception: If the trigger or the stream fails
    """
    res = api_trigger_export(server, token, entity_type=entity_type, name=name,
                             columns_name=columns_name, columns=columns,
                             filters=filters, application_scope=application_scope,
                             verbose=verbose, **trigger_kwargs)
    if res.status_code != 200:
        # An unknown exporter name comes back as a bare 500, which reads like a
        # platform fault rather than a bad argument. Name the alternatives.
        detail = res.text[:300]
        if "not found" in detail.lower():
            available = get_exporter_names(server, token, entity_type, verbose=verbose)
            if available:
                detail += f"\n  Exporters available for '{entity_type}': {available}"
        raise Exception(f"Failed to trigger export ({res.status_code}): {detail}")

    job_token = res.json().get("token")
    if not job_token:
        raise Exception(f"Export trigger returned no token: {res.text[:200]}")
    if verbose:
        print(f"Export job token: {job_token}")

    stream = api_stream_export(server, token, job_token, entity_type=entity_type,
                               timeout=timeout, verbose=verbose)
    if stream.status_code != 200:
        raise Exception(f"Failed to stream export ({stream.status_code}): "
                        f"{stream.text[:300]}")

    archive = stream.content
    if not archive[:2] == b'PK':
        raise Exception("Export stream did not return a ZIP archive")

    if output_file:
        with open(output_file, "wb") as handle:
            handle.write(archive)
        if verbose:
            print(f"Wrote {len(archive):,} bytes to {output_file}")

    return archive


def extract_export_csv(archive, output_file):
    """
    Write an export archive's CSV to disk without holding it in memory.

    Prefer this over :func:`read_export_archive` for anything estate-sized. The
    archive compresses extremely well -- a real 2.1M-row export was 32 MB zipped
    -- so materialising it as Python dicts is wildly disproportionate: the same
    archive costs ~6.8 GB of RSS as a list of dicts. This streams row by row and
    stays flat.

    Where the export was split across several CSV members, they are concatenated
    and only the first header is kept.

    Args:
        archive: ZIP archive bytes, as returned by :func:`export_vulnerabilities`
        output_file: Destination CSV path

    Returns:
        Number of data rows written (excluding the header)
    """
    import io
    import zipfile

    written = 0
    header_written = False

    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        csv_names = sorted(n for n in bundle.namelist() if n.lower().endswith(".csv"))

        with open(output_file, "w", newline="", encoding="utf-8") as out:
            writer = csv.writer(out)
            for csv_name in csv_names:
                with bundle.open(csv_name) as raw:
                    stream = io.TextIOWrapper(raw, encoding="utf-8", errors="replace",
                                              newline="")
                    for i, row in enumerate(csv.reader(stream)):
                        if i == 0:
                            if header_written:
                                continue        # one header across split files
                            header_written = True
                        else:
                            written += 1
                        writer.writerow(row)

    return written


def read_export_archive(archive):
    """
    Read the CSV out of an export archive into memory.

    Convenient for a filtered or small export. For an estate-sized one use
    :func:`extract_export_csv` instead -- a 32 MB archive of 2.1M rows costs
    ~6.8 GB of RSS once parsed into dicts.

    The archive holds ``aqua_export.csv`` alongside a ``manifest.json``.

    Args:
        archive: ZIP archive bytes, as returned by :func:`export_vulnerabilities`

    Returns:
        (rows, manifest) -- rows is a list of dicts keyed by the CSV's own
        header, manifest is the parsed manifest (or None if absent)
    """
    import io
    import json
    import zipfile

    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        manifest = None
        if "manifest.json" in bundle.namelist():
            try:
                manifest = json.loads(bundle.read("manifest.json"))
            except Exception:
                manifest = None

        csv_names = [n for n in bundle.namelist() if n.lower().endswith(".csv")]
        rows = []
        for csv_name in csv_names:
            text = bundle.read(csv_name).decode("utf-8", "replace")
            rows.extend(csv.DictReader(io.StringIO(text)))

    return rows, manifest
