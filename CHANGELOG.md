# Changelog

All notable changes to the aquasec library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.11.0] - 2026-08-07

### Added
- **NEW**: `vulnerabilities.py` module for vulnerability findings (`/api/v2/risks/vulnerabilities`)
  - `api_get_vulnerabilities()`: Raw call with scope/image/registry/digest/severity/cluster/namespace/workload/acknowledged filters, all passed as request params so they are URL-encoded correctly. `skip_count` defaults to `true` — the total count is a separate aggregate over the whole filtered set, and a paginating caller does not need it on every request
  - `get_vulnerability_count()`: One-off count for sizing a job
  - `image_ref()`: Builds the most selective filter available for an image object (digest preferred, registry + exact name as fallback), tolerating the differing field names returned by the inventory, repository and host-image endpoints
  - `get_image_vulnerabilities()`: All findings for a single image, with retry and backoff on retryable server errors
  - `iter_all_vulnerabilities()`: Per-image extraction across the estate, parallelised, yielding `(image, findings)` so callers can stream to disk
  - `get_all_vulnerabilities()`: List-returning convenience wrapper
  - `vulnerability_to_row()` / `write_vulnerabilities_csv()`: Flatten findings to CSV using the console export's own column order, appendable so a long run never holds the estate in memory
  - `finding_key()`: Identity of a finding — `scan_resource_id` + CVE where available, falling back to (CVE, registry, image UID, image, digest, package, version, path). A row from the endpoint is one *occurrence*, not a unique CVE
  - `unique_cves()` / `write_unique_cves_csv()`: Roll findings up to distinct CVEs, with occurrence and affected-image counts
  - `summarise_by_image()` / `write_image_summary_csv()`: Per-image breakdown — findings, distinct CVEs and severity split per image
- **NEW**: Server-side vulnerability export in `vulnerabilities.py` — the **documented** REST path, and the one the UI's own dialog points you to above 5M records
  - `export_vulnerabilities()`: Trigger + stream end to end, returning the ZIP. `POST /api/v2/risks/vulnerabilities/exporters/{entity_type}/export` -> token, then `POST .../stream` -> `application/zip` (blocking, server-side)
  - `api_trigger_export()`, `api_get_export_job()`, `api_stream_export()`: The individual steps, plus `.../jobs/{token}` for status
  - `get_available_columns()`: `GET /api/v2/risks/vulnerabilities/{entity_type}/columns/available` — **118 selectable columns** across 16 groups, including `epss_score`, `scan_resource_id`, `num_running_workloads`, `cluster`, `resource.purl`, `cisa_due_date`, `is_remote_exploit`
  - `read_export_archive()`: Reads `aqua_export.csv` + `manifest.json` out of the archive
  - Accepts the same server-side filters as the query API: `severities`, `has_workloads`, `cluster`, `namespace_names`, `registry_name`, `exploit_availability`, `exploit_type`, `network_attack`
  - `extract_export_csv()`: Stream the archive's CSV to disk — a 32 MB / 2.1M-row archive costs ~6.8 GB of RSS if parsed into dicts, ~70 MB streamed
- **NEW**: `exports.py` module for the CNAPP scheduled-export service (`https://{region}.edge.cloud.aquasec.com/cnapp/export`) — a **different service from the tenant console**, which is why no `/api/v2/...` route serves it. Authenticates with the same bearer token.
  - `resolve_region()` / `get_export_base_url()`: Derive the regional host from `AQUA_REGION`, else the token's `cspm_url` claim, else `AQUA_ENDPOINT` (`eu-1` -> `eu-central-1`, `asia-1` -> `ap-southeast-1`, `ap-2` -> `ap-southeast-2`, unprefixed -> `us-east-1`)
  - `create_export()` / `api_create_export()`: `POST /api/v1/exports` -> `export_id`, with named errors for 404 (integration missing), 409 (name taken) and 429 (at the active-export limit)
  - `get_export_capacity()`: Reads the active/limit pair, so a create can be refused with an explanation instead of a bare 429. The limit is low — 5 on the tenant verified against, which was already at 5/5
  - `get_exports()`, `get_export_entities()`, `get_integrations(only_working=True)`, `api_delete_exports()`, `api_set_export_active()`
- **NEW**: Test suite for the exports module (`tests/test_exports.py`)
- `get_all_inventory_images()`: General-purpose Hub inventory paginator with scope / `has_workloads` / registry / date filters. `get_all_stale_images()` is now a thin wrapper over it
- **NEW**: `vuln-extract` example utility — per-image vulnerability export with CSV/JSONL output, plus an `estimate` command that reports the tenant's real counts and puts deep pagination and the per-image walk side by side
- **NEW**: Test suite for the vulnerabilities module (`tests/test_vulnerabilities.py`)

### Why
- Walking `/api/v2/risks/vulnerabilities` page by page does not scale. Offset pagination makes the database produce and discard every row before the requested page, so reading page *p* costs roughly *p* pages of work and a full walk of *N* pages costs on the order of *N²/2*. At 400+ pages that is tens of millions of rows generated to return a few hundred thousand — a two-order-of-magnitude amplification. The run slows as it proceeds, total runtime grows quadratically with the data, and long reads on a replica eventually fail with `canceling statement due to conflict with recovery (SQLSTATE 40001)` at a page that is expensive to resume from.
- Every finding belongs to an image and the endpoint accepts an image filter, so enumerating images first and running one shallow, selective query per image makes the work linear, parallel, and cheap to retry. Filtering enumeration to `has_workloads=True` narrows it further, server-side.

### Note
- **The console's Export button and the documented REST export are different endpoints.** The UI calls `/api/v2/hub/findings/vulnerabilities/images/exporters/export` and assembles the file client-side — hence its own warning about session timeout and browser IndexedDB, and the 5M-record recommendation. The documented REST path is `/api/v2/risks/vulnerabilities/exporters/{entity_type}/export` + `/stream`, where the server builds the archive. Verified live end to end: filtered export returned a 25,899-byte ZIP containing 1,691 per-CVE rows in ~1s.
- Two required fields are easy to miss and both fail with HTTP **500**, not 4xx: `name` must match an **existing** exporter ("Compressed CSV"), not a free-text label; and one of `columns_name` / `columns` is mandatory.
- **The scheduled export is a push to your own destination, not a download**, and two questions about it are unresolved. `entities-data` advertises `vms`/`images`/`containers`/`code_repositories`/`functions`/`kubernetes_resources` but **not** `vulnerabilities` — yet exports of that type exist, so the discovery endpoint does not describe everything the service accepts. And the columns advertised for `images` are asset-level summaries ("Count of vulnerabilities by severity"), not one row per CVE. If `vulnerabilities` behaves the same way, this service is not a substitute for the per-finding extract. Neither could be settled: creating an export needs a free slot and a working destination integration, and the verification tenant was at 5/5 with every integration failing.
- **The two approaches return the same rows.** A vulnerability row is one (image, package, CVE) occurrence, not a unique CVE, so a full walk of the endpoint was always an image-level breakdown with the same CVE repeated across images. The per-image walk queries the same endpoint with an image filter, so the union over all images is the unfiltered set. **Verified live**: on a real tenant both approaches returned an identical 3,263-row set (0 rows unique to either) and the same 307 distinct CVEs — a 10.6× repetition factor. The only way they diverge is enumeration coverage, so `extract` reconciles against the endpoint's own count and reports any shortfall.
- **A row's real identity is `scan_resource_id` (+ `image_uid`), not the image/package/path triple.** The same CVE on the same package at the same path is legitimately reported more than once per image. On a live 2,111,019-row extract, keying without them showed 44,591 (2.1%) false duplicates; adding `image_uid` cut that to 6,412 (0.3%) and `scan_resource_id` to zero. Both are now CSV columns and part of `finding_key()`, so `--dedupe` cannot destroy genuine rows.
- CSV columns were confirmed against a live tenant. The console-export columns are retained unchanged for drop-in compatibility (several are legitimately empty — CVSS v2 is largely superseded, `v_patch_status` requires `include_vpatch_info`, custom severities are tenant-specific). Twenty fields the API returns but the console CSV omits are appended, notably **EPSS score/percentile** (~98% coverage), **running-workload counts and cluster** (100%), package **PURL/CPE**, CVSS v4, and `vulnerability_id`.
- Duplicate images are dropped before the fan-out, so an image reachable through two enumeration paths cannot inflate the result set. `--dedupe` additionally de-duplicates at finding level, at a memory cost proportional to the result set.
- **Images sharing a digest are distinct.** Identical content is routinely registered under several names — on a live tenant 3,369 inventory entries covered only 2,041 distinct digests, one of them shared by six images each reporting its own 92 findings — and the endpoint reports each entry separately. Both the enumeration de-duplication and `finding_key()` therefore key on the full identity (registry + name + digest), never the digest alone; keying on digest dropped ~15% of that tenant's findings. Relatedly, a `digest=` filter on its own matches every image sharing it, so each query is pinned with registry + exact name + digest together.
- Pagination in both new paginators deliberately continues until an **empty** page rather than stopping at the first short one: some filters are applied after pagination, so a short page does not reliably mean the last page, and stopping early would silently truncate results.

## [0.10.0] - 2026-07-30

### Added
- **Console URL normalisation**: `normalize_console_url()` accepts the forms people actually paste and returns `scheme://host[:port]` — bare host (`tenant.cloud.aquasec.com`), explicit `:443`, trailing slash, path/fragment, mixed case. Default ports are dropped; non-default ports are preserved for on-prem consoles served on e.g. `:8443`.
- **Console URL auto-detection**: Aqua SaaS tokens carry the tenant's URLs in `csp_metadata.urls`. `decode_token_claims()` and `get_console_urls_from_token()` read them, so `interactive_setup()` no longer asks for the console URL on SaaS at all — it is detected after sign-in and verified before saving. On-prem is still prompted, because sign-in there goes to the console itself.
- **Console URL validation**: `validate_console_url()` probes the console API and reports whether the URL really serves it.
- `get_console_url()` reads `CSP_ENDPOINT` from the environment and normalises it, so env/.env users get the same handling as profile users.
- `authenticate_with()` returns the token for an unsaved config/creds pair (`test_connection()` keeps its boolean contract).

### Changed
- Setup's "Set '<profile>' as the default profile?" question now defaults to yes — the profile you just configured is almost always the one you want to use next. Answering `n`/`no` still declines.

### Fixed
- **Broken profiles could be saved silently.** Sign-in happens against the regional API endpoint, so it succeeds even when the console URL is wrong; the profile then failed on every data call. Setup now verifies the console URL before saving and refuses to save a profile that cannot serve the API.
- **The tenant gateway URL is now detected.** Using the `-gw` host (e.g. `tenant-gw.cloud.aquasec.com`) is an easy mistake: it authenticates, then answers gRPC (HTTP 415) instead of REST. Setup recognises it, names the problem, and substitutes the correct console URL from the token.
- Profiles are normalised on read as well as on write, so existing profiles holding an unnormalised URL keep working without re-running setup.

### Why
- Reported from a first-run on a clean machine: a console URL entered with the `-gw` suffix produced a profile that authenticated successfully but failed on every subsequent call, with nothing pointing at the cause.

## [0.9.0] - 2026-07-24

### Added
- **NEW**: `containers.py` module for the running-container inventory (`/api/v2/containers`)
  - `api_get_containers()`: Raw call with optional scope/cluster/namespace/status filters (passed as request params so spaces/special characters are URL-encoded correctly)
  - `get_container_count()`: Total container count for a scope (reads the `count` field, pagesize=1)
  - `get_all_containers()`: Fetch all containers for the given filters with automatic pagination
  - `get_container_count_by_scope()`: Per-scope container counts
  - `container_key()`: Stable unique identifier for a container instance (`container_uid`, falling back to `id`) — used to compute scope deltas
- **NEW**: `global-scope-extract` example utility — reports the image repositories and running containers that are visible only in the Global scope (not selected by any application scope), with JSON/table/CSV output and a per-cluster/namespace breakdown of unscoped containers. Also produces a shareable multi-sheet Excel workbook (`--xlsx`) and a single self-contained, offline, theme-aware HTML dashboard (`--dashboard`): a two-pane explorer with a drag-to-resize splitter, whose left pane is an application-scope coverage heatmap (every scope's repository/container counts, unscoped "no application scope" bucket pinned neutrally, sort/search) and whose right pane lists the matched resources of whichever scope you click, in labelled sections (repositories by registry, containers by cluster, each searchable; deep-linkable via `#scope=`)
- **NEW**: Test suites for the containers module (`tests/test_containers.py`) and the utility (`examples/global-scope-extract/tests/`)

### Changed
- **Scopes**: `api_get_scopes()` now returns the response object instead of printing the error body and calling `sys.exit(1)`, matching the convention of the other `api_*` functions. `get_app_scopes()` now raises a clear `Exception` on a non-200 response (e.g. HTTP 403 when the API key lacks Access Management read permission) instead of silently exiting, so callers/CLIs can surface a meaningful error.

### Why
- Platform teams governing multi-tenant Aqua deployments need to identify the repositories and containers that are not assigned to any application scope ("Global only"), because those assets are not visible on any team's dashboard and effectively fall outside ownership. The Aqua console does not offer this out of the box (a product enhancement request tracks adding it natively); this release provides the programmatic building blocks (containers API + scope-delta utility) to produce the data on demand and on a schedule.

## [0.8.0] - 2026-06-11

### Added
- **NEW**: Added `host_images.py` module for images discovered on hosts/VMs by enforcers
  - `api_get_host_images()`: Raw call to `/api/v1/hosts/images` with optional application-scope filter (passed as a request param so spaces/special characters are URL-encoded correctly)
  - `get_host_image_count()`: Total host *image* count for a scope (reads the `count` field, pagesize=1)
  - `get_all_host_images()`: Fetch all host images for a scope with automatic pagination
  - `extract_repo_base()`: Strip tag/digest from a host image name to get the repository base name (preserves registry/port prefixes, e.g. `host:5000/path/image:tag` → `host:5000/path/image`)
  - `get_host_image_repos()`: Unique repository base names for a scope
  - `get_host_image_repo_count_by_scope()`: Per-scope unique-repository counts — the unit relevant for licensing utilization
- **NEW**: Comprehensive test suite for the host images module (17 tests covering repo-base extraction, pagination, and per-scope dedup)

### Fixed
- **CSV export**: `generate_csv_for_license_breakdown()` previously read enforcer counts as `value['agent']['connected']`, but the breakdown data carries flat integers (since the v0.4.0 enforcer structure change), so CSV export raised `TypeError: 'int' object is not subscriptable` on every row. It now normalises both int and legacy `{'connected': n}` shapes via `_enforcer_count()`, and adds a `host_image_repos` column.
- **Tests**: Updated `test_inventory.py` and `test_code_repositories.py`, which still patched `requests.get`/`requests.post` after those modules were migrated to `_request_with_retry` in v0.7.x. The stale patch targets raised `AttributeError: module has no attribute 'requests'`; they now patch `_request_with_retry` and assert on its call signature (11 tests restored to green).

### Why
- Host images land in a single bucket in the General Images tab and are not attributed to an application scope there. The Host Images API *does* support scope filtering (the enforcer group that found the image is considered behind the scenes), which lets multi-tenant operators attribute host images to a scope for per-customer licensing breakdowns. The licensing unit is the repository (base name), not each image instance, hence the tag/digest-stripped dedup.

### Technical Details
- Host images endpoint lives on the tenant console (the `ese_url` from the sign-in JWT, e.g. `https://<tenant>.cloud.aquasec.com`), not the regional login/CSPM portal
- Repository counting enumerates all host images per scope and collapses them to unique base names; `count` alone is image count, not repo count

## [0.7.2] - 2025-01-20

### Fixed
- **AUTH**: Added 10-second timeout to all authentication API requests
  - Prevents hanging on unresponsive servers
  - Affects `api_auth()`, `user_pass_saas_auth()`, and `user_pass_onprem_auth()`

### Enhanced
- **Image Cleanup Utility**: Added file-based bulk deletion mode
  - New `--file` argument to read image list from CSV file (bypasses slow API inventory extraction)
  - New `--batch-size` argument to control deletion batch size (default: 200)
  - CSV format: `image_id,image_name,registry_id,created`
  - Enables processing of 1M+ images from database queries
  - Integer conversion for image IDs (API expects int64)
  - Comprehensive test coverage for new functionality (9 new tests)

### Technical Details
- Auth timeouts apply to all three authentication methods (API key, SaaS user/pass, on-prem user/pass)
- File-based cleanup uses same batching logic as API-based cleanup
- Safe to re-run on same file (idempotent - already-deleted images return success)

## [0.6.0] - 2024-09-19

### Added
- **NEW**: Repository deletion functionality
  - `api_delete_repo()`: Delete individual repositories via DELETE API endpoint
  - Support for HTTP 202 (Accepted) async deletion responses
  - Proper error handling and status code validation
- **NEW**: Repository Delete Utility example (`examples/repo-delete-utility/`)
  - Safety-first bulk repository deletion tool with dry-run by default
  - Requires explicit `--apply` flag for actual deletions
  - Multiple filtering options: `--registry`, `--host-images`, `--empty-only`
  - Clean table-formatted output with status indicators (✓/✗)
  - Comprehensive test suite (10 tests) and full documentation
  - Profile-based authentication and configuration management

### Enhanced
- Repository module now supports both read and delete operations
- Consistent error handling and verbose output across all repository functions
- Updated library exports to include new deletion functionality

### Technical Details
- `api_delete_repo()` uses `/api/v2/repositories/{registry}/{name}` endpoint
- Repository Delete Utility follows same patterns as other production examples
- All deletion operations include proper authentication and error handling
- Table output provides clear visual feedback for bulk operations

## [0.5.1] - 2025-09-16

### Fixed
- **CRITICAL**: Fixed broken code repositories API endpoint in `code_repositories.py`
  - Changed from incorrect `/api/v2/hub/inventory/assets/code_repositories/list` to correct `/v2/build/repositories`
  - Updated to use Supply Chain API instead of Hub Inventory API
  - Fixed invalid `order_by` parameter from `"-scan_date,repository_status"` to `"-scan_date"`
  - Updated response field mapping from `count` to `total_count`
  - Added `next_page` support for proper pagination

### Added
- **NEW**: Intelligent region detection for Supply Chain API URLs
  - Added `_get_supply_chain_url()` function with smart region detection
  - Supports regional endpoints (eu-1, asia-1, au-1, etc.) and US endpoint
  - Falls back to detecting region from `AQUA_ENDPOINT` when CSP endpoint has no region info
- **NEW**: Comprehensive test suite for code repositories module
  - Unit tests for all functions including URL derivation, API calls, and pagination
  - Integration tests for license utility functionality
  - Real API testing capabilities with credential validation

### Enhanced
- **IMPROVED**: License utility debug logging for code repository operations
  - Enhanced error handling with full traceback support
  - Better import and execution debugging for troubleshooting
- **IMPROVED**: Backward compatibility maintained for all existing function signatures

### Technical Details
- Code repositories now correctly use Supply Chain API at `api.{region}.supply-chain.cloud.aquasec.com`
- Regional token handling ensures proper authentication across all regions
- License utility now correctly reports code repository counts in utilization analysis
- All changes maintain full backward compatibility with existing implementations

## [0.5.0] - 2025-01-08

### Added
- **NEW**: Added `vms.py` module with comprehensive VM inventory support
  - `api_get_vms()`: Get VMs from the hub inventory API with pagination
  - `api_get_vms_count()`: Get VM count from the server
  - `get_all_vms()`: Get all VMs with automatic pagination handling
  - `get_vm_count()`: Get total count of VMs
  - `filter_vms_by_coverage()`: Filter VMs by coverage types (enforcer, agentless, etc.)
  - `filter_vms_by_cloud_provider()`: Filter VMs by cloud provider (AWS, Azure, GCP)
  - `filter_vms_by_region()`: Filter VMs by region
  - `filter_vms_by_risk_level()`: Filter VMs by risk level (critical, high, medium, low)
- **NEW**: Full support for VM inventory operations with scope filtering
- **NEW**: Comprehensive VM filtering capabilities for onboarding analysis

### Technical Details
- VM module uses `/api/v2/hub/inventory/assets/vms/list` endpoint for inventory
- Automatic pagination with 100 VMs per page for efficiency
- Support for application scope filtering in all VM operations
- Case-insensitive filtering for cloud providers and risk levels
- Robust error handling with verbose output support

## [0.4.0] - 2025-01-11

### Added
- **NEW**: Added `functions.py` module with serverless functions support
  - `api_get_functions()`: Get serverless functions from the API
  - `get_function_count()`: Get total count of serverless functions across all scopes
- **NEW**: Added `get_repo_count()` function in `repositories.py` for efficient repository counting
- **NEW**: Consistent `verbose` parameter support across all API functions for debugging

### Changed
- **PERFORMANCE**: Completely redesigned `get_enforcer_count()` function for 50%+ performance improvement
  - Now uses direct API calls (4 calls vs 8+ recursive calls)
  - Eliminates recursive group enumeration for better efficiency
- **BREAKING**: Simplified enforcer count data structure 
  - Old format: `{"agent": {"connected": X, "disconnected": Y}}`
  - New format: `{"agent": X}` (flat integers, connected enforcers only)
- **REFACTOR**: Moved `get_repo_count_by_scope()` from `licenses.py` to `repositories.py`
  - Better module organization by functionality domain
  - Function now has comprehensive error handling

### Enhanced
- **DEBUG**: All functions now support consistent `verbose=False` parameter for detailed output
- **ERROR HANDLING**: Better error handling with comprehensive verbose output across all modules
- **API EFFICIENCY**: Direct API endpoint usage eliminates unnecessary data processing

### Technical Details
- `get_enforcer_count()` uses optimized direct API calls to `/api/v1/hosts?type=X&status=connect`
- Enhanced `get_app_scopes()` with verbose output and pagination details
- All repository functions now include robust error handling with debug output
- Functions module follows same patterns as other API modules

## [0.3.4] - 2025-01-08

### Added
- New `get_all_repositories()` function in `repositories.py` with pagination support
- Support for efficient fetching of large repository datasets (handles pagination automatically)
- Optional registry and scope filtering in `get_all_repositories()`
- Verbose logging for repository fetching progress tracking
- Enhanced repository API to handle datasets of any size efficiently

### Technical Details
- `get_all_repositories()` uses 100 items per page for optimal performance
- Automatic pagination handling with proper termination conditions
- Error handling for failed API calls with descriptive error messages
- Progress logging shows "Fetched X of Y repositories..." when verbose mode enabled

## [0.3.3] - Previous Release
- Previous functionality (baseline for this changelog)