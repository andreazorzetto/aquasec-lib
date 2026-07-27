# Changelog

All notable changes to the aqua-license-utility will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - 2026-06-11

### Added
- **NEW**: Added `license host-images` command — per-application-scope host image breakdown
  - Host images are images discovered on hosts/VMs by enforcers; this attributes them to a scope via the scope-filtered Host Images API
  - Counts by **repository** (image base name, tag/digest stripped), the unit relevant for licensing — not each image instance
  - Reports both unique repo count and total image count per scope
  - JSON by default, table with `-v`; supports `--csv-file`, `--json-file`, `--include-global`, and `--list-repos` (include the repo names per scope in JSON)
- **NEW**: `license breakdown` now includes a **Host Images** column (unique host image repos per scope) alongside images, code repos and enforcers
  - New asset filters `--only-host-images` and `--skip-host-images` (and existing `--only-*`/`--skip-repos` now account for host images)
  - Host image repo counts added to JSON output (`host_image_repos`) and CSV export

### Fixed
- **CSV export**: `breakdown --csv-file` was broken — it read enforcer counts as nested `['connected']` while the data holds flat integers, raising `TypeError` on every row. Fixed in the library's `generate_csv_for_license_breakdown()`; CSV now also carries the `host_image_repos` column.

### Usage
```bash
# Host image utilization per application scope (table)
python aqua_license_util.py license host-images -v

# Host image repos per scope as JSON, including the repo names
python aqua_license_util.py license host-images --list-repos

# Full breakdown now includes a Host Images column
python aqua_license_util.py license breakdown -v --csv-file report.csv
```

### Notes
- The Host Images API lives on the **tenant console** URL (the `ese_url` returned in the sign-in JWT, e.g. `https://<tenant>.cloud.aquasec.com`), not the regional login/CSPM portal (e.g. `https://eu-1.cloud.aquasec.com`). Set `CSP_ENDPOINT` to the tenant console or all API calls return 401.

### Technical Details
- Requires aquasec library v0.8.0 (new `host_images` module)
- Per-scope host image counting enumerates all host images for the scope and collapses them to unique repository base names

## [0.4.0] - 2025-01-11

### Added
- **NEW**: Added `license count` command for utilization vs limits analysis
  - Shows actual usage versus license limits for all resources
  - Displays utilization percentages for finite resources
  - Includes renewal-relevant data even for unlimited resources
- **NEW**: Support for serverless functions counting and utilization tracking
  - Integrates with new `get_function_count()` from aquasec library
  - Shows functions utilization in both count and breakdown commands
- **ENHANCED**: Improved table formatting with percentage utilization display
- **ENHANCED**: Better resource mapping with comprehensive coverage

### Changed
- **PERFORMANCE**: Updated to use new optimized enforcer counting API (50%+ faster)
- **DATA**: Simplified enforcer count references (removed nested connected/disconnected structure)
- **API**: Updated `get_app_scopes()` calls to use new verbose parameter for better debugging

### Fixed
- Updated enforcer count table references for new flat data structure
- Enhanced debug output consistency across all API calls

### Usage
```bash
# New command: Show utilization vs limits
python aqua_license_util.py license count

# Enhanced breakdown with better performance  
python aqua_license_util.py license breakdown -v

# Show license limits (existing command)
python aqua_license_util.py license show -v
```

### Technical Details
- Leverages aquasec library v0.4.0 performance improvements
- Uses direct API calls for enforcer counting (4 calls vs 8+ previous)
- Functions counting includes serverless functions across all scopes
- Enhanced error handling with comprehensive debug output

## [0.3.0] - Previous Release
- Previous functionality (baseline for this changelog)