# Changelog

All notable changes to the aquasec library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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