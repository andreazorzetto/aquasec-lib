# Changelog

All notable changes to the aquasec library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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