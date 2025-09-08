# Changelog

All notable changes to the aqua-license-utility will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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