# Changelog

All notable changes to the aqua-repo-breakdown utility will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2025-01-11

### Fixed
- **COMPATIBILITY**: Updated `get_app_scopes()` call to pass debug parameter
  - Fixes compatibility with aquasec library v0.4.0 
  - `get_app_scopes(server, token)` → `get_app_scopes(server, token, debug)`
- **DEBUG**: Enhanced debug output when verbose mode is enabled

### Technical Details  
- Compatible with aquasec library v0.4.0 which added verbose parameter to `get_app_scopes()`
- No functional changes to core repository breakdown logic
- Maintains backward compatibility with existing usage patterns

## [0.1.0] - Previous Release
- Initial repository breakdown functionality
- Repository scope mapping and orphaned repository detection
- CSV and JSON export capabilities
- Profile-based configuration management