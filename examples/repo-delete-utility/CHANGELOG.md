# Changelog

All notable changes to the Aqua Repository Delete Utility will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2] - 2024-09-19

### Improved
- Replaced verbose list output with clean table format:
  - Repository names in left column
  - Image count in right column
  - Status indicators (✓/✗) for apply mode
  - Better handling of long repository names
  - Error messages displayed in Images column for failed deletions

## [0.1.1] - 2024-09-19

### Fixed
- HTTP 202 (Accepted) responses now correctly treated as successful deletions
- Improved verbose output formatting:
  - Removed repetitive "WOULD DELETE" prefix in dry-run mode
  - Added clear header indicating mode ("Deleting repositories" vs "Repositories that would be deleted")
  - Simplified output with checkmarks (✓) for success and crosses (✗) for failures

## [0.1.0] - 2024-09-19

### Added
- Initial release of Aqua Repository Delete Utility
- Safety-first design with mandatory dry-run mode by default
- `--apply` flag required for actual repository deletions
- Flexible filtering options:
  - `--registry` for specific registry filtering
  - `--host-images` convenience flag for "Host Images" registry
  - `--empty-only` for deleting repositories with 0 images
- Multiple output formats:
  - JSON output by default for programmatic use
  - Verbose table output with `-v` flag
  - Debug mode with `-d` flag showing API calls
- Profile-based authentication system
- Comprehensive error handling and failure reporting
- Pagination support for large repository lists
- Full test coverage with unit and integration tests
- Detailed documentation and usage examples

### Features
- Bulk repository deletion with safety controls
- Interactive setup wizard for credential management
- Profile management commands (list, info, delete, set-default)
- Real-time progress tracking and summary reporting
- Dry-run mode preview of all operations
- Secure credential storage with encryption
- Cross-platform compatibility (Python 3.8+)

### Security
- All credentials stored encrypted at rest
- No credentials exposed in logs or output
- Bearer token authentication for API calls
- Mandatory confirmation for destructive operations