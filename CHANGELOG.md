# Changelog

All notable changes to the aquasec library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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