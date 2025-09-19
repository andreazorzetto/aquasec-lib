# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is the `aquasec` Python library - a clean API interface for interacting with Aqua Security platform. It's distributed via PyPI and provides reusable components extracted from the andreactl tool for building Aqua Security utilities.

## Development Commands

### Installation & Setup
```bash
# Install in development mode
pip install -e .

# Install dependencies 
pip install -r requirements.txt
```

### Testing
```bash
# Main library tests (when implemented)
python -m pytest tests/ --cov=aquasec --cov-report=xml

# Test specific examples
cd examples/license-utility && python -m pytest tests/ -v --tb=short
cd examples/repo-breakdown && python -m pytest tests/ -v --tb=short  
cd examples/vm-extract && python -m pytest tests/ -v --tb=short
```

### Build & Distribution
```bash
# Build distribution packages
python setup.py sdist bdist_wheel

# Check package before publishing
twine check dist/*
```

### Example Testing
```bash
# Test CLI help for examples
cd examples/license-utility && python aqua_license_util.py --help
cd examples/repo-breakdown && python aqua_repo_breakdown.py --help
cd examples/vm-extract && python aqua_vm_extract.py --help
```

## Library Architecture

### Core Module Structure
- **auth.py**: Authentication functions (API keys, username/password for SaaS/on-prem)
- **config.py**: Comprehensive configuration management with encrypted credential storage
- **licenses.py**: License API calls and utilization analysis 
- **repositories.py**: Container image repository management
- **code_repositories.py**: Source code repository functions
- **enforcers.py**: Enforcer group and count management (optimized in v0.4.0)
- **functions.py**: Serverless functions API calls (added in v0.4.0)
- **vms.py**: VM inventory management with filtering (added in v0.5.0)
- **scopes.py**: Application scope functions
- **common.py**: Utility functions for data export and processing

### Authentication Flow
1. Credentials stored via `ConfigManager` with encryption
2. `load_profile_credentials()` loads from saved profiles
3. `authenticate()` handles token acquisition
4. All API calls use bearer tokens

### Configuration System
- Profile-based credential management with encryption
- Support for multiple environments (production, staging, etc.)
- Interactive setup wizard via `interactive_setup()`
- Secure credential storage using cryptography library

### API Integration Patterns
- All API modules follow consistent patterns: `api_get_*()` for raw calls, `get_*()` for processed data
- Pagination handling built-in for large datasets
- Verbose mode support for debugging API calls
- Structured error handling and logging

## Production Examples

The `examples/` directory contains three production-ready utilities demonstrating library usage:

1. **license-utility/**: License utilization analysis and reporting
2. **repo-breakdown/**: Repository scope analysis and orphan detection  
3. **vm-extract/**: VM inventory extraction with advanced filtering

Each example includes:
- Comprehensive CLI interface with argparse
- Profile-based authentication
- Multiple output formats (table, JSON, CSV)
- Unit tests and CI integration
- Requirements and test requirements files

## CI/CD Configuration

### GitHub Actions Workflows
- **test.yml**: Comprehensive testing across Python 3.8-3.11
- **security.yml**: Security scanning and SARIF reporting
- **publish-library.yml**: PyPI package publishing

### Testing Strategy
- Path-based change detection for targeted testing
- Library tests + individual example tests
- CLI functionality validation
- Multi-Python version compatibility testing

## Key Design Patterns

### Modular API Design
Each domain (licenses, enforcers, VMs, etc.) has its own module with consistent patterns:
- Raw API functions prefixed with `api_`
- Higher-level convenience functions for common operations
- Built-in filtering and data processing capabilities

### Configuration Management
Secure, profile-based credential storage with:
- Encryption of sensitive data
- Multiple profile support for different environments
- Interactive setup and management functions
- Validation and testing capabilities

### Error Handling
- Structured error responses throughout
- User-friendly error messages
- API response validation
- Graceful fallbacks where appropriate

## Version Information

Current version: 0.6.0 (see setup.py and aquasec/__init__.py)

Major versions:
- v0.4.0: Added serverless functions support, enforcer optimizations
- v0.5.0: Added comprehensive VM inventory module
- v0.6.0: Added repository deletion functionality and bulk delete utility