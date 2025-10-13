# Aqua Repository Delete Utility

A focused tool for bulk deletion of image repositories from Aqua Security platform.

## Features

- **Safety-first design**: Defaults to dry-run mode, requires `--apply` flag for actual deletions
- **Flexible filtering**: Filter by registry name, empty repositories only, or use convenience flags
- **Multiple output formats**: JSON (default), verbose tables, and debug mode
- **Profile-based authentication**: Secure credential management with built-in multiple profile support
- **Progress tracking**: Real-time deletion progress and detailed summaries

## Installation

Using a virtual environment ensures dependencies are isolated and installed for the correct Python version:

```bash
cd examples/repo-delete-utility

# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate  # On Linux/Mac
# OR
.venv\Scripts\activate     # On Windows

# Install dependencies
pip install -r requirements.txt
```

## Quick Start

1. **Set up credentials** (interactive):
   ```bash
   python aqua_repo_delete.py setup
   ```

2. **Preview what would be deleted** (dry-run mode):
   ```bash
   python aqua_repo_delete.py repos delete
   ```

3. **Delete repositories** (requires --apply flag):
   ```bash
   python aqua_repo_delete.py repos delete --apply
   ```

## Usage Examples

### Basic Operations

```bash
# Interactive setup
python aqua_repo_delete.py setup

# List what would be deleted (dry-run mode, JSON output)
python aqua_repo_delete.py repos delete

# Show detailed table output
python aqua_repo_delete.py repos delete -v

# Actually delete repositories (with confirmation)
python aqua_repo_delete.py repos delete --apply

# Show debug information including API calls
python aqua_repo_delete.py repos delete -d
```

### Filtering Options

```bash
# Delete only empty repositories (0 images)
python aqua_repo_delete.py repos delete --empty-only --apply

# Filter by specific registry
python aqua_repo_delete.py repos delete --registry "MyRegistry" --apply

# Convenience flag for Host Images registry
python aqua_repo_delete.py repos delete --host-images --apply

# Combine filters: empty repositories in Host Images registry
python aqua_repo_delete.py repos delete --host-images --empty-only --apply
```

### Profile Management

```bash
# List available profiles
python aqua_repo_delete.py profile list

# Show profile information
python aqua_repo_delete.py profile info

# Use specific profile
python aqua_repo_delete.py -p production repos delete

# Set default profile
python aqua_repo_delete.py profile set-default production

# Delete a profile
python aqua_repo_delete.py profile delete old-profile
```

## Command Line Options

### Global Options

- `-v, --verbose`: Show human-readable table output instead of JSON
- `-d, --debug`: Show debug output including API calls
- `-p, --profile PROFILE`: Use specific configuration profile (default: default)
- `--version`: Show program version

### Delete Command Options

- `--apply`: Actually perform deletions (default is dry-run mode)
- `--registry REGISTRY`: Filter by registry name
- `--host-images`: Filter for "Host Images" registry (convenience flag)
- `--empty-only`: Delete only repositories with 0 images

## Output Formats

### JSON Output (Default)

```json
{
  "mode": "dry_run",
  "summary": {
    "repositories_scanned": 150,
    "repositories_would_delete": 25,
    "repositories_failed": 0
  },
  "filters": {
    "registry": "Host Images",
    "empty_only": true
  },
  "deletions": [
    {
      "registry": "Host Images",
      "name": "empty-repo-1",
      "num_images": 0
    }
  ]
}
```

### Verbose Table Output (`-v`)

```
Repositories that would be deleted:
+--------+--------------------------------------------------------+--------+
| Status | Repository                                             | Images |
+--------+--------------------------------------------------------+--------+
|        | Host Images/602401143452.dkr.ecr.us-east-2.amazonaws |      5 |
|        | Host Images/eks/coredns                               |      1 |
|        | Host Images/eks/pause                                 |      0 |
+--------+--------------------------------------------------------+--------+

Summary:
+----------------------+-------+
| Metric               | Count |
+----------------------+-------+
| Repositories Scanned |   150 |
| Repositories To Delete |    25 |
+----------------------+-------+

Filters Applied:
+------------+-------------+
| Filter     | Value       |
+------------+-------------+
| Registry   | Host Images |
| Empty Only | Yes         |
+------------+-------------+

Mode: DRY RUN - No repositories were actually deleted
Use --apply flag to actually perform the deletions.
```

## Safety Features

### Dry-Run Mode by Default

The utility **always** runs in dry-run mode unless the `--apply` flag is explicitly provided. This prevents accidental deletions.

### Detailed Preview

Before any actual deletions, you can see exactly what would be deleted:

```bash
# Preview deletions in JSON format
python aqua_repo_delete.py repos delete --registry "Test Registry"

# Preview with detailed table
python aqua_repo_delete.py repos delete --registry "Test Registry" -v
```

### Error Handling

- Failed deletions are tracked separately and reported
- API errors are captured and displayed
- Partial failures don't stop the process
- All operations are logged for audit purposes

## Configuration

The utility uses the same configuration system as other examples in this library:

- Credentials are stored encrypted using the `cryptography` library
- Multiple profiles supported for different environments
- Interactive setup wizard for easy configuration
- Profile management commands for ongoing maintenance

## Examples by Use Case

### 1. Clean up Host Images

```bash
# Preview what Host Images repositories would be deleted
python aqua_repo_delete.py repos delete --host-images -v

# Delete only empty Host Images repositories
python aqua_repo_delete.py repos delete --host-images --empty-only --apply
```

### 2. Registry Maintenance

```bash
# Clean up a specific test registry
python aqua_repo_delete.py repos delete --registry "Test Registry" --apply

# Remove all empty repositories across all registries
python aqua_repo_delete.py repos delete --empty-only --apply
```

### 3. Bulk Cleanup

```bash
# Preview full cleanup (all repositories)
python aqua_repo_delete.py repos delete -v

# Apply full cleanup with debug output
python aqua_repo_delete.py repos delete --apply -d
```

## Error Handling

### Common Errors

1. **Authentication failures**: Check profile configuration with `profile info`
2. **API endpoint issues**: Verify CSP_ENDPOINT environment variable
3. **Permission errors**: Ensure account has repository management permissions
4. **Network errors**: Check connectivity to Aqua Security platform

### Troubleshooting

```bash
# Debug authentication and API calls
python aqua_repo_delete.py repos delete -d

# Check profile configuration
python aqua_repo_delete.py profile info

# Verify setup
python aqua_repo_delete.py setup
```

## Dependencies

- Python 3.8+
- `aquasec` library (parent project)
- `cryptography` for secure credential storage
- `prettytable` for formatted output
- `requests` for API calls

## Security Considerations

- Credentials are encrypted at rest
- API calls use bearer token authentication
- No credentials are logged or exposed in output
- Dry-run mode prevents accidental deletions
- All operations require explicit confirmation via `--apply` flag

## Contributing

This utility follows the same patterns as other examples in the aquasec library. When contributing:

1. Maintain the safety-first approach
2. Follow existing code patterns and naming conventions
3. Update tests for any new functionality
4. Ensure output format consistency (JSON default, verbose tables)
5. Add appropriate error handling and logging
