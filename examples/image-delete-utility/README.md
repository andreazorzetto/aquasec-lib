# Aqua Image Delete Utility

A safety-first command-line tool for bulk deletion of stale images from Aqua Security platform.

## Features

- **Dry-run mode by default** - requires `--apply` flag for actual deletions
- Delete images registered more than X days ago (default: 90 days)
- Filter by images without running containers (workloads)
- Filter by registry or scope
- Clean table output with status indicators and progress tracking
- Profile-based authentication with interactive setup
- Per-page batch deletion (200 images per API call)

## Installation

### Prerequisites

- Python 3.8+
- aquasec library >= 0.6.0

### Setup

1. Create and activate a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure credentials:
```bash
python aqua_image_delete.py setup
```

## Usage

### Basic Commands

```bash
# Interactive setup for credentials
python aqua_image_delete.py setup

# Dry-run: Preview what would be deleted (default: 90 days, no workloads)
python aqua_image_delete.py images delete

# Actually delete the stale images
python aqua_image_delete.py images delete --apply

# Custom age threshold (180 days)
python aqua_image_delete.py images delete --days 180

# Filter by registry
python aqua_image_delete.py images delete --registry myregistry

# Filter by scope
python aqua_image_delete.py images delete --scope production

# Combine filters
python aqua_image_delete.py images delete --days 60 --registry myregistry --apply
```

### Global Options

These can be placed before or after the command:

- `-v, --verbose` - Show human-readable table output instead of JSON
- `-d, --debug` - Show debug output including API calls
- `-p, --profile NAME` - Use a specific configuration profile (default: default)
- `--version` - Show program version

### Profile Management

```bash
# List all profiles
python aqua_image_delete.py profile list

# Show profile information
python aqua_image_delete.py profile info
python aqua_image_delete.py profile info production

# Delete a profile
python aqua_image_delete.py profile delete old-profile

# Set default profile
python aqua_image_delete.py profile set-default production
```

## Examples

### Preview stale images (dry-run)

```bash
$ python aqua_image_delete.py images delete -v

Images that would be deleted:
+--------+----------------------------------+--------+
| Status | Image                            | UID    |
+--------+----------------------------------+--------+
|        | myregistry/app:v1.0.0           | 143420 |
|        | myregistry/api:latest           | 143421 |
|        | docker.io/nginx:1.19            | 143422 |
+--------+----------------------------------+--------+

Summary:
+------------------+-------+
| Metric           | Count |
+------------------+-------+
| Images Scanned   |     3 |
| Images To Delete |     3 |
+------------------+-------+

Filters Applied:
+---------------+----------+
| Filter        | Value    |
+---------------+----------+
| Age Threshold | >90 days |
| Has Workloads | No       |
+---------------+----------+

Mode: DRY RUN - No images were actually deleted
Use --apply flag to actually perform the deletions.
```

### Delete with apply

```bash
$ python aqua_image_delete.py images delete --apply -v

Deleting images:
+--------+----------------------------------+--------+
| Status | Image                            | UID    |
+--------+----------------------------------+--------+
| ✓      | myregistry/app:v1.0.0           | 143420 |
| ✓      | myregistry/api:latest           | 143421 |
| ✓      | docker.io/nginx:1.19            | 143422 |
+--------+----------------------------------+--------+

Summary:
+----------------+-------+
| Metric         | Count |
+----------------+-------+
| Images Scanned |     3 |
| Images Deleted |     3 |
+----------------+-------+

Mode: APPLIED - Images were actually deleted!
```

### JSON output (default)

```bash
$ python aqua_image_delete.py images delete --days 60

{
  "mode": "dry_run",
  "summary": {
    "images_scanned": 3,
    "images_would_delete": 3,
    "images_failed": 0
  },
  "filters": {
    "days": 60,
    "registry": null,
    "scope": null,
    "has_workloads": false
  },
  "deletions": [
    {
      "image_uid": 143420,
      "registry": "myregistry",
      "repository": "app",
      "tag": "v1.0.0",
      "name": "myregistry/app:v1.0.0"
    }
  ]
}
```

## How It Works

1. **Query Hub Inventory API** - Fetches images registered more than X days ago without running workloads
2. **Apply Filters** - Client-side filtering by registry if specified
3. **Batch Delete** - Deletes images in batches of 200 (per page) for efficiency
4. **Track Progress** - Shows success/failure status for each batch

## Safety Features

- **Dry-run by default**: No deletions happen unless `--apply` is specified
- **Verbose mode**: See exactly what will be deleted before applying
- **Batch processing**: Partial success is preserved if a batch fails
- **Clear status indicators**: ✓ for success, ✗ for failure

## Library Documentation

This utility uses the `aquasec` library. For detailed API documentation, see the main [README](../../README.md).
