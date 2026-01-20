# Aqua Image Cleanup Utility

Clean up stale images from Aqua Security inventory. **Dry-run by default** - requires `--apply` to actually remove images.

Images are considered stale when they are:
- Older than N days (default: 90)
- Not running in any workload

## Installation

```bash
# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Quick Start

```bash
# Configure credentials
python aqua_image_cleanup.py setup

# Preview cleanup (dry-run)
python aqua_image_cleanup.py images cleanup -v

# Actually remove images
python aqua_image_cleanup.py images cleanup --apply
```

## Usage

### API-Based Cleanup (Default)

Fetches the image list from the Aqua API inventory:

```bash
# Clean up images older than 90 days (default) without workloads
python aqua_image_cleanup.py images cleanup

# Custom filters
python aqua_image_cleanup.py images cleanup --days 180
python aqua_image_cleanup.py images cleanup --registry myregistry
python aqua_image_cleanup.py images cleanup --scope production

# Combine filters and apply
python aqua_image_cleanup.py images cleanup --days 60 --registry myregistry --apply
```

### File-Based Cleanup (For Large Datasets)

For large inventories (100K+ images), the API-based approach can be slow. Instead, export the image list via database query and use the `--file` option:

```bash
# Preview cleanup from CSV file
python aqua_image_cleanup.py images cleanup --file /path/to/images.csv -v

# Actually remove images from CSV file
python aqua_image_cleanup.py images cleanup --file /path/to/images.csv --apply

# Custom batch size (default: 200)
python aqua_image_cleanup.py images cleanup --file /path/to/images.csv --batch-size 500 --apply
```

#### CSV Format

The CSV file must have the following columns:

```csv
"image_id","image_name","registry_id","created"
1017079,scale_repos/my-image:v1.0,my_registry,2025-10-03 15:41:37.739 +0530
1220797,nginx:latest,docker_hub,2025-10-03 15:45:45.886 +0530
```

| Column | Description |
|--------|-------------|
| `image_id` | Numeric image ID (required) |
| `image_name` | Repository and tag in format `repo:tag` |
| `registry_id` | Registry name |
| `created` | Creation timestamp (informational only) |

**Note:** File-based cleanup is idempotent - re-running on the same file is safe as already-deleted images return success.

### Options

| Flag | Description |
|------|-------------|
| `--apply` | Actually perform cleanup (default is dry-run) |
| `--file PATH` | CSV file with image list (bypasses API inventory) |
| `--batch-size N` | Batch size for deletion (default: 200, only with --file) |
| `--days N` | Age threshold in days (default: 90, only without --file) |
| `--registry NAME` | Filter by registry (only without --file) |
| `--scope NAME` | Filter by scope (only without --file) |
| `-v, --verbose` | Human-readable output instead of JSON |
| `-d, --debug` | Show debug output including API calls |
| `-p, --profile` | Configuration profile to use |

### Profile Management

```bash
python aqua_image_cleanup.py profile list
python aqua_image_cleanup.py profile info [name]
python aqua_image_cleanup.py profile delete <name>
python aqua_image_cleanup.py profile set-default <name>
```

## Example Output

```bash
$ python aqua_image_cleanup.py images cleanup -v

Images that would be removed:
  Processing page 1 (2 images)...
    - myregistry/app:v1.0.0
    - docker.io/nginx:1.19

Summary:
  Images scanned: 2
  Images to remove: 2

Filters: age >90 days, has_workloads=false

Mode: DRY RUN - No images were actually removed
Use --apply flag to actually perform the cleanup.
```

## Requirements

- Python 3.8+
- aquasec library >= 0.7.2
