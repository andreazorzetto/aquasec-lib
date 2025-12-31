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

### Options

| Flag | Description |
|------|-------------|
| `--apply` | Actually perform cleanup (default is dry-run) |
| `--days N` | Age threshold in days (default: 90) |
| `--registry NAME` | Filter by registry |
| `--scope NAME` | Filter by scope |
| `-v, --verbose` | Human-readable output instead of JSON |
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
- aquasec library >= 0.7.0
