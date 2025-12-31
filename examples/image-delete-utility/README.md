# Aqua Image Delete Utility

Bulk delete stale images from Aqua Security Hub inventory. **Dry-run by default** - requires `--apply` to actually delete.

## Quick Start

```bash
pip install -r requirements.txt
python aqua_image_delete.py setup              # Configure credentials
python aqua_image_delete.py images delete -v   # Preview deletions (dry-run)
python aqua_image_delete.py images delete --apply  # Actually delete
```

## Usage

```bash
# Delete images older than 90 days (default) without workloads
python aqua_image_delete.py images delete

# Custom filters
python aqua_image_delete.py images delete --days 180
python aqua_image_delete.py images delete --registry myregistry
python aqua_image_delete.py images delete --scope production

# Combine filters and apply
python aqua_image_delete.py images delete --days 60 --registry myregistry --apply
```

### Options

| Flag | Description |
|------|-------------|
| `--apply` | Actually perform deletions (default is dry-run) |
| `--days N` | Age threshold in days (default: 90) |
| `--registry NAME` | Filter by registry |
| `--scope NAME` | Filter by scope |
| `-v, --verbose` | Human-readable table output instead of JSON |
| `-p, --profile` | Configuration profile to use |

### Profile Management

```bash
python aqua_image_delete.py profile list
python aqua_image_delete.py profile info [name]
python aqua_image_delete.py profile delete <name>
python aqua_image_delete.py profile set-default <name>
```

## Example Output

```bash
$ python aqua_image_delete.py images delete -v

Images that would be deleted:
+--------+---------------------------+--------+
| Status | Image                     | UID    |
+--------+---------------------------+--------+
|        | myregistry/app:v1.0.0     | 143420 |
|        | docker.io/nginx:1.19      | 143422 |
+--------+---------------------------+--------+

Summary:
+------------------+-------+
| Metric           | Count |
+------------------+-------+
| Images Scanned   |     2 |
| Images To Delete |     2 |
+------------------+-------+

Mode: DRY RUN - No images were actually deleted
Use --apply flag to actually perform the deletions.
```

## Requirements

- Python 3.8+
- aquasec library >= 0.7.0
