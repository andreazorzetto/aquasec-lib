# CI/CD Pipeline Documentation

This repository uses GitHub Actions with intelligent path-based conditional execution to optimize build times and resource usage.

## Workflow Overview

### 🧪 [test.yml](.github/workflows/test.yml) - Testing Pipeline

**Triggers:**
- Push to `main` or `develop` branches
- Pull requests to `main` branch  
- Scheduled runs (Mondays at 2 AM UTC)
- Manual workflow dispatch

**Conditional Execution Logic:**
- **Library tests** run when: `aquasec/**`, `setup.py`, `requirements.txt`, or workflow files change
- **License utility tests** run when: `examples/license-utility/**` files change
- **Repository breakdown tests** run when: `examples/repo-breakdown/**` files change  
- **VM extract tests** run when: `examples/vm-extract/**` files change
- **All tests** run on: scheduled runs or manual triggers

**Test Matrix:**
- Python versions: 3.8, 3.9, 3.10, 3.11
- Each component tested independently
- Examples use development library installation (`pip install -e .`)

### 🔒 [security.yml](.github/workflows/security.yml) - Security Analysis

**Triggers:**
- Push to `main` or `develop` branches
- Pull requests to `main` branch
- Scheduled runs (Mondays at 3 AM UTC)  
- Manual workflow dispatch

**Security Scans:**
- **Library security scan**: Uses Trivy to scan `aquasec/` directory
- **Example-specific scans**: Separate Trivy scans for each example
- **Dependency vulnerability check**: Uses Safety to check all requirements.txt files
- **SARIF upload**: Results uploaded to GitHub Security tab with categorization

**Conditional Execution:**
- Only scans components that have changed files
- Scheduled runs scan everything for comprehensive coverage

### 📦 [publish-library.yml](.github/workflows/publish-library.yml) - PyPI Publishing

**Triggers:**
- GitHub releases (automatic)
- Manual workflow dispatch (with Test PyPI option)

**Publishing Process:**
- Builds Python package
- Runs basic validation
- Publishes to PyPI or Test PyPI based on trigger

## Path-based Change Detection

The pipelines use [`dorny/paths-filter`](https://github.com/dorny/paths-filter) action to detect changes:

```yaml
filters: |
  library:
    - 'aquasec/**'
    - 'setup.py'  
    - 'requirements.txt'
    - 'MANIFEST.in'
    - '.github/workflows/**'
  license-utility:
    - 'examples/license-utility/**'
  repo-breakdown:
    - 'examples/repo-breakdown/**'
  vm-extract:
    - 'examples/vm-extract/**'
  dependencies:
    - '**/requirements*.txt'
    - 'setup.py'
```

## Example Scenarios

### Scenario 1: Library Change
**Files changed:** `aquasec/vms.py`
**Jobs executed:**
- ✅ `test-library` (all Python versions)
- ✅ `security-scan-library`
- ❌ Example tests (skipped)

### Scenario 2: License Utility Change  
**Files changed:** `examples/license-utility/aqua_license_util.py`
**Jobs executed:**
- ❌ Library tests (skipped)
- ✅ `test-license-utility` (all Python versions)
- ✅ `security-scan-license-utility`
- ❌ Other example tests (skipped)

### Scenario 3: Multiple Changes
**Files changed:** `aquasec/auth.py`, `examples/vm-extract/tests/test_basic.py`
**Jobs executed:**
- ✅ `test-library` (all Python versions)
- ✅ `security-scan-library`
- ✅ `test-vm-extract` (all Python versions)
- ✅ `security-scan-vm-extract`
- ❌ Other example tests (skipped)

### Scenario 4: Scheduled Run
**Trigger:** Monday 2 AM UTC
**Jobs executed:**
- ✅ All test jobs (comprehensive testing)
- ✅ All security scans (comprehensive security audit)

## Benefits

- **⚡ Faster CI**: Only relevant components tested
- **💰 Cost Effective**: Reduced GitHub Actions minutes usage
- **🎯 Targeted**: Clear failure attribution to specific components
- **🔄 Parallel**: Multiple components tested simultaneously
- **📊 Comprehensive**: Scheduled runs ensure nothing is missed

## Manual Triggers

Both workflows support manual triggering via GitHub UI:

1. Go to **Actions** tab
2. Select **Run Tests** or **Security Analysis**
3. Click **Run workflow**
4. Choose branch and click **Run workflow**

This is useful for:
- Testing specific branches
- Running comprehensive tests outside scheduled times
- Debugging pipeline issues
- Release preparation

## Workflow Status Badges

Add these badges to your README to show pipeline status:

```markdown
[![Tests](https://github.com/andreazorzetto/aquasec-lib/workflows/Run%20Tests/badge.svg)](https://github.com/andreazorzetto/aquasec-lib/actions/workflows/test.yml)
[![Security](https://github.com/andreazorzetto/aquasec-lib/workflows/Security%20Analysis/badge.svg)](https://github.com/andreazorzetto/aquasec-lib/actions/workflows/security.yml)
```

## Troubleshooting

### Common Issues

**Issue**: All jobs running even for small changes
**Solution**: Check if `.github/workflows/**` files were modified (triggers all jobs)

**Issue**: Example tests failing with import errors
**Solution**: Ensure library is installed in development mode (`pip install -e .`)

**Issue**: Security scans timing out
**Solution**: Check for large files or network issues, consider excluding test data

### Debugging Tips

1. **Check the change detection job** output to see which paths were detected
2. **Review job conditions** in workflow files for conditional logic
3. **Test locally** using the same commands as the CI pipeline
4. **Use manual triggers** to test specific scenarios

## Maintenance

### Adding New Examples

When adding a new example to `examples/new-tool/`:

1. **Add path filter** to both workflow files:
   ```yaml
   new-tool:
     - 'examples/new-tool/**'
   ```

2. **Add conditional job** to `test.yml`:
   ```yaml
   test-new-tool:
     needs: detect-changes
     if: needs.detect-changes.outputs.new-tool-changed == 'true' || github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'
     # ... rest of job definition
   ```

3. **Add security scan** to `security.yml` following the same pattern

4. **Test the pipeline** with a commit that only touches the new example

### Updating Dependencies

When updating dependencies:
- Library: Update `requirements.txt` 
- Examples: Update `examples/*/requirements*.txt`
- The dependency check job will automatically scan updated files

Remember to test changes locally before committing to ensure pipeline efficiency!