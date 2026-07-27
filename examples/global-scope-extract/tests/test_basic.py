"""Basic tests: syntax, version, and global-arg parsing."""
import os
import sys
import subprocess
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SCRIPT = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'aqua_global_scope_extract.py')


def test_syntax():
    import py_compile
    try:
        py_compile.compile(SCRIPT, doraise=True)
    except py_compile.PyCompileError:
        pytest.fail("Syntax error in aqua_global_scope_extract.py")


def test_version_defined():
    version_found = False
    with open(SCRIPT) as f:
        for line in f:
            if line.strip().startswith('__version__'):
                version_found = True
                version = line.split('=')[1].strip().strip('"').strip("'")
                assert version and '.' in version
                break
    assert version_found, "__version__ not found"


def test_version_flag_exits_zero():
    result = subprocess.run([sys.executable, SCRIPT, '--version'],
                            capture_output=True, text=True)
    assert result.returncode == 0
    assert 'aqua_global_scope_extract' in result.stdout


def test_parse_global_args():
    from aqua_global_scope_extract import parse_global_args
    cases = [
        (['-v', 'extract'], True, False, 'default', ['extract']),
        (['extract', '-v'], True, False, 'default', ['extract']),
        (['-p', 'prod', 'extract'], False, False, 'prod', ['extract']),
        (['extract', '--containers-only', '-d', '-p', 'x'], False, True, 'x', ['extract', '--containers-only']),
    ]
    for raw, exp_v, exp_d, exp_p, exp_filtered in cases:
        g, filtered = parse_global_args(raw)
        assert g['verbose'] == exp_v
        assert g['debug'] == exp_d
        assert g['profile'] == exp_p
        assert filtered == exp_filtered
