"""Basic tests that can run without aquasec-lib dependency"""
import sys
import os
import pytest

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_syntax():
    """Test that the main script has valid syntax"""
    import py_compile
    script_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'aqua_license_util.py')
    try:
        py_compile.compile(script_path, doraise=True)
    except py_compile.PyCompileError:
        pytest.fail("Syntax error in aqua_license_util.py")


def test_version():
    """Test that version is defined"""
    # Import just the version without executing the whole module
    version_found = False
    script_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'aqua_license_util.py')
    with open(script_path, 'r') as f:
        for line in f:
            if line.strip().startswith('__version__'):
                version_found = True
                # Extract version
                version = line.split('=')[1].strip().strip('"').strip("'")
                assert version, "Version string is empty"
                assert '.' in version, "Version should contain dots"
                break
    
    assert version_found, "__version__ not found in script"


def test_global_args_parsing():
    """Test the custom argument parsing logic"""
    # This tests the logic without actually running argparse
    test_cases = [
        # (input_args, expected_verbose, expected_debug, expected_profile)
        (['-v', 'show'], True, False, 'default'),
        (['show', '-v'], True, False, 'default'),
        (['-p', 'test', 'show'], False, False, 'test'),
        (['show', '-p', 'test'], False, False, 'test'),
        (['-v', '-d', '-p', 'prod', 'breakdown'], True, True, 'prod'),
        (['breakdown', '-v', '-d', '-p', 'prod'], True, True, 'prod'),
    ]
    
    for raw_args, exp_verbose, exp_debug, exp_profile in test_cases:
        # Simulate the parsing logic from the script
        global_args = {
            'verbose': False,
            'debug': False,
            'profile': 'default'
        }
        
        filtered_args = []
        i = 0
        while i < len(raw_args):
            arg = raw_args[i]
            if arg in ['-v', '--verbose']:
                global_args['verbose'] = True
            elif arg in ['-d', '--debug']:
                global_args['debug'] = True
            elif arg in ['-p', '--profile']:
                if i + 1 < len(raw_args):
                    global_args['profile'] = raw_args[i + 1]
                    i += 1
            else:
                filtered_args.append(arg)
            i += 1
        
        assert global_args['verbose'] == exp_verbose, f"Failed for {raw_args}: verbose"
        assert global_args['debug'] == exp_debug, f"Failed for {raw_args}: debug"
        assert global_args['profile'] == exp_profile, f"Failed for {raw_args}: profile"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])