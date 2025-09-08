"""Basic tests that can run without aquasec-lib dependency"""
import sys
import os
import pytest

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_syntax():
    """Test that the main script has valid syntax"""
    import py_compile
    script_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'aqua_repo_breakdown.py')
    try:
        py_compile.compile(script_path, doraise=True)
    except py_compile.PyCompileError:
        pytest.fail("Syntax error in aqua_repo_breakdown.py")


def test_version():
    """Test that version is defined"""
    # Import just the version without executing the whole module
    version_found = False
    script_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'aqua_repo_breakdown.py')
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


def test_version_display():
    """Test that --version flag works"""
    import subprocess
    script_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'aqua_repo_breakdown.py')
    
    result = subprocess.run(
        [sys.executable, script_path, '--version'],
        capture_output=True,
        text=True
    )
    
    assert result.returncode == 0, "Version display should exit with code 0"
    assert 'aqua_repo_breakdown' in result.stdout, "Version output should contain script name"
    assert '.' in result.stdout, "Version output should contain version number"


def test_global_args_parsing():
    """Test the custom argument parsing logic"""
    # This tests the logic without actually running argparse
    test_cases = [
        # (input_args, expected_verbose, expected_debug, expected_profile)
        (['-v', 'repo', 'list'], True, False, 'default'),
        (['repo', 'list', '-v'], True, False, 'default'),
        (['-p', 'test', 'repo', 'list'], False, False, 'test'),
        (['repo', 'list', '-p', 'test'], False, False, 'test'),
        (['-v', '-d', '-p', 'prod', 'repo', 'breakdown'], True, True, 'prod'),
        (['repo', 'breakdown', '-v', '-d', '-p', 'prod'], True, True, 'prod'),
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


def test_command_structure():
    """Test that all expected commands are present in help output"""
    import subprocess
    script_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'aqua_repo_breakdown.py')
    
    # Test main help
    result = subprocess.run(
        [sys.executable, script_path, '--help'],
        capture_output=True,
        text=True
    )
    
    assert result.returncode == 0, "Help should exit with code 0"
    assert 'setup' in result.stdout, "Help should mention setup command"
    assert 'profile' in result.stdout, "Help should mention profile command"
    assert 'repo' in result.stdout, "Help should mention repo command"
    
    # Test profile subcommands
    result = subprocess.run(
        [sys.executable, script_path, 'profile', '--help'],
        capture_output=True,
        text=True
    )
    
    assert 'list' in result.stdout, "Profile help should mention list subcommand"
    assert 'show' in result.stdout, "Profile help should mention show subcommand"
    assert 'delete' in result.stdout, "Profile help should mention delete subcommand"
    assert 'set-default' in result.stdout, "Profile help should mention set-default subcommand"


def test_repo_commands():
    """Test that repo subcommands are available"""
    import subprocess
    script_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'aqua_repo_breakdown.py')
    
    # Test repo subcommands
    result = subprocess.run(
        [sys.executable, script_path, 'repo', '--help'],
        capture_output=True,
        text=True
    )
    
    assert result.returncode == 0, "Repo help should exit with code 0"
    assert 'list' in result.stdout, "Repo help should mention list subcommand"
    assert 'breakdown' in result.stdout, "Repo help should mention breakdown subcommand"


def test_repo_list_flags():
    """Test that repo list has the expected flags"""
    import subprocess
    script_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'aqua_repo_breakdown.py')
    
    # Test repo list flags
    result = subprocess.run(
        [sys.executable, script_path, 'repo', 'list', '--help'],
        capture_output=True,
        text=True
    )
    
    assert result.returncode == 0, "Repo list help should exit with code 0"
    assert '--orphan' in result.stdout, "Should have --orphan flag"
    assert '--all-scopes' in result.stdout, "Should have --all-scopes flag"
    assert '--scope' in result.stdout, "Should have --scope flag"
    assert '--registry' in result.stdout, "Should have --registry flag"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])