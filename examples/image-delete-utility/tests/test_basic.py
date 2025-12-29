"""Basic tests for image-delete-utility"""
import sys
import os
import subprocess

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestCLI:
    """Test CLI interface"""

    def test_help_command(self):
        """Test that --help works"""
        script_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'aqua_image_delete.py'
        )

        result = subprocess.run(
            [sys.executable, script_path, '--help'],
            capture_output=True,
            text=True
        )

        assert result.returncode == 0
        assert 'Aqua Image Delete Utility' in result.stdout
        assert 'images' in result.stdout
        assert 'setup' in result.stdout
        assert 'profile' in result.stdout

    def test_version_command(self):
        """Test that --version works"""
        script_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'aqua_image_delete.py'
        )

        result = subprocess.run(
            [sys.executable, script_path, '--version'],
            capture_output=True,
            text=True
        )

        assert result.returncode == 0
        assert '0.1.0' in result.stdout

    def test_images_delete_help(self):
        """Test that images delete --help works"""
        script_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'aqua_image_delete.py'
        )

        result = subprocess.run(
            [sys.executable, script_path, 'images', 'delete', '--help'],
            capture_output=True,
            text=True
        )

        assert result.returncode == 0
        assert '--apply' in result.stdout
        assert '--days' in result.stdout
        assert '--registry' in result.stdout
        assert '--scope' in result.stdout


if __name__ == '__main__':
    import pytest
    pytest.main([__file__, '-v'])
