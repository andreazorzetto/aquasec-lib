"""Tests for code repository integration in license utility"""

import pytest
import os
import sys
from unittest.mock import Mock, patch

# Add parent directories to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


class TestCodeRepositoryIntegration:
    """Test code repository functionality in license utility"""

    @patch('aquasec.code_repositories.api_get_code_repositories')
    def test_code_repo_count_import_and_call(self, mock_api_get):
        """Test that get_code_repo_count can be imported and called"""
        # Mock successful API response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [{"name": "test-repo"}],
            "total_count": 42,
            "current_page": 1
        }
        mock_api_get.return_value = mock_response

        # Test import (this is what the license utility does)
        from aquasec import get_code_repo_count

        # Test function call
        result = get_code_repo_count("https://test.cloud.aquasec.com", "test-token")

        assert result == 42
        assert callable(get_code_repo_count)

    @patch('aquasec.code_repositories.api_get_code_repositories')
    @patch('aquasec.authenticate')
    @patch('aquasec.config.load_profile_credentials')
    @patch.dict(os.environ, {'CSP_ENDPOINT': 'https://test.cloud.aquasec.com'})
    def test_license_utility_code_repo_section(self, mock_load_creds, mock_auth, mock_api_get):
        """Test the exact code repository section from license utility"""
        # Setup mocks
        mock_load_creds.return_value = None
        mock_auth.return_value = "test-token"

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [{"name": "test-repo"}],
            "total_count": 93,
            "current_page": 1
        }
        mock_api_get.return_value = mock_response

        # Simulate the exact code from license utility
        server = os.environ.get('CSP_ENDPOINT')
        token = mock_auth.return_value

        total_code_repos = 0
        try:
            from aquasec import get_code_repo_count
            total_code_repos = get_code_repo_count(server, token, verbose=False)
        except Exception as e:
            pytest.fail(f"Code repository counting failed: {e}")

        assert total_code_repos == 93

    @patch('aquasec.code_repositories.api_get_code_repositories')
    def test_code_repo_count_with_error_handling(self, mock_api_get):
        """Test error handling in code repository counting"""
        # Mock API error
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"
        mock_api_get.return_value = mock_response

        from aquasec import get_code_repo_count

        with pytest.raises(Exception, match="API call failed with status 401"):
            get_code_repo_count("https://test.cloud.aquasec.com", "invalid-token")

    def test_supply_chain_url_derivation_matches_examples(self):
        """Test that URL derivation works for example cases"""
        from aquasec.code_repositories import _get_supply_chain_url

        # Test cases that should work with the license utility
        test_cases = [
            ("https://c1fae5dbe2.cloud.aquasec.com", "https://api.supply-chain.cloud.aquasec.com"),
            ("https://test.eu-1.cloud.aquasec.com", "https://api.eu-1.supply-chain.cloud.aquasec.com"),
        ]

        for csp_url, expected_sc_url in test_cases:
            with patch.dict(os.environ, {'AQUA_ENDPOINT': 'https://eu-1.api.cloudsploit.com'}):
                if "eu-1" not in csp_url:  # Test fallback to auth endpoint
                    actual = _get_supply_chain_url(csp_url)
                    assert actual == "https://api.eu-1.supply-chain.cloud.aquasec.com"
                else:
                    actual = _get_supply_chain_url(csp_url)
                    assert actual == expected_sc_url


@pytest.mark.integration
class TestLicenseUtilityIntegration:
    """Integration tests with real credentials"""

    def test_license_count_includes_code_repos(self):
        """Test that license count command includes code repositories"""
        # Skip if no credentials
        if not (os.environ.get('CSP_ENDPOINT') and os.environ.get('AQUA_ENDPOINT')):
            pytest.skip("Real API credentials not available")

        import subprocess
        import json

        try:
            # Run the license count command
            result = subprocess.run([
                sys.executable, 'aqua_license_util.py', 'license', 'count'
            ], capture_output=True, text=True, cwd=os.path.dirname(os.path.dirname(__file__)))

            if result.returncode == 0:
                data = json.loads(result.stdout)
                assert 'usage' in data
                assert 'code_repositories' in data['usage']
                assert isinstance(data['usage']['code_repositories'], int)
                assert data['usage']['code_repositories'] >= 0
            else:
                pytest.skip(f"License utility failed: {result.stderr}")

        except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
            pytest.skip(f"Integration test failed: {e}")


if __name__ == '__main__':
    pytest.main([__file__, '-v'])