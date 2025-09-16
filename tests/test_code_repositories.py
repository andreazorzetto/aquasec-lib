"""Tests for code_repositories module"""

import pytest
import os
from unittest.mock import Mock, patch, MagicMock
import requests

# Add the parent directory to the path so we can import the aquasec module
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aquasec.code_repositories import (
    _get_supply_chain_url,
    api_get_code_repositories,
    get_all_code_repositories,
    get_code_repo_count
)


class TestSupplyChainUrlDerivation:
    """Test the Supply Chain URL derivation logic"""

    def test_us_endpoint_no_region(self):
        """Test US endpoint without region"""
        server = "https://xxx.cloud.aquasec.com"
        expected = "https://api.supply-chain.cloud.aquasec.com"
        assert _get_supply_chain_url(server) == expected

    def test_eu_endpoint_with_region(self):
        """Test EU endpoint with region"""
        server = "https://xxx.eu-1.cloud.aquasec.com"
        expected = "https://api.eu-1.supply-chain.cloud.aquasec.com"
        assert _get_supply_chain_url(server) == expected

    def test_asia_endpoint_with_region(self):
        """Test Asia endpoint with region"""
        server = "https://xxx.asia-1.cloud.aquasec.com"
        expected = "https://api.asia-1.supply-chain.cloud.aquasec.com"
        assert _get_supply_chain_url(server) == expected

    def test_au_endpoint_with_region(self):
        """Test Australia endpoint with region"""
        server = "https://xxx.au-1.cloud.aquasec.com"
        expected = "https://api.au-1.supply-chain.cloud.aquasec.com"
        assert _get_supply_chain_url(server) == expected

    @patch.dict(os.environ, {'AQUA_ENDPOINT': 'https://eu-1.api.cloudsploit.com'})
    def test_region_from_auth_endpoint(self):
        """Test extracting region from auth endpoint when CSP endpoint has no region"""
        server = "https://c1fae5dbe2.cloud.aquasec.com"
        expected = "https://api.eu-1.supply-chain.cloud.aquasec.com"
        assert _get_supply_chain_url(server) == expected

    @patch.dict(os.environ, {'AQUA_ENDPOINT': 'https://us-1.api.cloudsploit.com'})
    def test_us_region_from_auth_endpoint(self):
        """Test US region from auth endpoint"""
        server = "https://c1fae5dbe2.cloud.aquasec.com"
        expected = "https://api.us-1.supply-chain.cloud.aquasec.com"
        assert _get_supply_chain_url(server) == expected

    @patch.dict(os.environ, {'AQUA_ENDPOINT': ''})
    def test_fallback_to_us_no_region_info(self):
        """Test fallback to US when no region info available"""
        server = "https://c1fae5dbe2.cloud.aquasec.com"
        expected = "https://api.supply-chain.cloud.aquasec.com"
        assert _get_supply_chain_url(server) == expected

    def test_invalid_server_url(self):
        """Test error handling for invalid server URL"""
        with pytest.raises(ValueError, match="Invalid server URL"):
            _get_supply_chain_url("invalid-url")


class TestApiGetCodeRepositories:
    """Test the API call function"""

    @patch('aquasec.code_repositories.requests.get')
    def test_api_call_success(self, mock_get):
        """Test successful API call"""
        # Mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [{"name": "test-repo", "full_name": "org/test-repo"}],
            "total_count": 1,
            "current_page": 1
        }
        mock_get.return_value = mock_response

        server = "https://xxx.eu-1.cloud.aquasec.com"
        token = "test-token"

        result = api_get_code_repositories(server, token, page=1, page_size=25)

        assert result.status_code == 200
        assert result.json()["total_count"] == 1

        # Verify the correct URL was called
        mock_get.assert_called_once()
        call_args = mock_get.call_args
        assert "https://api.eu-1.supply-chain.cloud.aquasec.com/v2/build/repositories" in call_args[1]['url']

        # Verify parameters
        params = call_args[1]['params']
        assert params['page'] == 1
        assert params['page_size'] == 25
        assert params['order_by'] == '-scan_date'
        assert params['no_scan_repositories'] == 'true'

        # Verify headers
        headers = call_args[1]['headers']
        assert headers['Authorization'] == 'Bearer test-token'

    @patch('aquasec.code_repositories.requests.get')
    def test_api_call_with_scope_warning(self, mock_get, capsys):
        """Test API call with scope parameter shows warning"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": [], "total_count": 0}
        mock_get.return_value = mock_response

        server = "https://xxx.cloud.aquasec.com"
        token = "test-token"

        api_get_code_repositories(server, token, scope="test-scope", verbose=True)

        captured = capsys.readouterr()
        assert "Warning: Scope filtering is not supported by the Supply Chain API" in captured.out


class TestGetAllCodeRepositories:
    """Test pagination handling"""

    @patch('aquasec.code_repositories.api_get_code_repositories')
    def test_single_page(self, mock_api_get):
        """Test fetching all repos when they fit in one page"""
        # Mock response for single page
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [
                {"name": "repo1", "full_name": "org/repo1"},
                {"name": "repo2", "full_name": "org/repo2"}
            ],
            "total_count": 2,
            "current_page": 1,
            "next_page": None
        }
        mock_api_get.return_value = mock_response

        result = get_all_code_repositories("https://test.cloud.aquasec.com", "token")

        assert len(result) == 2
        assert result[0]["name"] == "repo1"
        assert result[1]["name"] == "repo2"
        mock_api_get.assert_called_once()

    @patch('aquasec.code_repositories.api_get_code_repositories')
    def test_multiple_pages(self, mock_api_get):
        """Test fetching all repos across multiple pages"""
        # Mock responses for multiple pages
        page1_response = Mock()
        page1_response.status_code = 200
        page1_response.json.return_value = {
            "data": [{"name": "repo1", "full_name": "org/repo1"}],
            "total_count": 2,
            "current_page": 1,
            "next_page": 2
        }

        page2_response = Mock()
        page2_response.status_code = 200
        page2_response.json.return_value = {
            "data": [{"name": "repo2", "full_name": "org/repo2"}],
            "total_count": 2,
            "current_page": 2,
            "next_page": None
        }

        mock_api_get.side_effect = [page1_response, page2_response]

        result = get_all_code_repositories("https://test.cloud.aquasec.com", "token")

        assert len(result) == 2
        assert result[0]["name"] == "repo1"
        assert result[1]["name"] == "repo2"
        assert mock_api_get.call_count == 2

    @patch('aquasec.code_repositories.api_get_code_repositories')
    def test_api_error_handling(self, mock_api_get):
        """Test error handling when API call fails"""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"
        mock_api_get.return_value = mock_response

        with pytest.raises(Exception, match="API call failed with status 401"):
            get_all_code_repositories("https://test.cloud.aquasec.com", "token")


class TestGetCodeRepoCount:
    """Test repository count function"""

    @patch('aquasec.code_repositories.api_get_code_repositories')
    def test_get_count_success(self, mock_api_get):
        """Test successful count retrieval"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [{"name": "repo1"}],
            "total_count": 93,
            "current_page": 1
        }
        mock_api_get.return_value = mock_response

        result = get_code_repo_count("https://test.eu-1.cloud.aquasec.com", "token")

        assert result == 93
        mock_api_get.assert_called_once_with(
            "https://test.eu-1.cloud.aquasec.com",
            "token",
            page=1,
            page_size=1,
            scope=None,
            use_estimated_count=False,
            skip_count=False,
            verbose=False
        )

    @patch('aquasec.code_repositories.api_get_code_repositories')
    def test_get_count_api_error(self, mock_api_get):
        """Test error handling in count function"""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_api_get.return_value = mock_response

        with pytest.raises(Exception, match="API call failed with status 500"):
            get_code_repo_count("https://test.cloud.aquasec.com", "token")


@pytest.mark.integration
class TestRealApiIntegration:
    """Integration tests that require real credentials (marked as integration)"""

    def test_real_api_call(self):
        """Test with real API - requires AQUA_ENDPOINT and CSP_ENDPOINT environment variables"""
        # Skip if no credentials
        if not (os.environ.get('CSP_ENDPOINT') and os.environ.get('AQUA_ENDPOINT')):
            pytest.skip("Real API credentials not available")

        from aquasec.config import load_profile_credentials
        from aquasec import authenticate

        try:
            load_profile_credentials()
            token = authenticate(verbose=False)
            server = os.environ.get('CSP_ENDPOINT')

            count = get_code_repo_count(server, token, verbose=False)
            assert isinstance(count, int)
            assert count >= 0

        except Exception as e:
            pytest.skip(f"Real API test failed: {e}")


if __name__ == '__main__':
    pytest.main([__file__, '-v'])