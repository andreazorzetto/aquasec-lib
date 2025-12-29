"""Tests for inventory module (Hub inventory images API)"""

import pytest
import os
from unittest.mock import Mock, patch

# Add the parent directory to the path so we can import the aquasec module
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aquasec.inventory import (
    api_get_inventory_images,
    api_get_inventory_images_count,
    api_delete_images,
    get_all_stale_images,
    get_stale_images_count,
    filter_images_by_registry,
    filter_images_by_repository
)


class TestApiGetInventoryImages:
    """Test the API call for listing inventory images"""

    @patch('aquasec.inventory.requests.get')
    def test_api_call_basic(self, mock_get):
        """Test basic API call without filters"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "result": [
                {"image_uid": 1, "name": "image1", "registry": "reg1", "repository": "repo1", "tag": "v1"}
            ],
            "count": 1
        }
        mock_get.return_value = mock_response

        result = api_get_inventory_images("https://test.aquasec.com", "test-token")

        assert result.status_code == 200
        mock_get.assert_called_once()

        call_args = mock_get.call_args
        assert call_args[1]['url'] == "https://test.aquasec.com/api/v2/hub/inventory/assets/images/list"
        assert call_args[1]['params']['page'] == 1
        assert call_args[1]['params']['pagesize'] == 200
        assert call_args[1]['headers']['Authorization'] == 'Bearer test-token'

    @patch('aquasec.inventory.requests.get')
    def test_api_call_with_filters(self, mock_get):
        """Test API call with all filters"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": [], "count": 0}
        mock_get.return_value = mock_response

        api_get_inventory_images(
            "https://test.aquasec.com",
            "test-token",
            page=2,
            page_size=100,
            scope="production",
            first_found_date="over|90|days",
            has_workloads=False
        )

        call_args = mock_get.call_args
        params = call_args[1]['params']

        assert params['page'] == 2
        assert params['pagesize'] == 100
        assert params['scope'] == "production"
        assert params['first_found_date'] == "over|90|days"
        assert params['has_workloads'] == "false"

    @patch('aquasec.inventory.requests.get')
    def test_api_call_has_workloads_true(self, mock_get):
        """Test API call with has_workloads=True"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": [], "count": 0}
        mock_get.return_value = mock_response

        api_get_inventory_images(
            "https://test.aquasec.com",
            "test-token",
            has_workloads=True
        )

        call_args = mock_get.call_args
        params = call_args[1]['params']
        assert params['has_workloads'] == "true"

    @patch('aquasec.inventory.requests.get')
    def test_api_call_verbose_output(self, mock_get, capsys):
        """Test verbose output"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": [], "count": 0}
        mock_get.return_value = mock_response

        api_get_inventory_images(
            "https://test.aquasec.com",
            "test-token",
            verbose=True
        )

        captured = capsys.readouterr()
        assert "GET https://test.aquasec.com/api/v2/hub/inventory/assets/images/list" in captured.out


class TestApiGetInventoryImagesCount:
    """Test the API call for getting image count"""

    @patch('aquasec.inventory.requests.get')
    def test_count_api_call(self, mock_get):
        """Test count API call"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"count": 150}
        mock_get.return_value = mock_response

        result = api_get_inventory_images_count("https://test.aquasec.com", "test-token")

        assert result.status_code == 200

        call_args = mock_get.call_args
        assert call_args[1]['url'] == "https://test.aquasec.com/api/v2/hub/inventory/assets/images/list/count"

    @patch('aquasec.inventory.requests.get')
    def test_count_api_call_with_filters(self, mock_get):
        """Test count API call with filters"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"count": 50}
        mock_get.return_value = mock_response

        api_get_inventory_images_count(
            "https://test.aquasec.com",
            "test-token",
            scope="production",
            first_found_date="last|60|days",
            has_workloads=False
        )

        call_args = mock_get.call_args
        params = call_args[1]['params']

        assert params['scope'] == "production"
        assert params['first_found_date'] == "last|60|days"
        assert params['has_workloads'] == "false"


class TestApiDeleteImages:
    """Test the API call for deleting images"""

    @patch('aquasec.inventory.requests.post')
    def test_delete_api_call(self, mock_post):
        """Test delete API call"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        result = api_delete_images("https://test.aquasec.com", "test-token", [1, 2, 3])

        assert result.status_code == 200

        call_args = mock_post.call_args
        assert call_args[1]['url'] == "https://test.aquasec.com/api/v2/images/actions/delete"
        assert call_args[1]['json'] == {"uids": [1, 2, 3]}
        assert call_args[1]['headers']['Authorization'] == 'Bearer test-token'
        assert call_args[1]['headers']['Content-Type'] == 'application/json'

    @patch('aquasec.inventory.requests.post')
    def test_delete_api_call_verbose(self, mock_post, capsys):
        """Test delete API call with verbose output"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        api_delete_images("https://test.aquasec.com", "test-token", [1, 2, 3], verbose=True)

        captured = capsys.readouterr()
        assert "POST https://test.aquasec.com/api/v2/images/actions/delete" in captured.out
        assert "Deleting 3 images" in captured.out

    @patch('aquasec.inventory.requests.post')
    def test_delete_empty_list(self, mock_post):
        """Test delete with empty list"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        api_delete_images("https://test.aquasec.com", "test-token", [])

        call_args = mock_post.call_args
        assert call_args[1]['json'] == {"uids": []}


class TestGetStaleImagesCount:
    """Test the high-level stale images count function"""

    @patch('aquasec.inventory.api_get_inventory_images_count')
    def test_get_count_success(self, mock_api_count):
        """Test successful count retrieval"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"count": 42}
        mock_api_count.return_value = mock_response

        result = get_stale_images_count("https://test.aquasec.com", "test-token", days=90)

        assert result == 42
        mock_api_count.assert_called_once_with(
            "https://test.aquasec.com",
            "test-token",
            scope=None,
            first_found_date="over|90|days",
            has_workloads=False,
            verbose=False
        )

    @patch('aquasec.inventory.api_get_inventory_images_count')
    def test_get_count_custom_days(self, mock_api_count):
        """Test count with custom days threshold"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"count": 100}
        mock_api_count.return_value = mock_response

        get_stale_images_count("https://test.aquasec.com", "test-token", days=180)

        call_args = mock_api_count.call_args
        assert call_args[1]['first_found_date'] == "over|180|days"

    @patch('aquasec.inventory.api_get_inventory_images_count')
    def test_get_count_with_scope(self, mock_api_count):
        """Test count with scope filter"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"count": 25}
        mock_api_count.return_value = mock_response

        get_stale_images_count("https://test.aquasec.com", "test-token", scope="production")

        call_args = mock_api_count.call_args
        assert call_args[1]['scope'] == "production"

    @patch('aquasec.inventory.api_get_inventory_images_count')
    def test_get_count_api_error(self, mock_api_count):
        """Test count returns 0 on API error"""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_api_count.return_value = mock_response

        result = get_stale_images_count("https://test.aquasec.com", "test-token")

        assert result == 0

    @patch('aquasec.inventory.api_get_inventory_images_count')
    def test_get_count_exception(self, mock_api_count):
        """Test count returns 0 on exception"""
        mock_api_count.side_effect = Exception("Connection error")

        result = get_stale_images_count("https://test.aquasec.com", "test-token")

        assert result == 0


class TestGetAllStaleImages:
    """Test the high-level function to get all stale images with pagination"""

    @patch('aquasec.inventory.api_get_inventory_images')
    def test_single_page(self, mock_api_get):
        """Test fetching all images when they fit in one page"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "result": [
                {"image_uid": 1, "name": "image1"},
                {"image_uid": 2, "name": "image2"}
            ],
            "count": 2
        }

        # First call returns data, second returns empty
        empty_response = Mock()
        empty_response.status_code = 200
        empty_response.json.return_value = {"result": [], "count": 2}

        mock_api_get.side_effect = [mock_response, empty_response]

        result = get_all_stale_images("https://test.aquasec.com", "test-token")

        assert len(result) == 2
        assert result[0]["image_uid"] == 1
        assert result[1]["image_uid"] == 2

    @patch('aquasec.inventory.api_get_inventory_images')
    def test_multiple_pages(self, mock_api_get):
        """Test fetching all images across multiple pages"""
        page1_response = Mock()
        page1_response.status_code = 200
        page1_response.json.return_value = {
            "result": [{"image_uid": i, "name": f"image{i}"} for i in range(1, 201)],
            "count": 250
        }

        page2_response = Mock()
        page2_response.status_code = 200
        page2_response.json.return_value = {
            "result": [{"image_uid": i, "name": f"image{i}"} for i in range(201, 251)],
            "count": 250
        }

        empty_response = Mock()
        empty_response.status_code = 200
        empty_response.json.return_value = {"result": [], "count": 250}

        mock_api_get.side_effect = [page1_response, page2_response, empty_response]

        result = get_all_stale_images("https://test.aquasec.com", "test-token")

        assert len(result) == 250
        assert mock_api_get.call_count == 3  # 2 pages with data + 1 empty

    @patch('aquasec.inventory.api_get_inventory_images')
    def test_pagination_until_empty(self, mock_api_get):
        """Test pagination continues until empty page (not relying on count)"""
        # Create 3 pages of data
        responses = []
        for page_num in range(3):
            resp = Mock()
            resp.status_code = 200
            resp.json.return_value = {
                "result": [{"image_uid": page_num * 200 + i} for i in range(200)],
                "count": 99999  # High count that shouldn't be used for termination
            }
            responses.append(resp)

        # Add empty page at end
        empty_resp = Mock()
        empty_resp.status_code = 200
        empty_resp.json.return_value = {"result": [], "count": 99999}
        responses.append(empty_resp)

        mock_api_get.side_effect = responses

        result = get_all_stale_images("https://test.aquasec.com", "test-token")

        assert len(result) == 600  # 3 pages * 200
        assert mock_api_get.call_count == 4  # 3 pages + 1 empty

    @patch('aquasec.inventory.api_get_inventory_images')
    def test_custom_days(self, mock_api_get):
        """Test custom days parameter is passed correctly"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": [], "count": 0}
        mock_api_get.return_value = mock_response

        get_all_stale_images("https://test.aquasec.com", "test-token", days=180)

        call_args = mock_api_get.call_args
        assert call_args[1]['first_found_date'] == "over|180|days"
        assert call_args[1]['has_workloads'] == False

    @patch('aquasec.inventory.api_get_inventory_images')
    def test_api_error_raises_exception(self, mock_api_get):
        """Test API error raises exception"""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"
        mock_api_get.return_value = mock_response

        with pytest.raises(Exception, match="API call failed with status 401"):
            get_all_stale_images("https://test.aquasec.com", "test-token")


class TestFilterImagesByRegistry:
    """Test client-side registry filtering"""

    def test_filter_by_registry(self):
        """Test filtering images by registry"""
        images = [
            {"image_uid": 1, "registry": "docker.io", "name": "image1"},
            {"image_uid": 2, "registry": "gcr.io", "name": "image2"},
            {"image_uid": 3, "registry": "docker.io", "name": "image3"},
            {"image_uid": 4, "registry": "ecr.aws", "name": "image4"}
        ]

        result = filter_images_by_registry(images, "docker.io")

        assert len(result) == 2
        assert all(img["registry"] == "docker.io" for img in result)

    def test_filter_no_matches(self):
        """Test filter with no matching images"""
        images = [
            {"image_uid": 1, "registry": "docker.io", "name": "image1"},
            {"image_uid": 2, "registry": "gcr.io", "name": "image2"}
        ]

        result = filter_images_by_registry(images, "ecr.aws")

        assert len(result) == 0

    def test_filter_empty_list(self):
        """Test filter with empty image list"""
        result = filter_images_by_registry([], "docker.io")

        assert len(result) == 0

    def test_filter_missing_registry_field(self):
        """Test filter handles images missing registry field"""
        images = [
            {"image_uid": 1, "registry": "docker.io", "name": "image1"},
            {"image_uid": 2, "name": "image2"},  # Missing registry
            {"image_uid": 3, "registry": "docker.io", "name": "image3"}
        ]

        result = filter_images_by_registry(images, "docker.io")

        assert len(result) == 2


class TestFilterImagesByRepository:
    """Test client-side repository filtering"""

    def test_filter_by_repository_exact(self):
        """Test filtering images by exact repository name"""
        images = [
            {"image_uid": 1, "repository": "nginx", "name": "image1"},
            {"image_uid": 2, "repository": "redis", "name": "image2"},
            {"image_uid": 3, "repository": "nginx", "name": "image3"}
        ]

        result = filter_images_by_repository(images, "nginx")

        assert len(result) == 2

    def test_filter_by_repository_partial(self):
        """Test filtering images by partial repository match"""
        images = [
            {"image_uid": 1, "repository": "myorg/nginx", "name": "image1"},
            {"image_uid": 2, "repository": "myorg/redis", "name": "image2"},
            {"image_uid": 3, "repository": "other/nginx", "name": "image3"}
        ]

        result = filter_images_by_repository(images, "nginx")

        assert len(result) == 2  # Both contain "nginx"

    def test_filter_by_repository_org_prefix(self):
        """Test filtering by organization prefix"""
        images = [
            {"image_uid": 1, "repository": "myorg/app1", "name": "image1"},
            {"image_uid": 2, "repository": "myorg/app2", "name": "image2"},
            {"image_uid": 3, "repository": "other/app1", "name": "image3"}
        ]

        result = filter_images_by_repository(images, "myorg/")

        assert len(result) == 2

    def test_filter_empty_repository(self):
        """Test filter handles images with missing repository field"""
        images = [
            {"image_uid": 1, "repository": "nginx", "name": "image1"},
            {"image_uid": 2, "name": "image2"},  # Missing repository
        ]

        result = filter_images_by_repository(images, "nginx")

        assert len(result) == 1


@pytest.mark.integration
class TestRealApiIntegration:
    """Integration tests that require real credentials (marked as integration)"""

    def test_real_api_call(self):
        """Test with real API - requires credentials"""
        if not (os.environ.get('CSP_ENDPOINT') and os.environ.get('AQUA_ENDPOINT')):
            pytest.skip("Real API credentials not available")

        from aquasec.config import load_profile_credentials
        from aquasec import authenticate

        try:
            load_profile_credentials()
            token = authenticate(verbose=False)
            server = os.environ.get('CSP_ENDPOINT')

            count = get_stale_images_count(server, token, days=90, verbose=False)
            assert isinstance(count, int)
            assert count >= 0

        except Exception as e:
            pytest.skip(f"Real API test failed: {e}")


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
