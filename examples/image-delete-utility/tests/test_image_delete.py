"""Integration tests for image delete functionality"""
import sys
import os
import pytest
from unittest.mock import Mock, patch

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the main script
import aqua_image_delete


class TestImagesDelete:
    """Test image delete functionality"""

    def test_images_delete_dry_run_mode(self):
        """Test dry run mode (default behavior)"""
        # Mock API responses
        mock_get_response = Mock()
        mock_get_response.status_code = 200
        mock_get_response.json.return_value = {
            "result": [
                {"image_uid": 1, "name": "reg/repo:v1", "registry": "reg", "repository": "repo", "tag": "v1"},
                {"image_uid": 2, "name": "reg/repo:v2", "registry": "reg", "repository": "repo", "tag": "v2"},
                {"image_uid": 3, "name": "reg/other:latest", "registry": "reg", "repository": "other", "tag": "latest"}
            ],
            "count": 3
        }

        # Second call returns empty to stop pagination
        mock_empty_response = Mock()
        mock_empty_response.status_code = 200
        mock_empty_response.json.return_value = {"result": [], "count": 3}

        with patch('aqua_image_delete.api_get_inventory_images', side_effect=[mock_get_response, mock_empty_response]):
            with patch('builtins.print') as mock_print:
                aqua_image_delete.images_delete(
                    server="https://test.aquasec.com",
                    token="test-token",
                    days=90,
                    registry=None,
                    scope=None,
                    apply=False,
                    verbose=False,
                    debug=False
                )

                mock_print.assert_called_once()
                args = mock_print.call_args[0][0]

                import json
                result = json.loads(args)

                assert result["mode"] == "dry_run"
                assert result["summary"]["images_scanned"] == 3
                assert result["summary"]["images_would_delete"] == 3
                assert result["summary"]["images_failed"] == 0
                assert len(result["deletions"]) == 3

    def test_images_delete_with_registry_filter(self):
        """Test registry filter is passed to API (server-side filtering)"""
        # Mock response simulates server-side filtering - only docker.io images returned
        mock_get_response = Mock()
        mock_get_response.status_code = 200
        mock_get_response.json.return_value = {
            "result": [
                {"image_uid": 1, "name": "docker.io/nginx:v1", "registry": "docker.io", "repository": "nginx", "tag": "v1"},
                {"image_uid": 3, "name": "docker.io/redis:latest", "registry": "docker.io", "repository": "redis", "tag": "latest"}
            ],
            "count": 2
        }

        mock_empty_response = Mock()
        mock_empty_response.status_code = 200
        mock_empty_response.json.return_value = {"result": [], "count": 2}

        with patch('aqua_image_delete.api_get_inventory_images', side_effect=[mock_get_response, mock_empty_response]) as mock_get:
            with patch('builtins.print') as mock_print:
                aqua_image_delete.images_delete(
                    server="https://test.aquasec.com",
                    token="test-token",
                    days=90,
                    registry="docker.io",
                    scope=None,
                    apply=False,
                    verbose=False,
                    debug=False
                )

                # Verify registry_name was passed to API for server-side filtering
                call_args = mock_get.call_args_list[0]
                assert call_args[1]['registry_name'] == "docker.io"

                mock_print.assert_called_once()
                args = mock_print.call_args[0][0]

                import json
                result = json.loads(args)

                assert result["summary"]["images_scanned"] == 2
                assert result["summary"]["images_would_delete"] == 2
                # Verify only docker.io images are in deletions
                for deletion in result["deletions"]:
                    assert deletion["registry"] == "docker.io"

    def test_images_delete_apply_mode(self):
        """Test apply mode (actual deletions)"""
        mock_get_response = Mock()
        mock_get_response.status_code = 200
        mock_get_response.json.return_value = {
            "result": [
                {"image_uid": 1, "name": "reg/repo:v1", "registry": "reg", "repository": "repo", "tag": "v1"},
                {"image_uid": 2, "name": "reg/repo:v2", "registry": "reg", "repository": "repo", "tag": "v2"}
            ],
            "count": 2
        }

        mock_empty_response = Mock()
        mock_empty_response.status_code = 200
        mock_empty_response.json.return_value = {"result": [], "count": 2}

        mock_delete_response = Mock()
        mock_delete_response.status_code = 200

        with patch('aqua_image_delete.api_get_inventory_images', side_effect=[mock_get_response, mock_empty_response]):
            with patch('aqua_image_delete.api_delete_images', return_value=mock_delete_response) as mock_delete:
                with patch('builtins.print') as mock_print:
                    aqua_image_delete.images_delete(
                        server="https://test.aquasec.com",
                        token="test-token",
                        days=90,
                        registry=None,
                        scope=None,
                        apply=True,
                        verbose=False,
                        debug=False
                    )

                    # Verify delete API was called with batch of UIDs
                    mock_delete.assert_called_once()
                    call_args = mock_delete.call_args
                    assert call_args[0][0] == "https://test.aquasec.com"
                    assert call_args[0][1] == "test-token"
                    assert set(call_args[0][2]) == {1, 2}  # UIDs

                    # Verify JSON output
                    mock_print.assert_called_once()
                    args = mock_print.call_args[0][0]

                    import json
                    result = json.loads(args)

                    assert result["mode"] == "apply"
                    assert result["summary"]["images_deleted"] == 2
                    assert result["summary"]["images_failed"] == 0

    def test_images_delete_with_failures(self):
        """Test handling of deletion failures"""
        mock_get_response = Mock()
        mock_get_response.status_code = 200
        mock_get_response.json.return_value = {
            "result": [
                {"image_uid": 1, "name": "reg/repo:v1", "registry": "reg", "repository": "repo", "tag": "v1"},
                {"image_uid": 2, "name": "reg/repo:v2", "registry": "reg", "repository": "repo", "tag": "v2"}
            ],
            "count": 2
        }

        mock_empty_response = Mock()
        mock_empty_response.status_code = 200
        mock_empty_response.json.return_value = {"result": [], "count": 2}

        # Mock failed deletion
        mock_delete_response = Mock()
        mock_delete_response.status_code = 403
        mock_delete_response.text = "Forbidden"

        with patch('aqua_image_delete.api_get_inventory_images', side_effect=[mock_get_response, mock_empty_response]):
            with patch('aqua_image_delete.api_delete_images', return_value=mock_delete_response):
                with patch('builtins.print') as mock_print:
                    aqua_image_delete.images_delete(
                        server="https://test.aquasec.com",
                        token="test-token",
                        days=90,
                        registry=None,
                        scope=None,
                        apply=True,
                        verbose=False,
                        debug=False
                    )

                    mock_print.assert_called_once()
                    args = mock_print.call_args[0][0]

                    import json
                    result = json.loads(args)

                    assert result["mode"] == "apply"
                    assert result["summary"]["images_deleted"] == 0
                    assert result["summary"]["images_failed"] == 2
                    assert "failures" in result
                    assert len(result["failures"]) == 2

    def test_images_delete_pagination(self):
        """Test pagination handling with per-page batching"""
        # Page 1: 200 images
        page1_response = Mock()
        page1_response.status_code = 200
        page1_response.json.return_value = {
            "result": [
                {"image_uid": i, "name": f"reg/repo:v{i}", "registry": "reg", "repository": "repo", "tag": f"v{i}"}
                for i in range(1, 201)
            ],
            "count": 250
        }

        # Page 2: 50 images
        page2_response = Mock()
        page2_response.status_code = 200
        page2_response.json.return_value = {
            "result": [
                {"image_uid": i, "name": f"reg/repo:v{i}", "registry": "reg", "repository": "repo", "tag": f"v{i}"}
                for i in range(201, 251)
            ],
            "count": 250
        }

        # Page 3: empty
        empty_response = Mock()
        empty_response.status_code = 200
        empty_response.json.return_value = {"result": [], "count": 250}

        mock_delete_response = Mock()
        mock_delete_response.status_code = 200

        with patch('aqua_image_delete.api_get_inventory_images', side_effect=[page1_response, page2_response, empty_response]):
            with patch('aqua_image_delete.api_delete_images', return_value=mock_delete_response) as mock_delete:
                with patch('builtins.print') as mock_print:
                    aqua_image_delete.images_delete(
                        server="https://test.aquasec.com",
                        token="test-token",
                        days=90,
                        registry=None,
                        scope=None,
                        apply=True,
                        verbose=False,
                        debug=False
                    )

                    # Verify delete was called twice (once per page with data)
                    assert mock_delete.call_count == 2

                    # First batch: 200 UIDs
                    first_call_uids = mock_delete.call_args_list[0][0][2]
                    assert len(first_call_uids) == 200

                    # Second batch: 50 UIDs
                    second_call_uids = mock_delete.call_args_list[1][0][2]
                    assert len(second_call_uids) == 50

                    # Verify total in output
                    mock_print.assert_called_once()
                    args = mock_print.call_args[0][0]

                    import json
                    result = json.loads(args)

                    assert result["summary"]["images_scanned"] == 250
                    assert result["summary"]["images_deleted"] == 250

    def test_images_delete_custom_days(self):
        """Test custom days threshold"""
        mock_get_response = Mock()
        mock_get_response.status_code = 200
        mock_get_response.json.return_value = {"result": [], "count": 0}

        with patch('aqua_image_delete.api_get_inventory_images', return_value=mock_get_response) as mock_get:
            with patch('builtins.print'):
                aqua_image_delete.images_delete(
                    server="https://test.aquasec.com",
                    token="test-token",
                    days=180,
                    registry=None,
                    scope=None,
                    apply=False,
                    verbose=False,
                    debug=False
                )

                # Verify the first_found_date parameter
                call_args = mock_get.call_args
                assert call_args[1]['first_found_date'] == "over|180|days"

    def test_images_delete_with_scope(self):
        """Test scope filter is passed to API"""
        mock_get_response = Mock()
        mock_get_response.status_code = 200
        mock_get_response.json.return_value = {"result": [], "count": 0}

        with patch('aqua_image_delete.api_get_inventory_images', return_value=mock_get_response) as mock_get:
            with patch('builtins.print'):
                aqua_image_delete.images_delete(
                    server="https://test.aquasec.com",
                    token="test-token",
                    days=90,
                    registry=None,
                    scope="production",
                    apply=False,
                    verbose=False,
                    debug=False
                )

                call_args = mock_get.call_args
                assert call_args[1]['scope'] == "production"

    def test_images_delete_api_error(self):
        """Test API error handling"""
        mock_get_response = Mock()
        mock_get_response.status_code = 401
        mock_get_response.text = "Unauthorized"

        with patch('aqua_image_delete.api_get_inventory_images', return_value=mock_get_response):
            with pytest.raises(SystemExit):
                with patch('builtins.print'):
                    aqua_image_delete.images_delete(
                        server="https://test.aquasec.com",
                        token="invalid-token",
                        days=90,
                        registry=None,
                        scope=None,
                        apply=False,
                        verbose=False,
                        debug=False
                    )

    def test_images_delete_skips_images_without_uid(self):
        """Test images without UID are skipped"""
        mock_get_response = Mock()
        mock_get_response.status_code = 200
        mock_get_response.json.return_value = {
            "result": [
                {"image_uid": 1, "name": "reg/repo:v1", "registry": "reg", "repository": "repo", "tag": "v1"},
                {"name": "reg/repo:v2", "registry": "reg", "repository": "repo", "tag": "v2"},  # No UID
                {"image_uid": 3, "name": "reg/repo:v3", "registry": "reg", "repository": "repo", "tag": "v3"}
            ],
            "count": 3
        }

        mock_empty_response = Mock()
        mock_empty_response.status_code = 200
        mock_empty_response.json.return_value = {"result": [], "count": 3}

        with patch('aqua_image_delete.api_get_inventory_images', side_effect=[mock_get_response, mock_empty_response]):
            with patch('builtins.print') as mock_print:
                aqua_image_delete.images_delete(
                    server="https://test.aquasec.com",
                    token="test-token",
                    days=90,
                    registry=None,
                    scope=None,
                    apply=False,
                    verbose=False,
                    debug=False
                )

                mock_print.assert_called_once()
                args = mock_print.call_args[0][0]

                import json
                result = json.loads(args)

                # Only 2 images with UIDs should be counted
                assert result["summary"]["images_would_delete"] == 2
                assert len(result["deletions"]) == 2


class TestFiltersOutput:
    """Test filters are properly reported in output"""

    def test_filters_in_json_output(self):
        """Test filters appear in JSON output"""
        mock_get_response = Mock()
        mock_get_response.status_code = 200
        mock_get_response.json.return_value = {"result": [], "count": 0}

        with patch('aqua_image_delete.api_get_inventory_images', return_value=mock_get_response):
            with patch('builtins.print') as mock_print:
                aqua_image_delete.images_delete(
                    server="https://test.aquasec.com",
                    token="test-token",
                    days=120,
                    registry="myregistry",
                    scope="production",
                    apply=False,
                    verbose=False,
                    debug=False
                )

                mock_print.assert_called_once()
                args = mock_print.call_args[0][0]

                import json
                result = json.loads(args)

                assert result["filters"]["days"] == 120
                assert result["filters"]["registry"] == "myregistry"
                assert result["filters"]["scope"] == "production"
                assert result["filters"]["has_workloads"] == False


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
