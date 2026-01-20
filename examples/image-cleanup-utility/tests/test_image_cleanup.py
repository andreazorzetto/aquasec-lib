"""Integration tests for image cleanup functionality"""
import sys
import os
import pytest
from unittest.mock import Mock, patch

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the main script
import aqua_image_cleanup


class TestImagesCleanup:
    """Test image cleanup functionality"""

    def test_images_cleanup_dry_run_mode(self):
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

        with patch('aqua_image_cleanup.api_get_inventory_images', side_effect=[mock_get_response, mock_empty_response]):
            with patch('builtins.print') as mock_print:
                aqua_image_cleanup.images_cleanup(
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

    def test_images_cleanup_with_registry_filter(self):
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

        with patch('aqua_image_cleanup.api_get_inventory_images', side_effect=[mock_get_response, mock_empty_response]) as mock_get:
            with patch('builtins.print') as mock_print:
                aqua_image_cleanup.images_cleanup(
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

    def test_images_cleanup_apply_mode(self):
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

        with patch('aqua_image_cleanup.api_get_inventory_images', side_effect=[mock_get_response, mock_empty_response]):
            with patch('aqua_image_cleanup.api_delete_images', return_value=mock_delete_response) as mock_delete:
                with patch('builtins.print') as mock_print:
                    aqua_image_cleanup.images_cleanup(
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

    def test_images_cleanup_with_failures(self):
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

        with patch('aqua_image_cleanup.api_get_inventory_images', side_effect=[mock_get_response, mock_empty_response]):
            with patch('aqua_image_cleanup.api_delete_images', return_value=mock_delete_response):
                with patch('builtins.print') as mock_print:
                    aqua_image_cleanup.images_cleanup(
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

    def test_images_cleanup_pagination(self):
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

        with patch('aqua_image_cleanup.api_get_inventory_images', side_effect=[page1_response, page2_response, empty_response]):
            with patch('aqua_image_cleanup.api_delete_images', return_value=mock_delete_response) as mock_delete:
                with patch('builtins.print') as mock_print:
                    aqua_image_cleanup.images_cleanup(
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

    def test_images_cleanup_custom_days(self):
        """Test custom days threshold"""
        mock_get_response = Mock()
        mock_get_response.status_code = 200
        mock_get_response.json.return_value = {"result": [], "count": 0}

        with patch('aqua_image_cleanup.api_get_inventory_images', return_value=mock_get_response) as mock_get:
            with patch('builtins.print'):
                aqua_image_cleanup.images_cleanup(
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

    def test_images_cleanup_with_scope(self):
        """Test scope filter is passed to API"""
        mock_get_response = Mock()
        mock_get_response.status_code = 200
        mock_get_response.json.return_value = {"result": [], "count": 0}

        with patch('aqua_image_cleanup.api_get_inventory_images', return_value=mock_get_response) as mock_get:
            with patch('builtins.print'):
                aqua_image_cleanup.images_cleanup(
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

    def test_images_cleanup_api_error(self):
        """Test API error handling"""
        mock_get_response = Mock()
        mock_get_response.status_code = 401
        mock_get_response.text = "Unauthorized"

        with patch('aqua_image_cleanup.api_get_inventory_images', return_value=mock_get_response):
            with pytest.raises(SystemExit):
                with patch('builtins.print'):
                    aqua_image_cleanup.images_cleanup(
                        server="https://test.aquasec.com",
                        token="invalid-token",
                        days=90,
                        registry=None,
                        scope=None,
                        apply=False,
                        verbose=False,
                        debug=False
                    )

    def test_images_cleanup_skips_images_without_uid(self):
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

        with patch('aqua_image_cleanup.api_get_inventory_images', side_effect=[mock_get_response, mock_empty_response]):
            with patch('builtins.print') as mock_print:
                aqua_image_cleanup.images_cleanup(
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


class TestFileBasedCleanup:
    """Test file-based image cleanup functionality"""

    def test_file_cleanup_dry_run_mode(self, tmp_path):
        """Test dry run mode with CSV file"""
        # Create test CSV file
        csv_file = tmp_path / "test_images.csv"
        csv_file.write_text(
            '"image_id","image_name","registry_id","created"\n'
            '1001,repo/image1:v1,my_registry,2025-01-01 10:00:00\n'
            '1002,repo/image2:v2,my_registry,2025-01-01 10:00:00\n'
            '1003,repo/image3:latest,my_registry,2025-01-01 10:00:00\n'
        )

        with patch('builtins.print') as mock_print:
            aqua_image_cleanup.images_cleanup_from_file(
                server="https://test.aquasec.com",
                token="test-token",
                file_path=str(csv_file),
                batch_size=200,
                apply=False,
                verbose=False,
                debug=False
            )

            mock_print.assert_called_once()
            args = mock_print.call_args[0][0]

            import json
            result = json.loads(args)

            assert result["mode"] == "dry_run"
            assert result["source"] == "file"
            assert result["summary"]["images_scanned"] == 3
            assert result["summary"]["images_would_delete"] == 3
            assert len(result["deletions"]) == 3

    def test_file_cleanup_apply_mode(self, tmp_path):
        """Test apply mode with CSV file"""
        csv_file = tmp_path / "test_images.csv"
        csv_file.write_text(
            '"image_id","image_name","registry_id","created"\n'
            '1001,repo/image1:v1,my_registry,2025-01-01 10:00:00\n'
            '1002,repo/image2:v2,my_registry,2025-01-01 10:00:00\n'
        )

        mock_delete_response = Mock()
        mock_delete_response.status_code = 200

        with patch('aqua_image_cleanup.api_delete_images', return_value=mock_delete_response) as mock_delete:
            with patch('builtins.print') as mock_print:
                aqua_image_cleanup.images_cleanup_from_file(
                    server="https://test.aquasec.com",
                    token="test-token",
                    file_path=str(csv_file),
                    batch_size=200,
                    apply=True,
                    verbose=False,
                    debug=False
                )

                # Verify delete API was called with integer IDs
                mock_delete.assert_called_once()
                call_args = mock_delete.call_args
                assert call_args[0][0] == "https://test.aquasec.com"
                assert call_args[0][1] == "test-token"
                assert set(call_args[0][2]) == {1001, 1002}  # Integer IDs

                mock_print.assert_called_once()
                args = mock_print.call_args[0][0]

                import json
                result = json.loads(args)

                assert result["mode"] == "apply"
                assert result["summary"]["images_deleted"] == 2
                assert result["summary"]["images_failed"] == 0

    def test_file_cleanup_batching(self, tmp_path):
        """Test batching with custom batch size"""
        # Create CSV with 5 images
        csv_content = '"image_id","image_name","registry_id","created"\n'
        for i in range(1, 6):
            csv_content += f'{1000+i},repo/image{i}:v{i},my_registry,2025-01-01 10:00:00\n'

        csv_file = tmp_path / "test_images.csv"
        csv_file.write_text(csv_content)

        mock_delete_response = Mock()
        mock_delete_response.status_code = 200

        with patch('aqua_image_cleanup.api_delete_images', return_value=mock_delete_response) as mock_delete:
            with patch('builtins.print'):
                aqua_image_cleanup.images_cleanup_from_file(
                    server="https://test.aquasec.com",
                    token="test-token",
                    file_path=str(csv_file),
                    batch_size=2,  # Small batch size to test batching
                    apply=True,
                    verbose=False,
                    debug=False
                )

                # Should be called 3 times: 2 + 2 + 1
                assert mock_delete.call_count == 3

                # First batch: 2 IDs
                first_call_ids = mock_delete.call_args_list[0][0][2]
                assert len(first_call_ids) == 2

                # Second batch: 2 IDs
                second_call_ids = mock_delete.call_args_list[1][0][2]
                assert len(second_call_ids) == 2

                # Third batch: 1 ID
                third_call_ids = mock_delete.call_args_list[2][0][2]
                assert len(third_call_ids) == 1

    def test_file_cleanup_with_failures(self, tmp_path):
        """Test handling of deletion failures"""
        csv_file = tmp_path / "test_images.csv"
        csv_file.write_text(
            '"image_id","image_name","registry_id","created"\n'
            '1001,repo/image1:v1,my_registry,2025-01-01 10:00:00\n'
            '1002,repo/image2:v2,my_registry,2025-01-01 10:00:00\n'
        )

        mock_delete_response = Mock()
        mock_delete_response.status_code = 403
        mock_delete_response.text = "Forbidden"

        with patch('aqua_image_cleanup.api_delete_images', return_value=mock_delete_response):
            with patch('builtins.print') as mock_print:
                aqua_image_cleanup.images_cleanup_from_file(
                    server="https://test.aquasec.com",
                    token="test-token",
                    file_path=str(csv_file),
                    batch_size=200,
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

    def test_file_cleanup_skips_invalid_ids(self, tmp_path):
        """Test rows with invalid/missing image_id are skipped"""
        csv_file = tmp_path / "test_images.csv"
        csv_file.write_text(
            '"image_id","image_name","registry_id","created"\n'
            '1001,repo/image1:v1,my_registry,2025-01-01 10:00:00\n'
            ',repo/image2:v2,my_registry,2025-01-01 10:00:00\n'  # Empty ID
            'invalid,repo/image3:v3,my_registry,2025-01-01 10:00:00\n'  # Non-integer
            '1004,repo/image4:v4,my_registry,2025-01-01 10:00:00\n'
        )

        with patch('builtins.print') as mock_print:
            aqua_image_cleanup.images_cleanup_from_file(
                server="https://test.aquasec.com",
                token="test-token",
                file_path=str(csv_file),
                batch_size=200,
                apply=False,
                verbose=False,
                debug=False
            )

            mock_print.assert_called_once()
            args = mock_print.call_args[0][0]

            import json
            result = json.loads(args)

            # 4 rows scanned, but only 2 valid
            assert result["summary"]["images_scanned"] == 4
            assert result["summary"]["images_would_delete"] == 2
            assert len(result["deletions"]) == 2

    def test_file_cleanup_file_not_found(self, tmp_path):
        """Test error handling for missing file"""
        with pytest.raises(SystemExit):
            with patch('builtins.print'):
                aqua_image_cleanup.images_cleanup_from_file(
                    server="https://test.aquasec.com",
                    token="test-token",
                    file_path="/nonexistent/file.csv",
                    batch_size=200,
                    apply=False,
                    verbose=False,
                    debug=False
                )

    def test_file_cleanup_parses_image_name(self, tmp_path):
        """Test image_name is properly parsed into repository and tag"""
        csv_file = tmp_path / "test_images.csv"
        csv_file.write_text(
            '"image_id","image_name","registry_id","created"\n'
            '1001,my-repo/sub-path/image:v1.2.3,my_registry,2025-01-01 10:00:00\n'
            '1002,simple-image:latest,other_registry,2025-01-01 10:00:00\n'
            '1003,no-tag-image,another_registry,2025-01-01 10:00:00\n'
        )

        with patch('builtins.print') as mock_print:
            aqua_image_cleanup.images_cleanup_from_file(
                server="https://test.aquasec.com",
                token="test-token",
                file_path=str(csv_file),
                batch_size=200,
                apply=False,
                verbose=False,
                debug=False
            )

            mock_print.assert_called_once()
            args = mock_print.call_args[0][0]

            import json
            result = json.loads(args)

            deletions = result["deletions"]

            # First image: complex path with tag
            assert deletions[0]["repository"] == "my-repo/sub-path/image"
            assert deletions[0]["tag"] == "v1.2.3"
            assert deletions[0]["registry"] == "my_registry"

            # Second image: simple with tag
            assert deletions[1]["repository"] == "simple-image"
            assert deletions[1]["tag"] == "latest"

            # Third image: no tag
            assert deletions[2]["repository"] == "no-tag-image"
            assert deletions[2]["tag"] == ""


class TestProcessBatch:
    """Test _process_batch helper function"""

    def test_process_batch_success(self):
        """Test successful batch processing"""
        mock_delete_response = Mock()
        mock_delete_response.status_code = 200

        batch_ids = [1001, 1002, 1003]
        batch_images = [
            {"image_id": 1001, "registry": "reg", "repository": "repo", "tag": "v1", "name": "repo:v1"},
            {"image_id": 1002, "registry": "reg", "repository": "repo", "tag": "v2", "name": "repo:v2"},
            {"image_id": 1003, "registry": "reg", "repository": "repo", "tag": "v3", "name": "repo:v3"},
        ]

        with patch('aqua_image_cleanup.api_delete_images', return_value=mock_delete_response):
            deleted, failed, del_list, fail_list = aqua_image_cleanup._process_batch(
                "https://test.aquasec.com", "test-token",
                batch_ids, batch_images, apply=True, verbose=False, debug=False
            )

            assert deleted == 3
            assert failed == 0
            assert len(del_list) == 3
            assert len(fail_list) == 0

    def test_process_batch_dry_run(self):
        """Test dry run batch processing (no API call)"""
        batch_ids = [1001, 1002]
        batch_images = [
            {"image_id": 1001, "registry": "reg", "repository": "repo", "tag": "v1", "name": "repo:v1"},
            {"image_id": 1002, "registry": "reg", "repository": "repo", "tag": "v2", "name": "repo:v2"},
        ]

        with patch('aqua_image_cleanup.api_delete_images') as mock_delete:
            deleted, failed, del_list, fail_list = aqua_image_cleanup._process_batch(
                "https://test.aquasec.com", "test-token",
                batch_ids, batch_images, apply=False, verbose=False, debug=False
            )

            # API should not be called in dry run
            mock_delete.assert_not_called()

            assert deleted == 2
            assert failed == 0
            assert len(del_list) == 2
            assert len(fail_list) == 0


class TestFiltersOutput:
    """Test filters are properly reported in output"""

    def test_filters_in_json_output(self):
        """Test filters appear in JSON output"""
        mock_get_response = Mock()
        mock_get_response.status_code = 200
        mock_get_response.json.return_value = {"result": [], "count": 0}

        with patch('aqua_image_cleanup.api_get_inventory_images', return_value=mock_get_response):
            with patch('builtins.print') as mock_print:
                aqua_image_cleanup.images_cleanup(
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
