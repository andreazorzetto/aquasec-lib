"""Integration tests for repository delete functionality"""
import sys
import os
import pytest
from unittest.mock import Mock, patch, MagicMock

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the main script
import aqua_repo_delete


class TestRepoDelete:
    """Test repository delete functionality"""

    def test_repos_delete_dry_run_mode(self):
        """Test dry run mode (default behavior)"""
        # Mock API responses
        mock_get_response = Mock()
        mock_get_response.status_code = 200
        mock_get_response.json.return_value = {
            "result": [
                {"name": "test-repo-1", "registry": "Test Registry", "num_images": 5},
                {"name": "test-repo-2", "registry": "Test Registry", "num_images": 0},
                {"name": "test-repo-3", "registry": "Test Registry", "num_images": 2}
            ],
            "count": 3
        }

        with patch('aqua_repo_delete.api_get_repositories', return_value=mock_get_response):
            with patch('builtins.print') as mock_print:
                # Call repos_delete in dry-run mode (apply=False)
                aqua_repo_delete.repos_delete(
                    server="https://test.aquasec.com",
                    token="test-token",
                    registry="Test Registry",
                    empty_only=False,
                    apply=False,
                    verbose=False,
                    debug=False
                )

                # Verify print was called with JSON output
                mock_print.assert_called_once()
                args = mock_print.call_args[0][0]

                # Parse the JSON output
                import json
                result = json.loads(args)

                assert result["mode"] == "dry_run"
                assert result["summary"]["repositories_scanned"] == 3
                assert result["summary"]["repositories_would_delete"] == 3
                assert result["summary"]["repositories_failed"] == 0
                assert len(result["deletions"]) == 3

    def test_repos_delete_empty_only_filter(self):
        """Test empty-only filter"""
        # Mock API responses
        mock_get_response = Mock()
        mock_get_response.status_code = 200
        mock_get_response.json.return_value = {
            "result": [
                {"name": "test-repo-1", "registry": "Test Registry", "num_images": 5},
                {"name": "test-repo-2", "registry": "Test Registry", "num_images": 0},
                {"name": "test-repo-3", "registry": "Test Registry", "num_images": 2},
                {"name": "test-repo-4", "registry": "Test Registry", "num_images": 0}
            ],
            "count": 4
        }

        with patch('aqua_repo_delete.api_get_repositories', return_value=mock_get_response):
            with patch('builtins.print') as mock_print:
                # Call repos_delete with empty_only=True
                aqua_repo_delete.repos_delete(
                    server="https://test.aquasec.com",
                    token="test-token",
                    registry="Test Registry",
                    empty_only=True,
                    apply=False,
                    verbose=False,
                    debug=False
                )

                # Verify print was called with JSON output
                mock_print.assert_called_once()
                args = mock_print.call_args[0][0]

                # Parse the JSON output
                import json
                result = json.loads(args)

                assert result["mode"] == "dry_run"
                assert result["summary"]["repositories_scanned"] == 4
                assert result["summary"]["repositories_would_delete"] == 2  # Only empty repos
                assert len(result["deletions"]) == 2
                # Verify only empty repos are in deletions
                for deletion in result["deletions"]:
                    assert deletion["num_images"] == 0

    def test_repos_delete_apply_mode(self):
        """Test apply mode (actual deletions)"""
        # Mock API responses
        mock_get_response = Mock()
        mock_get_response.status_code = 200
        mock_get_response.json.return_value = {
            "result": [
                {"name": "test-repo-1", "registry": "Test Registry", "num_images": 0},
                {"name": "test-repo-2", "registry": "Test Registry", "num_images": 0}
            ],
            "count": 2
        }

        mock_delete_response = Mock()
        mock_delete_response.status_code = 202  # Test with 202 Accepted

        with patch('aqua_repo_delete.api_get_repositories', return_value=mock_get_response):
            with patch('aqua_repo_delete.api_delete_repo', return_value=mock_delete_response) as mock_delete:
                with patch('builtins.print') as mock_print:
                    # Call repos_delete in apply mode
                    aqua_repo_delete.repos_delete(
                        server="https://test.aquasec.com",
                        token="test-token",
                        registry="Test Registry",
                        empty_only=False,
                        apply=True,
                        verbose=False,
                        debug=False
                    )

                    # Verify delete API was called for each repository
                    assert mock_delete.call_count == 2

                    # Verify the calls were made with correct parameters
                    calls = mock_delete.call_args_list
                    assert calls[0][0] == ("https://test.aquasec.com", "test-token", "Test Registry", "test-repo-1")
                    assert calls[1][0] == ("https://test.aquasec.com", "test-token", "Test Registry", "test-repo-2")

                    # Verify JSON output
                    mock_print.assert_called_once()
                    args = mock_print.call_args[0][0]

                    import json
                    result = json.loads(args)

                    assert result["mode"] == "apply"
                    assert result["summary"]["repositories_deleted"] == 2
                    assert result["summary"]["repositories_failed"] == 0

    def test_repos_delete_with_failures(self):
        """Test handling of deletion failures"""
        # Mock API responses
        mock_get_response = Mock()
        mock_get_response.status_code = 200
        mock_get_response.json.return_value = {
            "result": [
                {"name": "test-repo-1", "registry": "Test Registry", "num_images": 0},
                {"name": "test-repo-2", "registry": "Test Registry", "num_images": 0}
            ],
            "count": 2
        }

        # Mock one successful and one failed deletion
        def mock_delete_side_effect(*args, **kwargs):
            repo_name = args[3]  # Fourth argument is the repository name
            mock_response = Mock()
            if repo_name == "test-repo-1":
                mock_response.status_code = 202  # Successful async delete
            else:
                mock_response.status_code = 403
                mock_response.text = "Forbidden"
            return mock_response

        with patch('aqua_repo_delete.api_get_repositories', return_value=mock_get_response):
            with patch('aqua_repo_delete.api_delete_repo', side_effect=mock_delete_side_effect):
                with patch('builtins.print') as mock_print:
                    # Call repos_delete in apply mode
                    aqua_repo_delete.repos_delete(
                        server="https://test.aquasec.com",
                        token="test-token",
                        registry="Test Registry",
                        empty_only=False,
                        apply=True,
                        verbose=False,
                        debug=False
                    )

                    # Verify JSON output includes failures
                    mock_print.assert_called_once()
                    args = mock_print.call_args[0][0]

                    import json
                    result = json.loads(args)

                    assert result["mode"] == "apply"
                    assert result["summary"]["repositories_deleted"] == 1
                    assert result["summary"]["repositories_failed"] == 1
                    assert "failures" in result
                    assert len(result["failures"]) == 1
                    assert result["failures"][0]["name"] == "test-repo-2"
                    assert "HTTP 403" in result["failures"][0]["error"]

    def test_repos_delete_pagination(self):
        """Test pagination handling"""
        # Mock multiple pages of results
        def mock_get_side_effect(*args, **kwargs):
            page = kwargs.get('page', args[2])  # Page is 3rd argument or in kwargs

            mock_response = Mock()
            mock_response.status_code = 200

            if page == 1:
                mock_response.json.return_value = {
                    "result": [
                        {"name": f"repo-{i}", "registry": "Test Registry", "num_images": 0}
                        for i in range(1, 201)  # 200 repos (full page)
                    ],
                    "count": 250  # Total count
                }
            elif page == 2:
                mock_response.json.return_value = {
                    "result": [
                        {"name": f"repo-{i}", "registry": "Test Registry", "num_images": 0}
                        for i in range(201, 251)  # 50 repos (partial page)
                    ],
                    "count": 250  # Total count
                }
            else:
                mock_response.json.return_value = {
                    "result": [],
                    "count": 250
                }

            return mock_response

        with patch('aqua_repo_delete.api_get_repositories', side_effect=mock_get_side_effect):
            with patch('builtins.print') as mock_print:
                # Call repos_delete - should handle pagination automatically
                aqua_repo_delete.repos_delete(
                    server="https://test.aquasec.com",
                    token="test-token",
                    registry="Test Registry",
                    empty_only=False,
                    apply=False,
                    verbose=False,
                    debug=False
                )

                # Verify all repositories were processed across pages
                mock_print.assert_called_once()
                args = mock_print.call_args[0][0]

                import json
                result = json.loads(args)

                assert result["summary"]["repositories_scanned"] == 250
                assert result["summary"]["repositories_would_delete"] == 250

    def test_api_error_handling(self):
        """Test API error handling"""
        # Mock API error response
        mock_get_response = Mock()
        mock_get_response.status_code = 401
        mock_get_response.text = "Unauthorized"

        with patch('aqua_repo_delete.api_get_repositories', return_value=mock_get_response):
            with pytest.raises(SystemExit):
                with patch('builtins.print') as mock_print:
                    aqua_repo_delete.repos_delete(
                        server="https://test.aquasec.com",
                        token="invalid-token",
                        registry="Test Registry",
                        empty_only=False,
                        apply=False,
                        verbose=False,
                        debug=False
                    )


if __name__ == '__main__':
    pytest.main([__file__, '-v'])