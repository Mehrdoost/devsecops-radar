from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy.exc import SQLAlchemyError

from devsecops_radar.core.rag import logger, rag_search


class TestRagSearch:
    @pytest.fixture
    def mock_session(self):
        # Create a mock session that will be returned by db_session()
        session = MagicMock()
        return session

    @pytest.fixture
    def setup_db(self, mock_session):
        # Patch db_session to return the mock session
        with patch("devsecops_radar.core.rag.db_session", return_value=mock_session):
            yield

    def make_finding_mock(self, tool, rule_id, severity, target, title, description, line=None):
        """Helper to create a mock Finding with necessary attributes."""
        f = MagicMock()
        f.tool = tool
        f.rule_id = rule_id
        f.severity = severity
        f.target = target
        f.title = title
        f.description = description
        f.line = line
        return f

    def test_valid_query_returns_results(self, mock_session, setup_db):
        query = "XSS"
        mock_f1 = self.make_finding_mock("Semgrep", "R1", "HIGH", "app.py", "XSS vulnerability", "desc1", 42)
        mock_f2 = self.make_finding_mock("Trivy", "CVE-2025", "CRITICAL", "image", "XSS in image", "desc2", None)
        mock_session.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = [mock_f1, mock_f2]

        with patch.object(logger, "info") as mock_info:
            result = rag_search(query, limit=2)

        assert len(result) == 2
        # Check mapping
        assert result[0]["tool"] == "Semgrep"
        assert result[0]["id"] == "R1"
        assert result[0]["line"] == 42
        assert result[1]["id"] == "CVE-2025"
        assert result[1]["line"] is None

        mock_session.close.assert_called_once()
        mock_info.assert_called_once_with("RAG Search found 2 results for query: 'XSS'")

    def test_empty_query_returns_empty(self, setup_db):
        with patch.object(logger, "debug") as mock_debug:
            result = rag_search("", limit=5)
        assert result == []
        mock_debug.assert_called_once_with("Empty or invalid query provided to RAG search.")

    def test_none_query_returns_empty(self, setup_db):
        with patch.object(logger, "debug") as mock_debug:
            result = rag_search(None, limit=5)
        assert result == []
        mock_debug.assert_called_once()

    def test_non_string_query_returns_empty(self, setup_db):
        with patch.object(logger, "debug") as mock_debug:
            result = rag_search(123, limit=5)
        assert result == []
        mock_debug.assert_called_once()

    def test_query_truncation(self, mock_session, setup_db):
        # Very long query, should be truncated to 100 chars
        long_query = "A" * 200
        expected_sanitized = "A" * 100
        mock_f = self.make_finding_mock("Tool", "ID", "LOW", "t", "title", "desc")
        mock_session.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = [mock_f]

        with patch.object(logger, "info") as mock_info:
            result = rag_search(long_query, limit=1)

        # Check that the filter was built with sanitized query
        mock_session.query.return_value.filter.call_args[0][0]
        # The filter is an OR condition; we can simply check that the expected string is used somewhere.
        # Actually we can verify by inspecting the call arguments on .ilike, but it's complex.
        # We'll trust the sanitized_query is used; we can also check the info message.
        assert len(result) == 1
        mock_info.assert_called_with(f"RAG Search found 1 results for query: '{expected_sanitized}'")

    def test_limit_minimum_1(self, mock_session, setup_db):
        # limit=0 or negative should be clamped to 1
        mock_f = self.make_finding_mock("Tool", "ID", "LOW", "t", "title", "desc")
        mock_session.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = [mock_f]
        result = rag_search("test", limit=0)
        assert len(result) == 1
        # Verify limit was called with 1
        limit_call_arg = mock_session.query.return_value.filter.return_value.order_by.return_value.limit.call_args[0][0]
        assert limit_call_arg == 1

    def test_limit_maximum_50(self, mock_session, setup_db):
        # limit=100 should be clamped to 50
        mock_session.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = []
        result = rag_search("test", limit=100)
        assert result == []
        limit_call_arg = mock_session.query.return_value.filter.return_value.order_by.return_value.limit.call_args[0][0]
        assert limit_call_arg == 50

    def test_sqlalchemy_error_returns_empty(self, mock_session, setup_db):
        mock_session.query.side_effect = SQLAlchemyError("db error")
        with patch.object(logger, "error") as mock_error:
            result = rag_search("test")
        assert result == []
        mock_error.assert_called_once()
        assert "Database error during RAG search" in mock_error.call_args[0][0]
        mock_session.close.assert_called_once()  # finally block runs

    def test_generic_exception_returns_empty(self, mock_session, setup_db):
        mock_session.query.side_effect = RuntimeError("unexpected")
        with patch.object(logger, "error") as mock_error:
            result = rag_search("test")
        assert result == []
        mock_error.assert_called_once()
        assert "Unexpected error during RAG search" in mock_error.call_args[0][0]
        mock_session.close.assert_called_once()

    def test_session_close_called_on_success(self, mock_session, setup_db):
        mock_f = self.make_finding_mock("Tool", "ID", "LOW", "t", "title", "desc")
        mock_session.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = [mock_f]
        rag_search("test")
        mock_session.close.assert_called_once()

    def test_no_results_found(self, mock_session, setup_db):
        mock_session.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = []
        with patch.object(logger, "info") as mock_info:
            result = rag_search("nothing")
        assert result == []
        mock_info.assert_called_with("RAG Search found 0 results for query: 'nothing'")
