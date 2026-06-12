"""Tests for the RAG search module."""

from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest
from loguru import logger
from sqlalchemy.exc import SQLAlchemyError

from devsecops_radar.core.rag import rag_search


# ---------------------------------------------------------------------------
# Capture loguru output
# ---------------------------------------------------------------------------
@contextmanager
def capture_loguru(level: str = "TRACE"):
    messages: list[str] = []

    def sink(msg):
        messages.append(str(msg))

    handler_id = logger.add(sink, level=level, format="{message}")
    try:
        yield messages
    finally:
        logger.remove(handler_id)


# ---------------------------------------------------------------------------
# Fixture – mock the database session
# ---------------------------------------------------------------------------
@pytest.fixture
def mock_db_session():
    """Replace the global db_session with a MagicMock."""
    session = MagicMock()
    with patch("devsecops_radar.core.rag.db_session", return_value=session):
        yield session


# ---------------------------------------------------------------------------
# Helper to create a mock Finding row
# ---------------------------------------------------------------------------
def mock_finding(
    tool="semgrep",
    rule_id="R1",
    severity="HIGH",
    target="app.py",
    title="SQLi",
    description="Found SQL injection",
    line=42,
):
    f = MagicMock()
    f.tool = tool
    f.rule_id = rule_id
    f.severity = severity
    f.target = target
    f.title = title
    f.description = description
    f.line = line
    return f


# ============================================================================
# Tests
# ============================================================================
class TestRagSearch:
    def test_empty_query(self):
        result = rag_search("")
        assert result == []
        result = rag_search(None)
        assert result == []

    def test_non_string_query(self):
        result = rag_search(123)
        assert result == []

    def test_query_truncation(self, mock_db_session):
        long_query = "A" * 200
        mock_db_session.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = []

        with capture_loguru() as msgs:
            rag_search(long_query)

        # The log message contains the sanitized query (first 100 chars)
        truncated = "A" * 100
        assert any(truncated in m for m in msgs)
        assert not any(long_query in m for m in msgs)

    def test_limit_clamped_to_maximum(self, mock_db_session):
        mock_db_session.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = []

        rag_search("test", limit=100)  # exceeds max 50

        # The limit call should be with 50
        mock_db_session.query.return_value.filter.return_value.order_by.return_value.limit.assert_called_with(50)

    def test_limit_clamped_to_minimum(self, mock_db_session):
        mock_db_session.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = []

        rag_search("test", limit=0)

        mock_db_session.query.return_value.filter.return_value.order_by.return_value.limit.assert_called_with(1)

    def test_successful_search(self, mock_db_session):
        f1 = mock_finding(tool="trivy", rule_id="CVE-123", severity="CRITICAL")
        f2 = mock_finding(tool="semgrep", rule_id="R2", severity="LOW")
        mock_db_session.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = [f1, f2]

        with capture_loguru() as msgs:
            result = rag_search("critical")

        assert len(result) == 2
        assert result[0]["id"] == "CVE-123"
        assert result[0]["tool"] == "trivy"
        assert result[0]["severity"] == "CRITICAL"
        assert result[0]["line"] == 42  # default from mock_finding
        assert result[1]["id"] == "R2"
        assert any("found 2 results" in m for m in msgs)

    def test_no_results(self, mock_db_session):
        mock_db_session.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = []

        with capture_loguru() as msgs:
            result = rag_search("nonexistent")

        assert result == []
        assert any("found 0 results" in m for m in msgs)

    def test_sqlalchemy_error(self, mock_db_session):
        mock_db_session.query.side_effect = SQLAlchemyError("db error")

        with capture_loguru() as msgs:
            result = rag_search("fail")

        assert result == []
        assert any("Database error during RAG search" in m for m in msgs)

    def test_generic_exception(self, mock_db_session):
        mock_db_session.query.side_effect = RuntimeError("unexpected")

        with capture_loguru() as msgs:
            result = rag_search("fail")

        assert result == []
        assert any("Unexpected error during RAG search" in m for m in msgs)

    def test_missing_line_attribute(self, mock_db_session):
        """If a Finding row does not have a 'line' attribute, it should default to None."""
        f = mock_finding()
        del f.line  # remove line attribute
        mock_db_session.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = [f]

        result = rag_search("test")
        assert len(result) == 1
        assert result[0]["line"] is None
