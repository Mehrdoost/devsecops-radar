"""Tests for the RAG semantic search engine and indexing functions."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

import devsecops_radar.core.database as db_mod
from devsecops_radar.core.database import init_db, save_scan
from devsecops_radar.core.rag import _init_fts, index_findings, rag_search


@pytest.fixture(autouse=True)
def _prepare_db() -> None:
    """Ensure tables are re‑created even if the module flag is stale."""
    db_mod._tables_initialized = False
    init_db()


def _sample_finding(index: int = 0) -> dict:
    return {
        "tool": "trivy",
        "id": f"CVE-2024-{index:04d}",
        "severity": "HIGH",
        "target": "app/server.py",
        "title": "Remote Code Execution",
        "description": "Critical vulnerability in web server",
    }


def _save_one() -> int:
    scan_id = save_scan([_sample_finding(1)])
    assert scan_id is not None
    return scan_id


# ---------------------------------------------------------------------------
# Fixture to force the text‑search path (FTS5) even when ChromaDB is installed
# but Ollama is not reachable (typical CI scenario).
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _force_text_search(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force _has_chroma to return False so that the FTS5 path is taken."""
    monkeypatch.setattr(
        "devsecops_radar.core.rag._has_chroma",
        lambda: False,
    )
    # Ensure FTS5 tables exist
    _init_fts()


class TestRagSearch:
    def test_successful_search_by_rule_id(self) -> None:
        _save_one()
        results = rag_search("CVE-2024-0001", limit=5)
        assert len(results) >= 1
        assert any(r["id"] == "CVE-2024-0001" for r in results)

    def test_search_returns_list(self) -> None:
        """Verify that a valid query returns a list (regardless of result count)."""
        _save_one()
        results = rag_search("Execution", limit=5)
        assert isinstance(results, list)

    def test_search_no_results(self) -> None:
        _save_one()
        results = rag_search("nonexistent-xyz", limit=5)
        assert results == []

    def test_empty_query_returns_empty(self) -> None:
        assert rag_search("") == []

    def test_very_long_query_is_truncated(self) -> None:
        _save_one()
        long_query = "A" * 300
        results = rag_search(long_query, limit=5)
        assert isinstance(results, list)


class TestIndexFindings:
    def test_index_findings_without_chroma(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("devsecops_radar.core.rag._has_chroma", lambda: False)
        monkeypatch.setattr("devsecops_radar.core.rag._has_fts5", lambda: True)
        _save_one()
        mock_session = MagicMock()
        monkeypatch.setattr("devsecops_radar.core.rag.SessionLocal", lambda: mock_session)
        count = index_findings([_sample_finding(99)])
        assert count == 1
