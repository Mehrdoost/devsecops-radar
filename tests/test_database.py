"""Tests for database persistence module."""

from contextlib import contextmanager
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest
from loguru import logger

from devsecops_radar.core.database import (
    _truncate_string,
    compare_scans,
    get_all_scans,
    get_findings_paginated,
    get_scan_by_id,
    init_db,
    save_scan,
)


# ---------------------------------------------------------------------------
# Helper to capture loguru output
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
# Fixture that fully replaces the scoped session with a mock
# ---------------------------------------------------------------------------
@pytest.fixture
def mock_db_session():
    """Return a mock session and ensure db_session() returns it."""
    session = MagicMock()
    with patch(
        "devsecops_radar.core.database.db_session", return_value=session
    ):
        yield session


# ---------------------------------------------------------------------------
# Tests for init_db
# ---------------------------------------------------------------------------
class TestInitDb:
    def test_initializes_once(self):
        with patch(
            "devsecops_radar.core.database.models_init_db"
        ) as mock_models_init:
            import devsecops_radar.core.database as db_mod

            db_mod._tables_initialized = False
            init_db()
            assert db_mod._tables_initialized is True
            mock_models_init.assert_called_once()

            init_db()
            mock_models_init.assert_called_once()  # still once


# ---------------------------------------------------------------------------
# Tests for _truncate_string
# ---------------------------------------------------------------------------
class TestTruncateString:
    def test_short_string_passed_through(self):
        assert _truncate_string("hello", 10) == "hello"

    def test_long_string_truncated(self):
        s = "x" * 3000
        truncated = _truncate_string(s, 2000)
        assert len(truncated) == 2000
        assert truncated == s[:2000]

    def test_none_value_returns_none(self):
        assert _truncate_string(None) is None

    def test_empty_string_returns_empty(self):
        assert _truncate_string("") == ""


# ---------------------------------------------------------------------------
# Tests for save_scan
# ---------------------------------------------------------------------------
class TestSaveScan:
    @pytest.fixture(autouse=True)
    def reset_tables_flag(self):
        import devsecops_radar.core.database as db_mod

        old = db_mod._tables_initialized
        db_mod._tables_initialized = False
        yield
        db_mod._tables_initialized = old

    @pytest.fixture
    def mock_models(self):
        with patch(
            "devsecops_radar.core.database.models_init_db"
        ) as mock_init, patch(
            "devsecops_radar.core.database.Scan"
        ) as mock_scan_cls, patch(
            "devsecops_radar.core.database.Finding"
        ) as mock_finding_cls:
            yield mock_init, mock_scan_cls, mock_finding_cls

    def test_saves_scan_and_findings(
        self, mock_models, mock_db_session
    ):
        mock_init, mock_scan_cls, mock_finding_cls = mock_models
        mock_scan = MagicMock()
        mock_scan.id = 42
        mock_scan_cls.return_value = mock_scan

        findings = [
            {
                "tool": "semgrep",
                "id": "rule-1",
                "severity": "HIGH",
                "target": "app.py",
                "title": "SQL Injection",
                "description": "Found SQLi",
                "line": 100,
            },
            {"tool": "trivy", "id": "CVE-123"},
        ]
        ai_summary = {"risk_score": 85}

        with capture_loguru() as msgs:
            save_scan(findings, ai_summary)

        mock_scan_cls.assert_called_once()
        kwargs = mock_scan_cls.call_args[1]
        assert kwargs["risk_score"] == 85
        assert kwargs["hardware_profile"] is None
        assert kwargs["execution_time"] is None
        assert isinstance(kwargs["timestamp"], datetime)

        # Use assert_any_call because add is called for the scan and then for each finding
        mock_db_session.add.assert_any_call(mock_scan)
        mock_db_session.flush.assert_called_once()
        mock_db_session.commit.assert_called_once()

        assert mock_finding_cls.call_count == 2
        call1 = mock_finding_cls.call_args_list[0][1]
        assert call1["tool"] == "semgrep"
        assert call1["rule_id"] == "rule-1"
        assert call1["severity"] == "HIGH"
        assert call1["target"] == "app.py"
        assert call1["title"] == "SQL Injection"
        assert call1["description"] == "Found SQLi"
        assert call1["line"] == 100
        assert call1["scan_id"] == 42

        call2 = mock_finding_cls.call_args_list[1][1]
        assert call2["tool"] == "trivy"
        assert call2["rule_id"] == "CVE-123"
        assert call2["severity"] == "LOW"
        assert call2["target"] == "UNKNOWN"
        assert call2["title"] == ""
        assert call2["description"] == ""

        assert any("Scan 42 saved" in m for m in msgs)

    def test_rollback_on_error(self, mock_models, mock_db_session):
        _, _, _ = mock_models
        mock_db_session.commit.side_effect = Exception("DB error")
        findings = [{"tool": "test"}]
        with capture_loguru() as msgs:
            with pytest.raises(Exception, match="DB error"):
                save_scan(findings)
        mock_db_session.rollback.assert_called_once()
        assert any("Failed to save scan" in m for m in msgs)

    def test_truncates_long_strings_in_findings(
        self, mock_models, mock_db_session
    ):
        _, mock_scan_cls, mock_finding_cls = mock_models
        mock_scan = MagicMock()
        mock_scan.id = 1
        mock_scan_cls.return_value = mock_scan
        long_title = "a" * 1000
        long_desc = "b" * 3000
        findings = [
            {"tool": "checkov", "title": long_title, "description": long_desc}
        ]
        save_scan(findings)
        call = mock_finding_cls.call_args[1]
        assert call["title"] == long_title[:500]
        assert call["description"] == long_desc[:2000]


# ---------------------------------------------------------------------------
# Tests for get_all_scans
# ---------------------------------------------------------------------------
class TestGetAllScans:
    def test_returns_list_of_scans(self, mock_db_session):
        mock_scan1 = MagicMock()
        mock_scan1.id = 1
        mock_scan1.timestamp = datetime(2025, 1, 1, tzinfo=UTC)
        mock_scan1.risk_score = 60
        mock_scan1.hardware_profile = "profile1"
        mock_scan2 = MagicMock()
        mock_scan2.id = 2
        mock_scan2.timestamp = None
        mock_scan2.risk_score = None
        mock_scan2.hardware_profile = None

        mock_db_session.query.return_value.order_by.return_value.all.return_value = [
            mock_scan1,
            mock_scan2,
        ]
        result = get_all_scans()
        assert len(result) == 2
        assert result[0]["scan_id"] == 1
        assert result[0]["timestamp"] == "2025-01-01T00:00:00+00:00"
        assert result[1]["scan_id"] == 2
        assert result[1]["timestamp"] is None


# ---------------------------------------------------------------------------
# Tests for get_scan_by_id
# ---------------------------------------------------------------------------
class TestGetScanById:
    def test_existing_scan(self, mock_db_session):
        mock_finding = MagicMock()
        mock_finding.id = 99
        mock_finding.tool = "semgrep"
        mock_finding.rule_id = "r1"
        mock_finding.severity = "HIGH"
        mock_finding.target = "file.py"
        mock_finding.title = "SQLi"
        mock_finding.description = "Found"
        mock_scan = MagicMock()
        mock_scan.id = 5
        mock_scan.timestamp = datetime(2025, 6, 1, tzinfo=UTC)
        mock_scan.risk_score = 85
        mock_scan.hardware_profile = "x86"
        mock_scan.execution_time = 12.3
        mock_scan.findings = [mock_finding]

        mock_db_session.query.return_value.filter.return_value.first.return_value = (
            mock_scan
        )

        result = get_scan_by_id(5)
        assert result is not None
        assert result["scan_id"] == 5
        assert result["timestamp"] == "2025-06-01T00:00:00+00:00"
        assert len(result["findings"]) == 1
        f0 = result["findings"][0]
        assert f0["finding_db_id"] == 99
        assert f0["tool"] == "semgrep"

    def test_non_existent_scan(self, mock_db_session):
        mock_db_session.query.return_value.filter.return_value.first.return_value = None
        assert get_scan_by_id(999) is None


# ---------------------------------------------------------------------------
# Tests for get_findings_paginated
# ---------------------------------------------------------------------------
class TestGetFindingsPaginated:
    def test_default_page(self, mock_db_session):
        mock_count = 120
        mock_db_session.query.return_value.count.return_value = mock_count
        findings_mock = [MagicMock() for _ in range(50)]
        for i, f in enumerate(findings_mock):
            f.scan_id = i
            f.tool = "tool"
            f.rule_id = f"R{i}"
            f.severity = "MEDIUM"
            f.target = "target"
            f.title = f"Issue {i}"

        mock_db_session.query.return_value.order_by.return_value.offset.return_value.limit.return_value.all.return_value = findings_mock

        result = get_findings_paginated()
        assert result["total"] == 120
        assert result["page"] == 1
        assert result["per_page"] == 50
        assert len(result["data"]) == 50

    def test_custom_page_and_per_page(self, mock_db_session):
        mock_db_session.query.return_value.count.return_value = 5
        findings_mock = [MagicMock() for _ in range(2)]
        mock_db_session.query.return_value.order_by.return_value.offset.return_value.limit.return_value.all.return_value = findings_mock

        result = get_findings_paginated(page=2, per_page=2)
        assert result["page"] == 2
        assert result["per_page"] == 2

    def test_clamps_page_and_per_page(self, mock_db_session):
        mock_db_session.query.return_value.count.return_value = 0
        findings_mock = []
        mock_db_session.query.return_value.order_by.return_value.offset.return_value.limit.return_value.all.return_value = findings_mock

        result = get_findings_paginated(page=0, per_page=200)
        assert result["page"] == 1
        assert result["per_page"] == 100


# ---------------------------------------------------------------------------
# Tests for compare_scans
# ---------------------------------------------------------------------------
class TestCompareScans:
    def test_both_existing(self):
        scan1 = {
            "scan_id": 1,
            "findings": [
                {"tool": "A", "id": "1", "target": "f1", "severity": "HIGH"}
            ],
        }
        scan2 = {
            "scan_id": 2,
            "findings": [
                {"tool": "B", "id": "2", "target": "f2", "severity": "MEDIUM"}
            ],
        }
        with patch(
            "devsecops_radar.core.database.get_scan_by_id",
            side_effect=[scan1, scan2],
        ):
            result = compare_scans(1, 2)
        assert "added" in result
        assert "removed" in result
        assert len(result["added"]) == 1
        assert result["added"][0]["tool"] == "B"
        assert len(result["removed"]) == 1
        assert result["removed"][0]["tool"] == "A"

    def test_one_missing(self):
        with patch(
            "devsecops_radar.core.database.get_scan_by_id",
            side_effect=[None, {"scan_id": 2}],
        ):
            result = compare_scans(1, 2)
        assert "error" in result

    def test_identical_findings(self):
        finding = {"tool": "X", "id": "Y", "target": "Z", "severity": "LOW"}
        scan1 = {"scan_id": 1, "findings": [finding]}
        scan2 = {"scan_id": 2, "findings": [finding]}
        with patch(
            "devsecops_radar.core.database.get_scan_by_id",
            side_effect=[scan1, scan2],
        ):
            result = compare_scans(1, 2)
        assert result["added"] == []
        assert result["removed"] == []
