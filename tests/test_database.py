from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest

from devsecops_radar.core.database import (
    _truncate_string,
    compare_scans,
    get_all_scans,
    get_findings_paginated,
    get_scan_by_id,
    init_db,
    logger,
    save_scan,
)


# ----------------------------------------------------------------------
# _truncate_string
# ----------------------------------------------------------------------
class TestTruncateString:
    def test_short(self):
        assert _truncate_string("hello", 10) == "hello"

    def test_exact_length(self):
        assert _truncate_string("1234567890", 10) == "1234567890"

    def test_long(self):
        assert _truncate_string("1234567890abc", 10) == "1234567890"

    def test_none(self):
        assert _truncate_string(None) is None


# ----------------------------------------------------------------------
# init_db
# ----------------------------------------------------------------------
class TestInitDb:
    def test_success(self):
        mock_sess = MagicMock()
        mock_db_factory = MagicMock(return_value=mock_sess)
        with patch("devsecops_radar.core.database.models_init_db") as mock_models_init, \
             patch("devsecops_radar.core.database.db_session", mock_db_factory), \
             patch("devsecops_radar.core.database.engine") as mock_engine, \
             patch.object(logger, "info") as mock_info:
            mock_engine.url = "sqlite:///test.db"
            init_db()
            mock_models_init.assert_called_once()
            mock_sess.execute.assert_called_once()
            mock_sess.close.assert_called_once()
            mock_info.assert_called_with("Database tables and constraints verified.")

    def test_exception_logged(self):
        mock_sess = MagicMock()
        mock_sess.execute.side_effect = Exception("db error")
        mock_db_factory = MagicMock(return_value=mock_sess)
        with patch("devsecops_radar.core.database.models_init_db"), \
             patch("devsecops_radar.core.database.db_session", mock_db_factory), \
             patch("devsecops_radar.core.database.engine") as mock_engine, \
             patch.object(logger, "warning") as mock_warn:
            mock_engine.url = "sqlite:///test.db"
            init_db()
            mock_warn.assert_called_once()
            assert "Could not enforce foreign keys" in mock_warn.call_args[0][0]


# ----------------------------------------------------------------------
# save_scan
# ----------------------------------------------------------------------
class TestSaveScan:
    @pytest.fixture
    def mock_session(self):
        return MagicMock()

    @pytest.fixture
    def sample_findings(self):
        return [
            {"id": "R1", "tool": "Semgrep", "severity": "HIGH", "target": "app.py",
             "title": "SQLi", "description": "desc"},
            {"id": "R2", "severity": "LOW"},
        ]

    def test_success(self, mock_session, sample_findings):
        ai_summary = {"risk_score": 85, "hardware_profile": "t2.micro", "execution_time": 12.5}
        fixed_now = datetime(2025, 1, 1, 12, 0, 0, tzinfo=UTC)
        mock_db_factory = MagicMock(return_value=mock_session)

        with patch("devsecops_radar.core.database.init_db") as mock_init, \
             patch("devsecops_radar.core.database.db_session", mock_db_factory), \
             patch("devsecops_radar.core.database.datetime") as mock_datetime, \
             patch.object(logger, "success") as mock_success:
            mock_datetime.now.return_value = fixed_now
            save_scan(sample_findings, ai_summary)

            mock_init.assert_called_once()
            # Verify Scan was added
            calls = mock_session.add.call_args_list
            assert len(calls) == 3  # 1 Scan + 2 Findings
            scan_obj = calls[0][0][0]
            assert scan_obj.risk_score == 85
            assert scan_obj.hardware_profile == "t2.micro"
            assert scan_obj.execution_time == 12.5
            assert scan_obj.timestamp == fixed_now
            mock_session.commit.assert_called_once()
            mock_success.assert_called_once()

    def test_no_ai_summary(self, mock_session, sample_findings):
        mock_db_factory = MagicMock(return_value=mock_session)
        with patch("devsecops_radar.core.database.init_db"), \
             patch("devsecops_radar.core.database.db_session", mock_db_factory), \
             patch("devsecops_radar.core.database.datetime"):
            save_scan(sample_findings, None)
            scan_obj = mock_session.add.call_args_list[0][0][0]
            assert scan_obj.risk_score is None
            assert scan_obj.hardware_profile is None
            assert scan_obj.execution_time is None

    def test_rollback_on_exception(self, mock_session, sample_findings):
        mock_session.commit.side_effect = RuntimeError("commit failed")
        mock_db_factory = MagicMock(return_value=mock_session)
        with patch("devsecops_radar.core.database.init_db"), \
             patch("devsecops_radar.core.database.db_session", mock_db_factory), \
             patch.object(logger, "error") as mock_error:
            with pytest.raises(RuntimeError):
                save_scan(sample_findings)
            mock_session.rollback.assert_called_once()
            mock_error.assert_called_once()


# ----------------------------------------------------------------------
# get_all_scans
# ----------------------------------------------------------------------
class TestGetAllScans:
    def test_returns_scans(self):
        mock_sess = MagicMock()
        scan1 = MagicMock(id=1, timestamp=datetime(2025, 1, 1, 12, tzinfo=UTC),
                          risk_score=50, hardware_profile="x")
        scan2 = MagicMock(id=2, timestamp=None, risk_score=None, hardware_profile=None)
        mock_sess.query().order_by().all.return_value = [scan1, scan2]

        mock_db_factory = MagicMock(return_value=mock_sess)
        with patch("devsecops_radar.core.database.db_session", mock_db_factory):
            result = get_all_scans()
            assert len(result) == 2
            assert result[0]["scan_id"] == 1
            assert result[0]["timestamp"] == "2025-01-01T12:00:00+00:00"
            assert result[0]["risk_score"] == 50
            assert result[1]["timestamp"] is None
            mock_sess.close.assert_called_once()


# ----------------------------------------------------------------------
# get_scan_by_id
# ----------------------------------------------------------------------
class TestGetScanById:
    def test_existing(self):
        mock_sess = MagicMock()
        finding = MagicMock(id=1, tool="X", rule_id="R1", severity="HIGH",
                            target="f.py", title="T", description="D")
        scan = MagicMock(id=10, timestamp=datetime(2025, 1, 1, 12, tzinfo=UTC),
                         risk_score=90, hardware_profile="p", execution_time=5.0,
                         findings=[finding])
        mock_sess.query().filter().first.return_value = scan

        mock_db_factory = MagicMock(return_value=mock_sess)
        with patch("devsecops_radar.core.database.db_session", mock_db_factory):
            result = get_scan_by_id(10)
            assert result is not None
            assert result["scan_id"] == 10
            assert len(result["findings"]) == 1
            assert result["findings"][0]["tool"] == "X"
            mock_sess.close.assert_called_once()

    def test_not_found(self):
        mock_sess = MagicMock()
        mock_sess.query().filter().first.return_value = None

        mock_db_factory = MagicMock(return_value=mock_sess)
        with patch("devsecops_radar.core.database.db_session", mock_db_factory):
            result = get_scan_by_id(999)
            assert result is None
            mock_sess.close.assert_called_once()


# ----------------------------------------------------------------------
# get_findings_paginated
# ----------------------------------------------------------------------
class TestGetFindingsPaginated:
    def test_defaults(self):
        mock_sess = MagicMock()
        # Simulate count query
        mock_sess.query().count.return_value = 100
        finding = MagicMock(scan_id=1, tool="X", rule_id="R", severity="H",
                            target="t", title="T")
        mock_sess.query().order_by().offset().limit().all.return_value = [finding]

        mock_db_factory = MagicMock(return_value=mock_sess)
        with patch("devsecops_radar.core.database.db_session", mock_db_factory):
            result = get_findings_paginated()
            assert result["total"] == 100
            assert result["page"] == 1
            assert result["per_page"] == 50
            assert len(result["data"]) == 1
            mock_sess.close.assert_called_once()

    def test_custom_page(self):
        mock_sess = MagicMock()
        mock_sess.query().count.return_value = 5
        mock_db_factory = MagicMock(return_value=mock_sess)
        with patch("devsecops_radar.core.database.db_session", mock_db_factory):
            result = get_findings_paginated(page=2, per_page=20)
            assert result["page"] == 2
            assert result["per_page"] == 20

    def test_per_page_capped(self):
        mock_sess = MagicMock()
        mock_db_factory = MagicMock(return_value=mock_sess)
        with patch("devsecops_radar.core.database.db_session", mock_db_factory):
            result = get_findings_paginated(per_page=200)
            assert result["per_page"] == 100  # capped

    def test_page_minimum(self):
        mock_sess = MagicMock()
        mock_db_factory = MagicMock(return_value=mock_sess)
        with patch("devsecops_radar.core.database.db_session", mock_db_factory):
            result = get_findings_paginated(page=0)
            assert result["page"] == 1


# ----------------------------------------------------------------------
# compare_scans
# ----------------------------------------------------------------------
class TestCompareScans:
    def test_both_present(self):
        s1 = {"scan_id": 1, "findings": [
            {"tool": "A", "id": "R1", "target": "f1.py", "severity": "HIGH"},
            {"tool": "B", "id": "R2", "target": "f2.py", "severity": "LOW"},
        ]}
        s2 = {"scan_id": 2, "findings": [
            {"tool": "B", "id": "R2", "target": "f2.py", "severity": "LOW"},
            {"tool": "C", "id": "R3", "target": "f3.py", "severity": "MEDIUM"},
        ]}
        with patch("devsecops_radar.core.database.get_scan_by_id", side_effect=[s1, s2]):
            result = compare_scans(1, 2)
            assert result["scan_id1"] == 1
            assert len(result["added"]) == 1
            assert result["added"][0]["id"] == "R3"
            assert len(result["removed"]) == 1
            assert result["removed"][0]["id"] == "R1"

    def test_one_missing(self):
        with patch("devsecops_radar.core.database.get_scan_by_id",
                   side_effect=[{"scan_id": 1, "findings": []}, None]):
            result = compare_scans(1, 2)
            assert result == {"error": "One or both scans not found"}

    def test_both_missing(self):
        with patch("devsecops_radar.core.database.get_scan_by_id", return_value=None):
            result = compare_scans(1, 2)
            assert result == {"error": "One or both scans not found"}
