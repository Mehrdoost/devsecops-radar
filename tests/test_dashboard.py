# tests/test_database.py (mypy‑clean)
"""Integration tests for the database persistence layer.

Covers scan saving, AI summary updates, scan listing, paginated findings,
scan‑by‑id retrieval, and the compare_scans function.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from sqlalchemy import MetaData

import devsecops_radar.core.database as db_mod
from devsecops_radar.core.database import (
    compare_scans,
    get_all_scans,
    get_findings_paginated,
    get_scan_by_id,
    init_db,
    save_scan,
    update_scan_ai_summary,
)
from devsecops_radar.core.models import SessionLocal


@pytest.fixture(autouse=True)
def _init_database() -> None:
    """Drop every table and re‑create them to guarantee test isolation."""
    session = SessionLocal()
    try:
        engine = session.get_bind()
        metadata = MetaData()
        metadata.reflect(bind=engine)
        metadata.drop_all(bind=engine)
    finally:
        session.close()

    db_mod._tables_initialized = False
    init_db()


def _sample_finding(tool: str = "trivy", rule_id: str = "CVE-0001") -> dict[str, Any]:
    return {
        "tool": tool,
        "target": "app/server.py",
        "id": rule_id,
        "severity": "HIGH",
        "title": "Test Finding",
        "description": "A synthetic vulnerability",
    }


class TestSaveScan:
    def test_save_single_finding(self) -> None:
        scan_id = save_scan([_sample_finding()])
        assert isinstance(scan_id, int)
        assert scan_id > 0

    def test_save_multiple_findings(self) -> None:
        findings = [
            _sample_finding(rule_id="CVE-0001"),
            _sample_finding(rule_id="CVE-0002", tool="semgrep"),
        ]
        scan_id = save_scan(findings)
        assert scan_id is not None

    def test_save_with_ai_summary(self) -> None:
        ai = {"executive_summary": "All good", "risk_score": 12.5}
        scan_id = save_scan([_sample_finding()], ai_summary=ai)
        assert scan_id is not None
        scan = get_scan_by_id(scan_id)
        assert scan is not None
        assert scan["risk_score"] == 12.5
        assert scan["ai_summary_json"] == json.dumps(ai)

    def test_save_invalid_finding_skipped(self, caplog: pytest.LogCaptureFixture) -> None:
        invalid = {"tool": "x", "id": "no-severity"}
        scan_id = save_scan([invalid, _sample_finding()])
        assert scan_id is not None
        scan = get_scan_by_id(scan_id)
        assert scan is not None
        assert len(scan["findings"]) == 1

    def test_save_empty_findings(self) -> None:
        scan_id = save_scan([])
        assert scan_id is not None
        scan = get_scan_by_id(scan_id)
        assert scan is not None
        assert scan["findings"] == []


class TestUpdateAiSummary:
    def test_update_existing_scan(self) -> None:
        scan_id = save_scan([_sample_finding()])
        assert scan_id is not None
        result = update_scan_ai_summary(scan_id, {"risk_score": 99.9})
        assert result is True
        scan = get_scan_by_id(scan_id)
        assert scan is not None
        assert scan["risk_score"] == 99.9

    def test_update_nonexistent_scan(self) -> None:
        result = update_scan_ai_summary(99999, {"risk_score": 10})
        assert result is False


class TestGetAllScans:
    def test_empty(self) -> None:
        scans = get_all_scans()
        assert scans == []

    def test_multiple_scans_returned_desc(self) -> None:
        sid1 = save_scan([_sample_finding(rule_id="A")])
        sid2 = save_scan([_sample_finding(rule_id="B")])
        assert sid1 is not None and sid2 is not None
        scans = get_all_scans()
        assert len(scans) == 2
        assert scans[0]["scan_id"] > scans[1]["scan_id"]


class TestGetScanById:
    def test_existing_scan(self) -> None:
        scan_id = save_scan([_sample_finding()])
        assert scan_id is not None
        scan = get_scan_by_id(scan_id)
        assert scan is not None
        assert scan["scan_id"] == scan_id

    def test_missing_scan(self) -> None:
        assert get_scan_by_id(12345) is None


class TestGetFindingsPaginated:
    def test_pagination_basics(self) -> None:
        for i in range(5):
            save_scan([_sample_finding(rule_id=f"CVE-{i:04d}")])
        page = get_findings_paginated(page=1, per_page=2)
        assert page["total"] == 5
        assert len(page["data"]) == 2

    def test_page_out_of_range(self) -> None:
        save_scan([_sample_finding()])
        page = get_findings_paginated(page=10, per_page=10)
        assert page["data"] == []


class TestCompareScans:
    def test_both_existing(self) -> None:
        s1 = save_scan([_sample_finding(rule_id="R1", tool="trivy")])
        s2 = save_scan([_sample_finding(rule_id="R2", tool="semgrep")])
        assert s1 is not None and s2 is not None
        diff = compare_scans(s1, s2)
        assert diff["scan_id1"] == s1
        assert diff["scan_id2"] == s2
        assert len(diff["added"]) == 1
        assert len(diff["removed"]) == 1
        assert diff["added"][0]["id"] == "R2"
        assert diff["removed"][0]["id"] == "R1"

    def test_one_missing_scan(self) -> None:
        s1 = save_scan([_sample_finding()])
        assert s1 is not None
        diff = compare_scans(s1, 99999)
        assert diff["added"] == []
        assert len(diff["removed"]) == 1
        assert diff["removed"][0]["id"] == "CVE-0001"

    def test_identical_findings(self) -> None:
        f = _sample_finding(rule_id="ID")
        s1 = save_scan([f])
        s2 = save_scan([f])
        assert s1 is not None and s2 is not None
        diff = compare_scans(s1, s2)
        assert diff["added"] == []
        assert diff["removed"] == []
