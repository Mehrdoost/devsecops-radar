"""Tests for database models and schema validation."""

import os

import pytest
from pydantic import ValidationError
from sqlalchemy import inspect, text
from sqlalchemy.orm import sessionmaker

# Set a safe in‑memory database before importing the module
os.environ["DATABASE_URL"] = "sqlite:///:memory:"

# Now import the module under test
from devsecops_radar.core import models
from devsecops_radar.core.models import (
    Base,
    Finding,
    FindingSchema,
    Scan,
    init_db,
)


@pytest.fixture(autouse=True)
def clean_tables():
    """Drop and recreate tables for each test to isolate state."""
    Base.metadata.drop_all(models.engine)
    Base.metadata.create_all(models.engine)
    yield
    Base.metadata.drop_all(models.engine)


# ---------------------------------------------------------------------------
# Tests for FindingSchema (Pydantic)
# ---------------------------------------------------------------------------
class TestFindingSchema:
    def test_valid_input(self):
        data = {
            "tool": "semgrep",
            "id": "rule-1",
            "severity": "high",
            "target": "app.py",
            "title": "SQL Injection",
            "description": "Found",
            "line": 42,
        }
        obj = FindingSchema(**data)
        assert obj.tool == "semgrep"
        assert obj.severity == "HIGH"

    def test_severity_upper(self):
        obj = FindingSchema(
            tool="t", id="i", severity="low", target="t", title="t"
        )
        assert obj.severity == "LOW"

    def test_empty_tool_raises(self):
        with pytest.raises(ValidationError, match="cannot be empty"):
            FindingSchema(
                tool="", id="i", severity="LOW", target="t", title="t"
            )

    def test_whitespace_only_title_raises(self):
        with pytest.raises(ValidationError, match="cannot be empty"):
            FindingSchema(
                tool="t", id="i", severity="LOW", target="t", title="   "
            )

    def test_missing_required_field(self):
        with pytest.raises(ValidationError):
            FindingSchema(tool="t", severity="LOW", target="t", title="t")

    def test_defaults(self):
        obj = FindingSchema(
            tool="t", id="i", severity="LOW", target="t", title="t"
        )
        assert obj.description == ""
        assert obj.line is None


# ---------------------------------------------------------------------------
# Tests for SQLAlchemy Scan and Finding models
# ---------------------------------------------------------------------------
class TestModels:
    def test_create_scan_and_finding(self, clean_tables):
        session = sessionmaker(bind=models.engine)()
        scan = Scan(risk_score=85, hardware_profile="x86")
        session.add(scan)
        session.commit()

        assert scan.id is not None
        assert scan.timestamp is not None

        f = Finding(
            scan_id=scan.id,
            tool="trivy",
            rule_id="CVE-2024-001",
            severity="HIGH",
            target="lib.so",
            title="Buffer Overflow",
            description="RCE",
        )
        session.add(f)
        session.commit()

        assert f.id is not None
        assert f.severity == "HIGH"

    def test_risk_score_constraint(self, clean_tables):
        session = sessionmaker(bind=models.engine)()
        with pytest.raises(Exception):
            scan = Scan(risk_score=150)
            session.add(scan)
            session.commit()

    def test_valid_severity_constraint(self, clean_tables):
        session = sessionmaker(bind=models.engine)()
        scan = Scan()
        session.add(scan)
        session.commit()

        with pytest.raises(Exception):
            f = Finding(
                scan_id=scan.id,
                tool="t",
                rule_id="r",
                severity="INVALID",
                target="t",
                title="t",
            )
            session.add(f)
            session.commit()

    def test_relationship(self, clean_tables):
        session = sessionmaker(bind=models.engine)()
        scan = Scan()
        session.add(scan)
        session.flush()
        f = Finding(
            scan_id=scan.id,
            tool="t",
            rule_id="r",
            severity="LOW",
            target="t",
            title="t",
        )
        session.add(f)
        session.commit()

        assert scan.findings[0] == f
        assert f.scan == scan


# ---------------------------------------------------------------------------
# Tests for init_db
# ---------------------------------------------------------------------------
class TestInitDb:
    def test_creates_tables(self):
        Base.metadata.drop_all(models.engine)
        insp = inspect(models.engine)
        assert not insp.has_table("scans")
        init_db()
        insp = inspect(models.engine)
        assert insp.has_table("scans")
        assert insp.has_table("findings")

    def test_idempotent(self):
        init_db()
        init_db()


# ---------------------------------------------------------------------------
# Tests for the SQLite event listener (pragmas)
# ---------------------------------------------------------------------------
class TestSQLiteEventListener:
    def test_sqlite_pragma_foreign_keys(self, clean_tables):
        session = sessionmaker(bind=models.engine)()
        result = session.execute(text("PRAGMA foreign_keys")).fetchone()
        assert result[0] == 1  # ON
