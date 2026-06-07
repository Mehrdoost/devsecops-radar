from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, event
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from devsecops_radar.core.models import (
    Base,
    Finding,
    FindingSchema,
    Scan,
    engine,
    get_session,
    init_db,
)


# ------------------------------------------------------------
# Pydantic FindingSchema
# ------------------------------------------------------------
class TestFindingSchema:
    def test_valid_data(self):
        data = {
            "tool": "Semgrep",
            "id": "RCE-001",
            "severity": "high",
            "target": "app.py",
            "title": "Remote Code Execution",
            "description": "Found RCE",
            "line": 42,
        }
        finding = FindingSchema(**data)
        assert finding.severity == "HIGH"
        assert finding.tool == "Semgrep"

    def test_severity_converts_to_uppercase(self):
        f = FindingSchema(tool="x", id="1", severity="low", target="t", title="t")
        assert f.severity == "LOW"

    def test_empty_tool_raises(self):
        with pytest.raises(ValidationError):
            FindingSchema(tool="", id="1", severity="LOW", target="t", title="t")

    def test_whitespace_only_raises(self):
        with pytest.raises(ValidationError):
            FindingSchema(tool="   ", id="1", severity="LOW", target="t", title="t")

    def test_optional_description_defaults(self):
        f = FindingSchema(tool="x", id="1", severity="LOW", target="t", title="t")
        assert f.description == ""

    def test_line_none_allowed(self):
        f = FindingSchema(tool="x", id="1", severity="LOW", target="t", title="t", line=None)
        assert f.line is None


# ------------------------------------------------------------
# Model constraints (in‑memory SQLite)
# ------------------------------------------------------------
class TestModelConstraints:
    @pytest.fixture(autouse=True)
    def in_memory_db(self):
        """Create a fresh in‑memory database for each test."""
        self.engine = create_engine("sqlite:///:memory:")
        @event.listens_for(self.engine, "connect")
        def set_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.execute("PRAGMA foreign_keys=ON;")
            cursor.close()
        Base.metadata.create_all(self.engine)
        self.Session = Session(bind=self.engine)
        yield
        self.Session.close()
        self.engine.dispose()

    def test_scan_risk_score_valid(self):
        scan = Scan(risk_score=50)
        self.Session.add(scan)
        self.Session.commit()
        assert scan.risk_score == 50

    def test_scan_risk_score_too_low(self):
        scan = Scan(risk_score=-1)
        self.Session.add(scan)
        with pytest.raises(IntegrityError):
            self.Session.commit()
        self.Session.rollback()

    def test_scan_risk_score_too_high(self):
        scan = Scan(risk_score=101)
        self.Session.add(scan)
        with pytest.raises(IntegrityError):
            self.Session.commit()
        self.Session.rollback()

    def test_finding_severity_valid(self):
        # Create a valid Scan first so that foreign key is satisfied
        scan = Scan(risk_score=50)
        self.Session.add(scan)
        self.Session.flush()  # populates scan.id

        f = Finding(scan_id=scan.id, tool="x", rule_id="R1", severity="HIGH", target="t", title="t")
        self.Session.add(f)
        self.Session.commit()
        assert f.severity == "HIGH"

    def test_finding_severity_invalid(self):
        scan = Scan(risk_score=50)
        self.Session.add(scan)
        self.Session.flush()

        f = Finding(scan_id=scan.id, tool="x", rule_id="R1", severity="INVALID", target="t", title="t")
        self.Session.add(f)
        with pytest.raises(IntegrityError):
            self.Session.commit()
        self.Session.rollback()

    def test_cascade_delete(self):
        """Ensure deleting a scan cascades to its findings."""
        scan = Scan(risk_score=50)
        self.Session.add(scan)
        self.Session.flush()

        f1 = Finding(scan_id=scan.id, tool="x", rule_id="R1", severity="LOW", target="t", title="t")
        f2 = Finding(scan_id=scan.id, tool="y", rule_id="R2", severity="MEDIUM", target="t2", title="t2")
        self.Session.add_all([f1, f2])
        self.Session.commit()
        # Delete scan
        self.Session.delete(scan)
        self.Session.commit()
        # Findings should be gone
        remaining = self.Session.query(Finding).filter(Finding.scan_id == scan.id).all()
        assert len(remaining) == 0


# ------------------------------------------------------------
# init_db
# ------------------------------------------------------------
class TestInitDb:
    def test_calls_create_all(self):
        with patch("devsecops_radar.core.models.Base.metadata.create_all") as mock_create:
            init_db()
            mock_create.assert_called_once_with(engine)


# ------------------------------------------------------------
# get_session context manager
# ------------------------------------------------------------
class TestGetSession:
    def test_commit_on_success(self):
        mock_session = MagicMock()
        # Patch SessionLocal inside the models module to return our mock
        with patch("devsecops_radar.core.models.SessionLocal", return_value=mock_session):
            with get_session():
                pass  # do nothing, commit should be called on exit
            mock_session.commit.assert_called_once()
            mock_session.close.assert_called_once()

    def test_rollback_on_exception(self):
        mock_session = MagicMock()
        with patch("devsecops_radar.core.models.SessionLocal", return_value=mock_session):
            with pytest.raises(ValueError):
                with get_session():
                    raise ValueError("oops")
            mock_session.rollback.assert_called_once()
            mock_session.close.assert_called_once()

    def test_close_called_even_if_commit_fails(self):
        mock_session = MagicMock()
        mock_session.commit.side_effect = RuntimeError("commit error")
        with patch("devsecops_radar.core.models.SessionLocal", return_value=mock_session):
            # The context manager catches the commit exception and calls rollback, then re-raises
            with pytest.raises(RuntimeError):
                with get_session():
                    pass
            mock_session.commit.assert_called_once()
            mock_session.rollback.assert_called_once()
            mock_session.close.assert_called_once()
