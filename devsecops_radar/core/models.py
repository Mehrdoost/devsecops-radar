# devsecops_radar/core/models.py
"""
SQLAlchemy ORM models with mandatory sanitization and optional
transparent database encryption (sqlcipher3).
"""

from __future__ import annotations

import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from loguru import logger
from pydantic import BaseModel, field_validator
from sqlalchemy import (
    CheckConstraint,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    create_engine,
    event,
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

Base = declarative_base()

# ---------------------------------------------------------------------------
# Sanitization helpers
# ---------------------------------------------------------------------------
_HTML_TAG_RE = re.compile(r"<[^>]*>", re.IGNORECASE)
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _sanitize_html_and_control(text: str) -> str:
    """Remove HTML tags and ASCII control characters (except newline, tab)."""
    if not isinstance(text, str):
        return ""
    text = _HTML_TAG_RE.sub("", text)
    text = _CONTROL_CHARS_RE.sub("", text)
    return text.strip()


def _safe_path_segment(path: str) -> str:
    """Allow only safe characters in a path; reject traversal sequences.
    Repeatedly URL‑decode until stable to defeat multiple‑encoding attacks."""
    if not path or not path.strip():
        raise ValueError("Target path cannot be empty.")

    decoded = path
    # Loop until no more percent‑encoded characters remain
    while "%" in decoded:
        try:
            new_decoded = __import__('urllib.parse', fromlist=['unquote']).unquote(decoded)
        except Exception:
            break
        if new_decoded == decoded:
            break
        decoded = new_decoded

    # Reject traversal sequences
    if ".." in decoded or decoded.startswith("~"):
        raise ValueError("Target contains unsafe path characters.")
    # Reject null bytes and other control chars
    if re.search(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', decoded):
        raise ValueError("Target contains control characters.")
    # Reject multiple consecutive slashes (often used in bypass attempts)
    if "//" in decoded or "\\\\" in decoded:
        raise ValueError("Target contains suspicious path separators.")

    # Return sanitized form (fully decoded and stripped)
    return decoded.strip()


# ---------------------------------------------------------------------------
# Pydantic schema for input validation
# ---------------------------------------------------------------------------
class FindingSchema(BaseModel):
    """Schema for input validation (used by adapter.py and database.py)."""
    tool: str
    id: str
    severity: str
    target: str
    title: str
    description: str | None = ""
    line: int | None = None
    dynamic_risk_score: float = -1.0
    rule_id: str | None = None

    @field_validator("severity")
    @classmethod
    def _severity_upper(cls, v: str) -> str:
        allowed = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
        upper = v.upper()
        if upper not in allowed:
            raise ValueError(f"Severity must be one of {allowed}")
        return upper

    @field_validator("tool", "id", "title")
    @classmethod
    def _no_empty_and_sanitize(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Field cannot be empty")
        return _sanitize_html_and_control(v)

    @field_validator("target")
    @classmethod
    def _sanitize_target(cls, v: str) -> str:
        return _safe_path_segment(v)

    @field_validator("description")
    @classmethod
    def _sanitize_description(cls, v: str | None) -> str:
        if v is None:
            return ""
        return _sanitize_html_and_control(v)


# ---------------------------------------------------------------------------
# SQLAlchemy ORM models
# ---------------------------------------------------------------------------
class Scan(Base):           # type: ignore[valid-type, misc]
    __tablename__ = "scans"
    __table_args__ = (
        CheckConstraint(
            "risk_score >= 0 AND risk_score <= 100", name="ck_risk_score_range"
        ),
        Index("ix_scans_timestamp", "timestamp"),
    )

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(UTC))
    risk_score = Column(Float, nullable=True)
    hardware_profile = Column(String, nullable=True)
    execution_time = Column(Float, nullable=True)
    ai_summary_json = Column(Text, nullable=True)
    findings = relationship(
        "Finding", back_populates="scan", cascade="all, delete-orphan"
    )


class Finding(Base):            # type: ignore[valid-type, misc]
    __tablename__ = "findings"
    __table_args__ = (
        CheckConstraint(
            "severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')",
            name="ck_valid_severity",
        ),
    )

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), index=True)
    tool = Column(String, nullable=False)
    rule_id = Column(String, index=True, nullable=False, default="UNKNOWN")
    severity = Column(String, index=True, nullable=False)
    target = Column(String, nullable=False)
    title = Column(String, nullable=False)
    description = Column(String, default="")
    line = Column(Integer, nullable=True)
    dynamic_risk_score = Column(Float, nullable=True, default=-1.0)
    scan = relationship("Scan", back_populates="findings")


# ---------------------------------------------------------------------------
# Unified Database Engine (with optional encryption)
# ---------------------------------------------------------------------------
_DB_DIR = Path.cwd() / ".sentinel"
_DB_DIR.mkdir(parents=True, exist_ok=True)

DB_URL = os.environ.get("DATABASE_URL", f"sqlite:///{_DB_DIR / 'pipeline_sentinel.db'}")

engine_kwargs: dict[str, Any] = {
    "pool_pre_ping": True,
    "pool_recycle": 3600,
}

if "sqlite" in DB_URL:
    engine_kwargs["connect_args"] = {"check_same_thread": False}

    use_encryption = os.environ.get("DB_ENCRYPTION_KEY") is not None

    if use_encryption:
        try:
            import sqlcipher3  # type: ignore[import-untyped] # noqa: F401  # noqa: F401
        except ImportError:
            logger.warning(
                "sqlcipher3 not installed; running with unencrypted database. "
                "Install it with: pip install pysqlcipher3"
            )
            use_encryption = False

    engine = create_engine(DB_URL, **engine_kwargs)

    if use_encryption:
        @event.listens_for(engine, "connect")
        def _set_sqlcipher_pragma(dbapi_connection, connection_record):
            key = os.environ["DB_ENCRYPTION_KEY"]
            cursor = dbapi_connection.cursor()
            # Safe parameterized PRAGMA
            cursor.execute("PRAGMA key = ?", (key,))
            cursor.execute("PRAGMA cipher_page_size = 4096")
            cursor.execute("PRAGMA kdf_iter = 256000")
            cursor.execute("PRAGMA foreign_keys = ON")
            cursor.close()
    else:
        @event.listens_for(engine, "connect")
        def _set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys = ON")
            cursor.execute("PRAGMA journal_mode = WAL")
            cursor.close()
else:
    engine_kwargs.update({
        "pool_size": 5,
        "max_overflow": 10,
        "pool_timeout": 30,
    })
    engine = create_engine(DB_URL, **engine_kwargs)

SessionLocal = sessionmaker(bind=engine)


def init_db():
    """Create all tables. Idempotent."""
    Base.metadata.create_all(engine)
