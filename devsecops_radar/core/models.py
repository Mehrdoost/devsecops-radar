# devsecops_radar/core/models.py
import os
from datetime import UTC, datetime
from typing import Any

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
    create_engine,
    event,
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

Base = declarative_base()


class FindingSchema(BaseModel):
    """Schema for input validation (used by adapter.py and database.py)."""
    tool: str
    id: str
    severity: str
    target: str
    title: str
    description: str | None = ""
    line: int | None = None
    dynamic_risk_score: float = -1.0        # -1.0 means "not yet computed"
    rule_id: str | None = None               # populated by adapter / database layer

    @field_validator("severity")
    @classmethod
    def severity_upper(cls, v: str) -> str:
        allowed = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
        upper = v.upper()
        if upper not in allowed:
            raise ValueError(f"Severity must be one of {allowed}")
        return upper

    @field_validator("tool", "id", "target", "title")
    @classmethod
    def no_empty_strings(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Field cannot be empty")
        return v.strip()

    @field_validator("target")
    @classmethod
    def no_path_traversal(cls, v: str) -> str:
        # Block path traversal and suspicious characters
        # Decode URL-encoded sequences first, then check
        import re
        decoded = v
        # Repeatedly decode %XX until stable (handles double-encoding)
        for _ in range(3):
            try:
                new_decoded = __import__('urllib.parse', fromlist=['unquote']).unquote(decoded)
                if new_decoded == decoded:
                    break
                decoded = new_decoded
            except Exception:
                break
        # Block obvious traversals
        if ".." in decoded or decoded.startswith("~"):
            raise ValueError("Target contains unsafe path characters")
        # Block null bytes and control characters
        if re.search(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', decoded):
            raise ValueError("Target contains control characters")
        # Block multiple consecutive slashes (often used to bypass filters)
        if "//" in decoded or "\\\\" in decoded:
            raise ValueError("Target contains suspicious path separators")
        return v  # Return original, not decoded – let downstream handle encoding


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


# ==============================
# Unified Database Engine
# ==============================
DB_URL = os.environ.get("DATABASE_URL", "sqlite:///pipeline_sentinel.db")

engine_kwargs: dict[str, Any] = {
    "pool_pre_ping": True,
    "pool_recycle": 3600,
}

if "sqlite" in DB_URL:
    engine_kwargs["connect_args"] = {"check_same_thread": False}
    engine = create_engine(DB_URL, **engine_kwargs)

    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA foreign_keys=ON;")
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
