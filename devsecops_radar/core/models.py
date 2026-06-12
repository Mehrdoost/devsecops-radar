import os
from datetime import UTC, datetime

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
    """Schema for input validation (used by adapter.py)."""
    tool: str
    id: str
    severity: str
    target: str
    title: str
    description: str | None = ""
    line: int | None = None

    @field_validator("severity")
    @classmethod
    def severity_upper(cls, v: str) -> str:
        return v.upper()

    @field_validator("tool", "id", "target", "title")
    @classmethod
    def no_empty_strings(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Field cannot be empty")
        return v.strip()


class Scan(Base):
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
    execution_time = Column(Float, nullable=True)   # Stored as seconds
    # Redundant findings_json column removed
    findings = relationship(
        "Finding", back_populates="scan", cascade="all, delete-orphan"
    )


class Finding(Base):
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
    rule_id = Column(String, index=True, nullable=False)
    severity = Column(String, index=True, nullable=False)
    target = Column(String, nullable=False)
    title = Column(String, nullable=False)
    description = Column(String, default="")
    line = Column(Integer, nullable=True)
    scan = relationship("Scan", back_populates="findings")


# ==============================
# Unified Database Engine
# ==============================
DB_URL = os.environ.get("DATABASE_URL", "sqlite:///pipeline_sentinel.db")

engine_kwargs = {
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
