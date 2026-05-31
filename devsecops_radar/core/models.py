import os
from contextlib import contextmanager
from datetime import UTC, datetime

from pydantic import BaseModel, field_validator
from sqlalchemy import JSON, Column, DateTime, ForeignKey, Integer, String, create_engine
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

Base = declarative_base()

class FindingSchema(BaseModel):
    tool: str
    id: str
    severity: str
    target: str
    title: str
    description: str | None = ""
    line: int | None = None

    @field_validator('severity')
    @classmethod
    def severity_upper(cls, v: str) -> str:
        return v.upper()

class Scan(Base):
    __tablename__ = 'scans'
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(UTC))
    findings_json = Column(JSON)
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")

class Finding(Base):
    __tablename__ = 'findings'
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id'), index=True)
    tool = Column(String)
    severity = Column(String, index=True)
    target = Column(String)
    title = Column(String)
    description = Column(String)
    line = Column(Integer)
    scan = relationship("Scan", back_populates="findings")

DB_URL = os.environ.get("DATABASE_URL", "sqlite:///scan_history.db")
engine = create_engine(DB_URL)
SessionLocal = sessionmaker(bind=engine)

def init_db():
    Base.metadata.create_all(engine)

@contextmanager
def get_session():
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

def save_scan_to_db(findings: list) -> None:
    validated = [FindingSchema(**f) for f in findings]
    init_db()
    with get_session() as session:
        scan = Scan()
        scan.findings_json = [f.model_dump() for f in validated]
        session.add(scan)
        session.flush()
        for f in validated:
            finding = Finding(
                scan_id=scan.id,
                tool=f.tool,
                severity=f.severity,
                target=f.target,
                title=f.title,
                description=f.description,
                line=f.line
            )
            session.add(finding)
