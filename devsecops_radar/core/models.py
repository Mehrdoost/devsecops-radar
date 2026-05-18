from sqlalchemy import create_engine, Column, Integer, String, DateTime, JSON, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from pydantic import BaseModel, validator
from typing import List, Optional
import datetime
import os

Base = declarative_base()

class FindingSchema(BaseModel):
    tool: str
    id: str
    severity: str
    target: str
    title: str
    description: Optional[str] = ""
    line: Optional[int] = None

    @validator('severity')
    def severity_upper(cls, v):
        return v.upper()

class Scan(Base):
    __tablename__ = 'scans'
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
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

def save_scan_to_db(findings: list):
    validated = [FindingSchema(**f) for f in findings]
    init_db()
    session = SessionLocal()
    try:
        scan = Scan()
        session.add(scan)
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
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()