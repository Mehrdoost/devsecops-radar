from sqlalchemy import create_engine, Column, Integer, String, DateTime, JSON, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
import datetime
import os

Base = declarative_base()

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
    init_db()
    session = SessionLocal()
    scan = Scan()
    session.add(scan)
    for f in findings:
        finding = Finding(
            scan_id=scan.id,
            tool=f.get('tool'),
            severity=f.get('severity'),
            target=f.get('target'),
            title=f.get('title'),
            description=f.get('description'),
            line=f.get('line')
        )
        session.add(finding)
    session.commit()
    session.close()