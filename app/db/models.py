from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Text, Boolean
from sqlalchemy.orm import relationship
from app.db.database import Base

def utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    target_url = Column(String, index=True, nullable=False)
    status = Column(String, default="pending")  # pending, crawling, scanning, completed, failed
    security_score = Column(Float, default=100.0)
    total_urls_crawled = Column(Integer, default=0)
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    start_time = Column(DateTime, default=utc_now)
    end_time = Column(DateTime, nullable=True)
    duration_seconds = Column(Float, default=0.0)
    error_message = Column(Text, nullable=True)

    findings = relationship("FindingModel", back_populates="scan", cascade="all, delete-orphan")
    crawled_urls = relationship("CrawledURLModel", back_populates="scan", cascade="all, delete-orphan")


class FindingModel(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    url = Column(String, nullable=False)
    rule_id = Column(String, nullable=False)
    title = Column(String, nullable=False)
    severity = Column(String, nullable=False)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    evidence = Column(Text, nullable=True)
    remediation = Column(Text, nullable=False)
    cwe_id = Column(String, nullable=True)

    scan = relationship("Scan", back_populates="findings")


class CrawledURLModel(Base):
    __tablename__ = "crawled_urls"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    url = Column(String, nullable=False)
    status_code = Column(Integer, nullable=True)
    content_type = Column(String, nullable=True)
    response_time_ms = Column(Float, default=0.0)

    scan = relationship("Scan", back_populates="crawled_urls")


class ScheduledScan(Base):
    __tablename__ = "scheduled_scans"

    id = Column(Integer, primary_key=True, index=True)
    target_url = Column(String, nullable=False)
    interval_hours = Column(Integer, default=24)
    max_depth = Column(Integer, default=3)
    max_pages = Column(Integer, default=50)
    is_active = Column(Boolean, default=True)
    last_run = Column(DateTime, nullable=True)
    next_run = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utc_now)
