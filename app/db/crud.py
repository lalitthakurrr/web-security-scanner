from datetime import datetime, timedelta, timezone
from typing import List, Optional
from sqlalchemy.orm import Session
from app.db.models import Scan, FindingModel, CrawledURLModel, ScheduledScan

def utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)

def create_scan(db: Session, target_url: str) -> Scan:
    scan = Scan(
        target_url=target_url,
        status="pending",
        security_score=100.0,
        total_urls_crawled=0,
        total_findings=0,
        critical_count=0,
        high_count=0,
        medium_count=0,
        low_count=0,
        info_count=0,
        duration_seconds=0.0,
        start_time=utc_now()
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan

def get_scan(db: Session, scan_id: int) -> Optional[Scan]:
    return db.query(Scan).filter(Scan.id == scan_id).first()

def get_all_scans(db: Session, skip: int = 0, limit: int = 100) -> List[Scan]:
    return db.query(Scan).order_by(Scan.id.desc()).offset(skip).limit(limit).all()

def update_scan_status(db: Session, scan_id: int, status: str, error_message: Optional[str] = None) -> Optional[Scan]:
    scan = get_scan(db, scan_id)
    if scan:
        scan.status = status
        if error_message:
            scan.error_message = error_message
        db.commit()
        db.refresh(scan)
    return scan

def complete_scan(
    db: Session,
    scan_id: int,
    security_score: float,
    total_urls: int,
    counts: dict,
    duration: float
) -> Optional[Scan]:
    scan = get_scan(db, scan_id)
    if scan:
        scan.status = "completed"
        scan.security_score = security_score
        scan.total_urls_crawled = total_urls
        scan.total_findings = sum(counts.values())
        scan.critical_count = counts.get("CRITICAL", 0)
        scan.high_count = counts.get("HIGH", 0)
        scan.medium_count = counts.get("MEDIUM", 0)
        scan.low_count = counts.get("LOW", 0)
        scan.info_count = counts.get("INFO", 0)
        scan.end_time = utc_now()
        scan.duration_seconds = duration
        db.commit()
        db.refresh(scan)
    return scan

def add_finding(
    db: Session,
    scan_id: int,
    url: str,
    rule_id: str,
    title: str,
    severity: str,
    category: str,
    description: str,
    evidence: str,
    remediation: str,
    cwe_id: Optional[str] = None
) -> FindingModel:
    finding = FindingModel(
        scan_id=scan_id,
        url=url,
        rule_id=rule_id,
        title=title,
        severity=severity,
        category=category,
        description=description,
        evidence=evidence,
        remediation=remediation,
        cwe_id=cwe_id
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding

def add_crawled_url(
    db: Session,
    scan_id: int,
    url: str,
    status_code: Optional[int],
    content_type: Optional[str],
    response_time_ms: float
) -> CrawledURLModel:
    crawled_url = CrawledURLModel(
        scan_id=scan_id,
        url=url,
        status_code=status_code,
        content_type=content_type,
        response_time_ms=response_time_ms
    )
    db.add(crawled_url)
    db.commit()
    db.refresh(crawled_url)
    return crawled_url

def add_crawled_urls_bulk(db: Session, scan_id: int, pages: list) -> List[CrawledURLModel]:
    objs = [
        CrawledURLModel(
            scan_id=scan_id,
            url=p["url"],
            status_code=p.get("status_code"),
            content_type=p.get("content_type"),
            response_time_ms=p.get("response_time_ms", 0.0)
        )
        for p in pages
    ]
    if objs:
        db.add_all(objs)
        db.commit()
    return objs

def add_findings_bulk(db: Session, scan_id: int, findings: list) -> List[FindingModel]:
    objs = [
        FindingModel(
            scan_id=scan_id,
            url=f.url,
            rule_id=f.rule_id,
            title=f.title,
            severity=f.severity,
            category=f.category,
            description=f.description,
            evidence=f.evidence,
            remediation=f.remediation,
            cwe_id=f.cwe_id
        )
        for f in findings
    ]
    if objs:
        db.add_all(objs)
        db.commit()
    return objs

def delete_scan(db: Session, scan_id: int) -> bool:
    scan = get_scan(db, scan_id)
    if scan:
        db.delete(scan)
        db.commit()
        return True
    return False

# ================= Scheduled Scans CRUD =================

def create_scheduled_scan(
    db: Session,
    target_url: str,
    interval_hours: int = 24,
    max_depth: int = 3,
    max_pages: int = 50
) -> ScheduledScan:
    now = utc_now()
    next_run = now + timedelta(hours=interval_hours)
    sched = ScheduledScan(
        target_url=target_url,
        interval_hours=interval_hours,
        max_depth=max_depth,
        max_pages=max_pages,
        is_active=True,
        next_run=next_run
    )
    db.add(sched)
    db.commit()
    db.refresh(sched)
    return sched

def get_scheduled_scan(db: Session, sched_id: int) -> Optional[ScheduledScan]:
    return db.query(ScheduledScan).filter(ScheduledScan.id == sched_id).first()

def get_all_scheduled_scans(db: Session) -> List[ScheduledScan]:
    return db.query(ScheduledScan).order_by(ScheduledScan.id.desc()).all()

def update_scheduled_scan_run(db: Session, sched_id: int) -> Optional[ScheduledScan]:
    sched = get_scheduled_scan(db, sched_id)
    if sched:
        now = utc_now()
        sched.last_run = now
        sched.next_run = now + timedelta(hours=sched.interval_hours)
        db.commit()
        db.refresh(sched)
    return sched

def delete_scheduled_scan(db: Session, sched_id: int) -> bool:
    sched = get_scheduled_scan(db, sched_id)
    if sched:
        db.delete(sched)
        db.commit()
        return True
    return False
