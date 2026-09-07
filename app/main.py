import os
import re
import asyncio
import traceback
from contextlib import asynccontextmanager
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
import httpx
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, status, Query, Request
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.database import get_db, init_db, SessionLocal
from app.db import crud
from app.db.models import Scan
from app.schemas.scan import (
    ScanCreateRequest, ScanResponse, ScanDetailResponse,
    ScheduleCreateRequest, ScheduleResponse, NotificationTestRequest
)
from app.core.scanner import ScannerEngine
from app.core.diff_engine import ScanDiffEngine
from app.core.scheduler import start_scheduler, shutdown_scheduler
from app.core.notifications import NotificationManager
from app.reports.pdf_generator import generate_pdf_report

# Ensure Database Tables Exist immediately
init_db()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Ensure DB tables exist & start background scheduler
    init_db()
    
    # Reset stuck scans to failed
    db = SessionLocal()
    try:
        stuck_scans = db.query(Scan).filter(Scan.status.in_(["pending", "crawling", "scanning"])).all()
        for scan in stuck_scans:
            scan.status = "failed"
            scan.error_message = "Scan interrupted by server shutdown or restart."
        if stuck_scans:
            db.commit()
    finally:
        db.close()

    start_scheduler()
    yield
    # Shutdown: Stop scheduler
    shutdown_scheduler()

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Production-grade Web Application Security Audit & Scanner API",
    lifespan=lifespan
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def validate_target_url(raw: str) -> str:
    """
    Validates and normalises the target URL.
    1. Must not be empty.
    2. Must have a valid hostname with a dot (or be localhost/IP).
    3. Must pass a live HTTP reachability probe (5s timeout HEAD request).
    Raises HTTPException(422) on any failure. Never raises 500.
    """
    try:
        target = raw.strip()
        if not target:
            raise HTTPException(status_code=422, detail="Target URL cannot be empty.")

        # Prepend scheme if missing
        if not target.startswith(("http://", "https://")):
            target = "http://" + target

        parsed = urlparse(target)
        hostname = parsed.hostname  # None if malformed

        # 1. Must have a parseable hostname
        if not hostname:
            raise HTTPException(
                status_code=422,
                detail=f"'{raw}' is not a valid URL — no hostname found. "
                       f"Enter a full domain like https://example.com"
            )

        # 2. Hostname format check (must contain dot unless localhost/IP)
        local_hosts = {"localhost", "127.0.0.1", "::1"}
        if hostname not in local_hosts:
            if "." not in hostname:
                raise HTTPException(
                    status_code=422,
                    detail=f"'{hostname}' is not a valid domain name. "
                           f"Domains must contain a dot (e.g. google.com, upgrad.com). "
                           f"Random words are not valid scan targets."
                )
            hostname_re = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$")
            if not hostname_re.match(hostname):
                raise HTTPException(
                    status_code=422,
                    detail=f"'{hostname}' contains illegal characters. "
                           f"Only letters, digits, hyphens, and dots are allowed."
                )

        # 3. Live reachability probe — quick HEAD request with tight timeout
        if hostname not in local_hosts:
            try:
                with httpx.Client(
                    timeout=httpx.Timeout(connect=5.0, read=5.0, write=5.0, pool=5.0),
                    follow_redirects=True,
                    verify=False
                ) as probe:
                    probe_resp = probe.head(target, headers={"User-Agent": "Mozilla/5.0 SecurityScanner/probe"})
                    # Any HTTP response (even 4xx) means the host is reachable
            except httpx.ConnectError:
                raise HTTPException(
                    status_code=422,
                    detail=f"Cannot connect to '{hostname}': connection refused or host unreachable. "
                           f"Make sure the URL is correct and the server is running."
                )
            except httpx.ConnectTimeout:
                raise HTTPException(
                    status_code=422,
                    detail=f"Connection to '{hostname}' timed out after 5 seconds. "
                           f"The server may be down or blocking requests."
                )
            except httpx.RequestError as e:
                raise HTTPException(
                    status_code=422,
                    detail=f"Cannot reach '{hostname}': {type(e).__name__}. "
                           f"Please verify the URL is correct and accessible."
                )

        return target

    except HTTPException:
        raise  # Re-raise our own clean errors
    except Exception as e:
        # Catch-all: never let unexpected errors become a 500
        raise HTTPException(
            status_code=422,
            detail=f"Could not validate URL '{raw}': {str(e)}"
        )


async def run_scanner_background(scan_id: int, target_url: str, max_depth: int, max_pages: int, webhook_url: Optional[str] = None):
    """
    Background worker task running the scanner engine.
    """
    db = SessionLocal()
    try:
        engine = ScannerEngine(db=db, scan_id=scan_id, max_depth=max_depth, max_pages=max_pages, webhook_url=webhook_url)
        await engine.execute_scan(target_url)
    finally:
        db.close()

@app.get("/api/health", tags=["Health"])
def health_check():
    return {
        "status": "healthy",
        "engine": settings.PROJECT_NAME,
        "version": settings.VERSION
    }

@app.post("/api/scans", response_model=ScanResponse, status_code=status.HTTP_202_ACCEPTED, tags=["Scans"])
def create_scan(request: ScanCreateRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    """
    Initiate a new asynchronous security scan against the target URL.
    Validates the URL format and performs a DNS lookup before queuing the scan.
    """
    target = validate_target_url(request.target_url)

    try:
        scan = crud.create_scan(db, target_url=target)
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=f"Database or backend error while creating scan: {type(e).__name__} - {str(e)}"
        )

    # Schedule background execution
    background_tasks.add_task(
        run_scanner_background,
        scan_id=scan.id,
        target_url=target,
        max_depth=request.max_depth if request.max_depth is not None else settings.DEFAULT_MAX_DEPTH,
        max_pages=request.max_pages if request.max_pages is not None else settings.DEFAULT_MAX_PAGES,
        webhook_url=request.webhook_url
    )

    return scan

@app.get("/api/scans", response_model=List[ScanResponse], tags=["Scans"])
def list_scans(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    """
    Retrieve history of all security scans.
    """
    return crud.get_all_scans(db, skip=skip, limit=limit)

@app.get("/api/scans/diff", tags=["Analytics"])
def compare_scans(base_scan_id: int = Query(...), target_scan_id: int = Query(...), db: Session = Depends(get_db)):
    """
    Compare two historical scans to calculate security score delta, fixed findings, and new findings.
    """
    base_scan = crud.get_scan(db, base_scan_id)
    target_scan = crud.get_scan(db, target_scan_id)

    if not base_scan or not target_scan:
        raise HTTPException(status_code=404, detail="One or both scan IDs were not found.")

    return ScanDiffEngine.compare_scans(base_scan, target_scan)

@app.get("/api/scans/{scan_id}", response_model=ScanDetailResponse, tags=["Scans"])
def get_scan_detail(scan_id: int, db: Session = Depends(get_db)):
    """
    Retrieve full details, crawled URLs, and findings for a specific scan.
    """
    scan = crud.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan ID {scan_id} not found.")
    return scan

@app.delete("/api/scans/{scan_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Scans"])
def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    """
    Delete a scan record and all associated findings.
    """
    success = crud.delete_scan(db, scan_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Scan ID {scan_id} not found.")

@app.get("/api/scans/{scan_id}/report", tags=["Reports"])
def download_pdf_report(scan_id: int, db: Session = Depends(get_db)):
    """
    Generate and download executive PDF assessment report.
    """
    scan = crud.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan ID {scan_id} not found.")

    if scan.status != "completed":
        raise HTTPException(status_code=400, detail=f"Cannot generate report for scan in '{scan.status}' status.")

    filepath = generate_pdf_report(scan, scan.findings)
    filename = os.path.basename(filepath)

    return FileResponse(
        filepath,
        media_type="application/pdf",
        filename=filename
    )

# ================= Scheduled Scans Endpoints =================

@app.post("/api/schedules", response_model=ScheduleResponse, status_code=status.HTTP_201_CREATED, tags=["Schedules"])
def create_schedule(request: ScheduleCreateRequest, db: Session = Depends(get_db)):
    """
    Create a new automated recurring scan schedule.
    Validates the URL before scheduling.
    """
    target = validate_target_url(request.target_url)

    return crud.create_scheduled_scan(
        db,
        target_url=target,
        interval_hours=request.interval_hours if request.interval_hours is not None else 24,
        max_depth=request.max_depth if request.max_depth is not None else settings.DEFAULT_MAX_DEPTH,
        max_pages=request.max_pages if request.max_pages is not None else settings.DEFAULT_MAX_PAGES
    )

@app.get("/api/schedules", response_model=List[ScheduleResponse], tags=["Schedules"])
def list_schedules(db: Session = Depends(get_db)):
    """
    List all active and configured recurring scan schedules.
    """
    return crud.get_all_scheduled_scans(db)

@app.delete("/api/schedules/{sched_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Schedules"])
def delete_schedule(sched_id: int, db: Session = Depends(get_db)):
    """
    Cancel and delete a scheduled scan.
    """
    success = crud.delete_scheduled_scan(db, sched_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Schedule ID {sched_id} not found.")

@app.post("/api/notifications/test", tags=["Notifications"])
def test_webhook_notification(request: NotificationTestRequest):
    """
    Test a webhook alert endpoint.
    """
    dummy_scan = Scan(id=999, target_url="http://test.local", security_score=45.0, critical_count=1, high_count=2, medium_count=3, total_findings=6)
    dummy_findings = []
    success = NotificationManager.send_webhook_alert(request.webhook_url, dummy_scan, dummy_findings)
    return {"success": success, "webhook_url": request.webhook_url}

@app.get("/api/stats", tags=["Analytics"])
def get_aggregated_stats(db: Session = Depends(get_db)):
    """
    Returns aggregated metrics across all historical security scans.
    """
    scans = crud.get_all_scans(db, skip=0, limit=1000)
    total_scans = len(scans)
    if total_scans == 0:
        return {
            "total_scans": 0,
            "avg_security_score": 100.0,
            "total_findings": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0
        }

    completed_scans = [s for s in scans if s.status == "completed"]
    avg_score = sum(s.security_score for s in completed_scans) / len(completed_scans) if completed_scans else 100.0

    return {
        "total_scans": total_scans,
        "avg_security_score": round(avg_score, 1),
        "total_findings": sum(s.total_findings for s in scans),
        "critical_count": sum(s.critical_count for s in scans),
        "high_count": sum(s.high_count for s in scans),
        "medium_count": sum(s.medium_count for s in scans),
        "low_count": sum(s.low_count for s in scans),
        "info_count": sum(s.info_count for s in scans)
    }
