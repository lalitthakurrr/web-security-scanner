import asyncio
import logging
from datetime import datetime, timezone
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from app.db.database import SessionLocal
from app.db import crud
from app.core.scanner import ScannerEngine

logger = logging.getLogger(__name__)

scheduler = AsyncIOScheduler()

async def check_and_execute_scheduled_scans():
    """
    Periodic job checking for due scheduled scans.
    """
    db = SessionLocal()
    try:
        schedules = crud.get_all_scheduled_scans(db)
        now = datetime.now(timezone.utc).replace(tzinfo=None)

        for sched in schedules:
            if sched.is_active and (sched.next_run is None or sched.next_run <= now):
                logger.info(f"Triggering scheduled scan ID {sched.id} for target {sched.target_url}")
                
                # 1. Create scan entry
                scan = crud.create_scan(db, target_url=sched.target_url)

                # 2. Execute scanner engine
                engine = ScannerEngine(
                    db=db,
                    scan_id=scan.id,
                    max_depth=sched.max_depth,
                    max_pages=sched.max_pages
                )
                await engine.execute_scan(sched.target_url)

                # 3. Update schedule timestamps
                crud.update_scheduled_scan_run(db, sched.id)

    except Exception as exc:
        logger.error(f"Error executing scheduled scan check: {exc}")
    finally:
        db.close()

def start_scheduler():
    if not scheduler.running:
        scheduler.add_job(check_and_execute_scheduled_scans, 'interval', minutes=1, id="check_scheduled_scans", replace_existing=True)
        scheduler.start()
        logger.info("APScheduler background service started successfully.")

def shutdown_scheduler():
    if scheduler.running:
        scheduler.shutdown()
