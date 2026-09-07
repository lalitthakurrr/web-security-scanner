import asyncio
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.db.database import Base, engine, SessionLocal
from app.db import crud
from app.core.diff_engine import ScanDiffEngine
from app.core.notifications import NotificationManager

def test_bonus_pipeline():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    print("=== Testing Bonus Features Pipeline ===")

    # 1. Create Scan 1 (Baseline)
    scan1 = crud.create_scan(db, target_url="http://127.0.0.1:8888")
    crud.add_finding(db, scan1.id, "http://127.0.0.1:8888", "SEC-HDR-001", "Missing CSP", "MEDIUM", "Headers", "Desc", "Ev", "Rem")
    crud.add_finding(db, scan1.id, "http://127.0.0.1:8888", "SEC-COOKIE-001", "Insecure Cookie", "HIGH", "Cookies", "Desc", "Ev", "Rem")
    crud.complete_scan(db, scan1.id, security_score=77.0, total_urls=1, counts={"MEDIUM": 1, "HIGH": 1}, duration=1.0)
    print(f"Created Baseline Scan #{scan1.id} (Score: {scan1.security_score})")

    # 2. Create Scan 2 (Target - Fixed CSP, introduced Exposed .env)
    scan2 = crud.create_scan(db, target_url="http://127.0.0.1:8888")
    crud.add_finding(db, scan2.id, "http://127.0.0.1:8888", "SEC-COOKIE-001", "Insecure Cookie", "HIGH", "Cookies", "Desc", "Ev", "Rem")
    crud.add_finding(db, scan2.id, "http://127.0.0.1:8888/.env", "SEC-EXP-ENV", "Exposed .env", "CRITICAL", "Exposure", "Desc", "Ev", "Rem")
    crud.complete_scan(db, scan2.id, security_score=60.0, total_urls=2, counts={"HIGH": 1, "CRITICAL": 1}, duration=1.2)
    print(f"Created Target Scan #{scan2.id} (Score: {scan2.security_score})")

    # 3. Test Scan Diff Engine
    diff = ScanDiffEngine.compare_scans(scan1, scan2)
    print("\n--- Scan Diff Engine Result ---")
    print(f"Score Delta: {diff['score_delta']}")
    print(f"Fixed Vulnerabilities ({diff['total_fixed']}): {[f['title'] for f in diff['fixed_findings']]}")
    print(f"New Vulnerabilities ({diff['total_new']}): {[f['title'] for f in diff['new_findings']]}")
    print(f"Persistent Vulnerabilities ({diff['total_persistent']}): {[f['title'] for f in diff['persistent_findings']]}")

    assert diff["score_delta"] == -17.0
    assert diff["total_fixed"] == 1
    assert diff["total_new"] == 1

    # 4. Test Recurring Schedule Creation
    sched = crud.create_scheduled_scan(db, target_url="http://127.0.0.1:8888", interval_hours=24)
    print(f"\nCreated Schedule #{sched.id} (Interval: {sched.interval_hours}h, Next Run: {sched.next_run})")

    print("\nALL BONUS FEATURES VERIFIED SUCCESSFULLY!")

if __name__ == "__main__":
    test_bonus_pipeline()
