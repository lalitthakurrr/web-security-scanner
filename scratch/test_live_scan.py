import asyncio
import sys
import os
import threading
import time
import uvicorn

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tests.mock_target_app import app as mock_app
from app.db.database import Base, engine, SessionLocal
from app.db import crud
from app.core.scanner import ScannerEngine
from app.reports.pdf_generator import generate_pdf_report

def start_mock_server():
    uvicorn.run(mock_app, host="127.0.0.1", port=8889, log_level="warning")

async def run_test():
    # 1. Start mock server in thread
    server_thread = threading.Thread(target=start_mock_server, daemon=True)
    server_thread.start()
    time.sleep(1.5)  # Wait for server to bind

    # 2. Init DB
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    target_url = "http://127.0.0.1:8889"
    scan = crud.create_scan(db, target_url=target_url)
    print(f"Created scan ID: {scan.id} for target {target_url}")

    # 3. Execute Scan Engine
    scanner = ScannerEngine(db=db, scan_id=scan.id, max_depth=2, max_pages=15)
    await scanner.execute_scan(target_url)

    # 4. Fetch results
    scan = crud.get_scan(db, scan.id)
    print(f"Scan Status: {scan.status}")
    print(f"Security Score: {scan.security_score}")
    print(f"Total Crawled Pages: {scan.total_urls_crawled}")
    print(f"Total Findings: {scan.total_findings}")

    for idx, f in enumerate(scan.findings, 1):
        print(f"  [{f.severity}] #{idx} {f.title} ({f.url}) - {f.rule_id}")

    # 5. Test PDF report generation
    pdf_file = generate_pdf_report(scan, scan.findings)
    print(f"PDF Report generated at: {pdf_file}")
    assert os.path.exists(pdf_file)
    print("LIVE END-TO-END SCAN VERIFICATION SUCCESSFUL!")

if __name__ == "__main__":
    asyncio.run(run_test())
