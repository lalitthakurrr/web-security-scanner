import pytest
from app.db.database import Base, engine, SessionLocal
from app.db import crud

@pytest.fixture(autouse=True)
def setup_database():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

def test_schedule_crud():
    db = SessionLocal()
    # 1. Create schedule
    sched = crud.create_scheduled_scan(db, target_url="http://test.local", interval_hours=12)
    assert sched.id is not None
    assert sched.target_url == "http://test.local"
    assert sched.interval_hours == 12

    # 2. Get list
    schedules = crud.get_all_scheduled_scans(db)
    assert len(schedules) == 1

    # 3. Update run
    updated = crud.update_scheduled_scan_run(db, sched.id)
    assert updated.last_run is not None

    # 4. Delete schedule
    deleted = crud.delete_scheduled_scan(db, sched.id)
    assert deleted is True
    db.close()
