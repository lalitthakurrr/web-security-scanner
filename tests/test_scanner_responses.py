from unittest.mock import AsyncMock

import pytest

from app.core.scanner import ScannerEngine


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [None, 403, 502])
async def test_scan_fails_without_a_successful_response(monkeypatch, status):
    from app.core import scanner

    monkeypatch.setattr(scanner.AsyncCrawler, "crawl", AsyncMock(return_value=[{
        "url": "https://example.test", "status_code": status,
        "headers": {}, "body": "", "cookies": [],
    }]))
    statuses = []
    monkeypatch.setattr(scanner.crud, "update_scan_status", lambda db, scan_id, state, **kwargs: statuses.append((state, kwargs)))
    engine = ScannerEngine(db=None, scan_id=1)
    await engine.execute_scan("https://example.test")
    assert statuses[-1][0] == "failed"
    assert "No successful page responses" in statuses[-1][1]["error_message"]
