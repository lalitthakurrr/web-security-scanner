import pytest
from app.core.notifications import NotificationManager

class DummyScan:
    def __init__(self):
        self.id = 1
        self.target_url = "http://test.local"
        self.security_score = 45.0
        self.total_findings = 3
        self.critical_count = 1
        self.high_count = 1
        self.medium_count = 1

def test_webhook_invalid_url():
    scan = DummyScan()
    # Empty or invalid webhook URL should return False gracefully
    assert NotificationManager.send_webhook_alert("", scan, []) is False
