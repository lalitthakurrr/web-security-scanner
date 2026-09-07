import pytest
from app.core.diff_engine import ScanDiffEngine

class DummyScan:
    def __init__(self, scan_id, target_url, score, findings):
        self.id = scan_id
        self.target_url = target_url
        self.security_score = score
        self.findings = findings

class DummyFinding:
    def __init__(self, rule_id, title, severity, category, url, remediation="Fix it"):
        self.rule_id = rule_id
        self.title = title
        self.severity = severity
        self.category = category
        self.url = url
        self.remediation = remediation

def test_scan_diff_engine():
    # Scan A (Baseline)
    f1 = DummyFinding("SEC-HDR-001", "Missing CSP", "MEDIUM", "Headers", "http://test.local")
    f2 = DummyFinding("SEC-COOKIE-001", "Insecure Cookie", "HIGH", "Cookies", "http://test.local")
    scan_a = DummyScan(1, "http://test.local", 77.0, [f1, f2])

    # Scan B (Newer scan - CSP fixed, but exposed file added)
    f2_b = DummyFinding("SEC-COOKIE-001", "Insecure Cookie", "HIGH", "Cookies", "http://test.local")
    f3 = DummyFinding("SEC-EXP-ENV", "Exposed .env", "CRITICAL", "Exposure", "http://test.local/.env")
    scan_b = DummyScan(2, "http://test.local", 60.0, [f2_b, f3])

    diff = ScanDiffEngine.compare_scans(scan_a, scan_b)

    assert diff["score_delta"] == -17.0
    assert diff["total_fixed"] == 1
    assert diff["fixed_findings"][0]["rule_id"] == "SEC-HDR-001"
    assert diff["total_new"] == 1
    assert diff["new_findings"][0]["rule_id"] == "SEC-EXP-ENV"
    assert diff["total_persistent"] == 1
