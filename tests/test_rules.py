import pytest
from app.rules.headers import (
    MissingCSPRule, MissingHSTSRule, MissingXFrameOptionsRule, MissingXContentTypeOptionsRule,
    MissingPermissionsPolicyRule
)
from app.rules.cookies import CookieSecurityRule
from app.rules.info_disclosure import ServerHeaderDisclosureRule, SensitiveCommentsRule
from app.rules.cors import InsecureCORSRule
from app.core.risk_engine import RiskEngine
from app.rules.base import Finding

def test_missing_csp_rule():
    rule = MissingCSPRule()
    # Case 1: Missing CSP header
    findings = rule.evaluate("http://test.local", {}, "<html></html>", [])
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-HDR-001"

    # Case 2: Present CSP header
    findings_ok = rule.evaluate("http://test.local", {"content-security-policy": "default-src 'self'"}, "<html></html>", [])
    assert len(findings_ok) == 0

def test_missing_hsts_rule():
    rule = MissingHSTSRule()
    # Case 1: Plain HTTP (not applicable)
    assert len(rule.evaluate("http://test.local", {}, "", [])) == 0

    # Case 2: HTTPS missing HSTS header
    findings = rule.evaluate("https://test.local", {}, "", [])
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-HDR-002"

def test_cookie_security_rule():
    rule = CookieSecurityRule()
    cookies = [
        {"name": "session", "value": "123", "secure": False, "httponly": False, "samesite": "None"}
    ]
    findings = rule.evaluate("https://test.local", {}, "", cookies)
    assert len(findings) == 1
    assert "Insecure Flags" in findings[0].title


def test_cookie_missing_samesite_key():
    """Cookies with NO samesite key at all should be flagged (not silently skipped)."""
    rule = CookieSecurityRule()
    # Samesite key entirely absent (as parsed from a real Set-Cookie header with no SameSite)
    cookies = [
        {"name": "tracker", "value": "abc", "secure": True, "httponly": True}
        # samesite key is completely missing
    ]
    findings = rule.evaluate("https://test.local", {}, "", cookies)
    assert len(findings) == 1, "Cookie without any SameSite attribute should be flagged"
    assert "SameSite" in findings[0].description


def test_cookie_fully_secure_no_finding():
    """A properly configured cookie should not generate any finding."""
    rule = CookieSecurityRule()
    cookies = [
        {"name": "secure_session", "value": "xyz", "secure": True, "httponly": True, "samesite": "Lax"}
    ]
    findings = rule.evaluate("https://test.local", {}, "", cookies)
    assert len(findings) == 0, "A fully configured secure cookie should generate no finding"

def test_info_disclosure_comments_rule():
    rule = SensitiveCommentsRule()
    body = "<html><body><!-- TODO: Fix admin password secret123 --></body></html>"
    findings = rule.evaluate("http://test.local", {}, body, [])
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-INFO-003"

def test_cors_rule():
    rule = InsecureCORSRule()
    headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true"
    }
    findings = rule.evaluate("http://test.local", headers, "", [])
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"

def test_risk_engine_score():
    findings = [
        Finding("1", "T1", "HIGH", "C", "D", "U", "E", "R"),
        Finding("2", "T2", "MEDIUM", "C", "D", "U", "E", "R"),
        Finding("3", "T3", "LOW", "C", "D", "U", "E", "R")
    ]
    # Deductions: HIGH (-15) + MEDIUM (-8) + LOW (-3) = -26 -> 100 - 26 = 74.0
    score = RiskEngine.calculate_score(findings)
    assert score == 74.0


def test_score_deduplicates_rule_occurrences_using_highest_severity():
    findings = [
        Finding("cookie", "cookie A", "MEDIUM", "C", "D", "/a", "E", "R"),
        Finding("cookie", "cookie B", "HIGH", "C", "D", "/b", "E", "R"),
        *[Finding("header", "missing header", "MEDIUM", "C", "D", f"/{i}", "E", "R") for i in range(50)],
    ]
    assert RiskEngine.calculate_score(findings) == 77.0
    assert RiskEngine.calculate_score(list(reversed(findings))) == 77.0
    assert RiskEngine.count_by_severity(findings)["MEDIUM"] == 51


def test_score_preserves_separate_rule_penalties_and_bounds():
    assert RiskEngine.calculate_score([]) == 100.0
    findings = [Finding(str(i), "issue", "CRITICAL", "C", "D", "/", "E", "R") for i in range(5)]
    assert RiskEngine.calculate_score(findings) == 0.0


def test_missing_x_frame_options_csp_frame_ancestors():
    """CSP with frame-ancestors should suppress X-Frame-Options finding; CSP without it should NOT."""
    rule = MissingXFrameOptionsRule()
    
    # Case 1: No X-Frame-Options, no CSP at all -> should find
    findings = rule.evaluate("http://test.local", {}, "", [])
    assert len(findings) == 1, "Expected finding when both X-Frame-Options and CSP are absent"
    
    # Case 2: No X-Frame-Options, CSP present but NO frame-ancestors -> should STILL find
    findings2 = rule.evaluate(
        "http://test.local",
        {"content-security-policy": "default-src 'self'; script-src 'self'"},
        "", []
    )
    assert len(findings2) == 1, "Expected finding when CSP has no frame-ancestors directive"
    
    # Case 3: CSP with frame-ancestors -> finding suppressed
    findings3 = rule.evaluate(
        "http://test.local",
        {"content-security-policy": "default-src 'self'; frame-ancestors 'none'"},
        "", []
    )
    assert len(findings3) == 0, "Expected no finding when CSP has frame-ancestors directive"
    
    # Case 4: X-Frame-Options present -> finding suppressed
    findings4 = rule.evaluate(
        "http://test.local",
        {"x-frame-options": "DENY"},
        "", []
    )
    assert len(findings4) == 0, "Expected no finding when X-Frame-Options is set"


def test_missing_permissions_policy_rule():
    rule = MissingPermissionsPolicyRule()
    # Case 1: Missing header -> should find
    findings = rule.evaluate("http://test.local", {}, "", [])
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-HDR-006"
    
    # Case 2: Permissions-Policy present -> no finding
    findings2 = rule.evaluate(
        "http://test.local",
        {"permissions-policy": "camera=(), microphone=()"},
        "", []
    )
    assert len(findings2) == 0
    
    # Case 3: Legacy Feature-Policy also accepted
    findings3 = rule.evaluate(
        "http://test.local",
        {"feature-policy": "geolocation 'none'"},
        "", []
    )
    assert len(findings3) == 0
