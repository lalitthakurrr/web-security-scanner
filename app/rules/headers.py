from typing import List, Dict, Any
from app.rules.base import BaseRule, Finding

class MissingCSPRule(BaseRule):
    rule_id = "SEC-HDR-001"
    title = "Missing Content-Security-Policy (CSP) Header"
    category = "Security Headers"
    severity = "MEDIUM"
    cwe_id = "CWE-693"

    def evaluate(self, url: str, response_headers: Dict[str, str], response_body: str, cookies: List[Dict[str, Any]]) -> List[Finding]:
        headers_lower = {k.lower(): v for k, v in response_headers.items()}
        if "content-security-policy" not in headers_lower:
            return [
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.severity,
                    category=self.category,
                    description="The server did not return a Content-Security-Policy (CSP) header. CSP protects against Cross-Site Scripting (XSS) and data injection attacks.",
                    url=url,
                    evidence="Content-Security-Policy header is missing in response.",
                    remediation="Configure a robust Content-Security-Policy header (e.g., default-src 'self').",
                    cwe_id=self.cwe_id
                )
            ]
        return []

class MissingHSTSRule(BaseRule):
    rule_id = "SEC-HDR-002"
    title = "Missing Strict-Transport-Security (HSTS) Header"
    category = "Security Headers"
    severity = "MEDIUM"
    cwe_id = "CWE-523"

    def evaluate(self, url: str, response_headers: Dict[str, str], response_body: str, cookies: List[Dict[str, Any]]) -> List[Finding]:
        if not url.startswith("https://"):
            return []  # HSTS is only applicable over HTTPS
        headers_lower = {k.lower(): v for k, v in response_headers.items()}
        if "strict-transport-security" not in headers_lower:
            return [
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.severity,
                    category=self.category,
                    description="HTTP Strict Transport Security (HSTS) instructs browsers to only connect via HTTPS, protecting against SSL Strip attacks.",
                    url=url,
                    evidence="Strict-Transport-Security header missing on HTTPS endpoint.",
                    remediation="Add Strict-Transport-Security: max-age=31536000; includeSubDomains to your response headers.",
                    cwe_id=self.cwe_id
                )
            ]
        return []

class MissingXFrameOptionsRule(BaseRule):
    rule_id = "SEC-HDR-003"
    title = "Missing Clickjacking Protection (X-Frame-Options)"
    category = "Security Headers"
    severity = "LOW"
    cwe_id = "CWE-1021"

    def evaluate(self, url: str, response_headers: Dict[str, str], response_body: str, cookies: List[Dict[str, Any]]) -> List[Finding]:
        headers_lower = {k.lower(): v for k, v in response_headers.items()}
        has_x_frame = "x-frame-options" in headers_lower
        # CSP frame-ancestors directive is the modern equivalent of X-Frame-Options
        csp_value = headers_lower.get("content-security-policy", "")
        has_frame_ancestors = "frame-ancestors" in csp_value.lower()
        if not has_x_frame and not has_frame_ancestors:
            return [
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.severity,
                    category=self.category,
                    description="Neither X-Frame-Options nor CSP frame-ancestors directive was found. The site may be vulnerable to Clickjacking attacks.",
                    url=url,
                    evidence="X-Frame-Options header missing in response.",
                    remediation="Set X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN.",
                    cwe_id=self.cwe_id
                )
            ]
        return []

class MissingXContentTypeOptionsRule(BaseRule):
    rule_id = "SEC-HDR-004"
    title = "Missing X-Content-Type-Options Header"
    category = "Security Headers"
    severity = "LOW"
    cwe_id = "CWE-116"

    def evaluate(self, url: str, response_headers: Dict[str, str], response_body: str, cookies: List[Dict[str, Any]]) -> List[Finding]:
        headers_lower = {k.lower(): v for k, v in response_headers.items()}
        if headers_lower.get("x-content-type-options", "").lower() != "nosniff":
            return [
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.severity,
                    category=self.category,
                    description="X-Content-Type-Options prevents browsers from MIME-sniffing a response away from the declared content-type.",
                    url=url,
                    evidence=f"X-Content-Type-Options is '{headers_lower.get('x-content-type-options', 'missing')}'.",
                    remediation="Set X-Content-Type-Options: nosniff in server responses.",
                    cwe_id=self.cwe_id
                )
            ]
        return []

class MissingReferrerPolicyRule(BaseRule):
    rule_id = "SEC-HDR-005"
    title = "Missing or Weak Referrer-Policy Header"
    category = "Security Headers"
    severity = "LOW"
    cwe_id = "CWE-200"

    def evaluate(self, url: str, response_headers: Dict[str, str], response_body: str, cookies: List[Dict[str, Any]]) -> List[Finding]:
        headers_lower = {k.lower(): v for k, v in response_headers.items()}
        policy = headers_lower.get("referrer-policy", "")
        if not policy:
            return [
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.severity,
                    category=self.category,
                    description="Referrer-Policy header is missing. Browsers may leak sensitive URL path information in HTTP Referer headers.",
                    url=url,
                    evidence="Referrer-Policy header is missing.",
                    remediation="Set Referrer-Policy: strict-origin-when-cross-origin or no-referrer.",
                    cwe_id=self.cwe_id
                )
            ]
        return []


class MissingPermissionsPolicyRule(BaseRule):
    rule_id = "SEC-HDR-006"
    title = "Missing Permissions-Policy Header"
    category = "Security Headers"
    severity = "LOW"
    cwe_id = "CWE-693"

    def evaluate(self, url: str, response_headers: Dict[str, str], response_body: str, cookies: List[Dict[str, Any]]) -> List[Finding]:
        headers_lower = {k.lower(): v for k, v in response_headers.items()}
        # Check both legacy Feature-Policy and modern Permissions-Policy
        if "permissions-policy" not in headers_lower and "feature-policy" not in headers_lower:
            return [
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.severity,
                    category=self.category,
                    description="Permissions-Policy (formerly Feature-Policy) header is missing. Without this header, malicious scripts may access powerful browser APIs (camera, microphone, geolocation, payment) if injected via XSS.",
                    url=url,
                    evidence="Permissions-Policy header absent in response.",
                    remediation="Set Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=() to restrict unused browser feature access.",
                    cwe_id=self.cwe_id
                )
            ]
        return []
