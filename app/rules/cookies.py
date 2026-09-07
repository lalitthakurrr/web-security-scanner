from typing import List, Dict, Any
from app.rules.base import BaseRule, Finding

class CookieSecurityRule(BaseRule):
    rule_id = "SEC-COOKIE-001"
    title = "Insecure Cookie Flags (Missing Secure / HttpOnly / SameSite)"
    category = "Cookie Security"
    severity = "HIGH"
    cwe_id = "CWE-614"

    def evaluate(self, url: str, response_headers: Dict[str, str], response_body: str, cookies: List[Dict[str, Any]]) -> List[Finding]:
        findings = []
        for cookie in cookies:
            cookie_name = cookie.get("name", "Unknown")
            is_secure = cookie.get("secure", False)
            is_httponly = cookie.get("httponly", False)
            samesite = cookie.get("samesite", "")  # Default empty so missing samesite is properly detected

            issues = []
            if not is_secure and url.startswith("https://"):
                issues.append("Missing 'Secure' flag (cookie sent over plain HTTP)")
            if not is_httponly:
                issues.append("Missing 'HttpOnly' flag (cookie accessible via JavaScript / XSS)")
            if not samesite or str(samesite).lower() in ["none", "false", ""]:
                issues.append("Missing or weak 'SameSite' attribute (potential CSRF risk)")

            if issues:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=f"Insecure Flags on Cookie '{cookie_name}'",
                        severity="HIGH" if not is_httponly else "MEDIUM",
                        category=self.category,
                        description=f"Cookie '{cookie_name}' has security configuration issues: {', '.join(issues)}.",
                        url=url,
                        evidence=f"Cookie: {cookie_name} | Secure: {is_secure} | HttpOnly: {is_httponly} | SameSite: {samesite}",
                        remediation=f"Set 'Secure', 'HttpOnly', and 'SameSite=Lax' (or Strict) flags on cookie '{cookie_name}'.",
                        cwe_id="CWE-1004" if not is_httponly else self.cwe_id
                    )
                )
        return findings
