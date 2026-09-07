import re
from typing import List, Dict, Any
from bs4 import BeautifulSoup, Comment
from app.rules.base import BaseRule, Finding

class ServerHeaderDisclosureRule(BaseRule):
    rule_id = "SEC-INFO-001"
    title = "Server Software Version Disclosure"
    category = "Information Disclosure"
    severity = "LOW"
    cwe_id = "CWE-200"

    def evaluate(self, url: str, response_headers: Dict[str, str], response_body: str, cookies: List[Dict[str, Any]]) -> List[Finding]:
        findings = []
        headers_lower = {k.lower(): v for k, v in response_headers.items()}
        
        server = headers_lower.get("server", "")
        if server and any(char.isdigit() for char in server):
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title="Server Version Information Disclosure in 'Server' Header",
                    severity=self.severity,
                    category=self.category,
                    description=f"The 'Server' header exposes detailed software and version information: '{server}'. Attackers can leverage specific version details to target known CVEs.",
                    url=url,
                    evidence=f"Server: {server}",
                    remediation="Configure web server to obscure or omit detailed version tokens from the Server header.",
                    cwe_id=self.cwe_id
                )
            )

        powered_by = headers_lower.get("x-powered-by", "")
        if powered_by:
            findings.append(
                Finding(
                    rule_id="SEC-INFO-002",
                    title="Technology Framework Disclosure in 'X-Powered-By' Header",
                    severity="LOW",
                    category=self.category,
                    description=f"The 'X-Powered-By' header exposes backend technology details: '{powered_by}'.",
                    url=url,
                    evidence=f"X-Powered-By: {powered_by}",
                    remediation="Remove the X-Powered-By response header from web application server configurations.",
                    cwe_id="CWE-200"
                )
            )

        return findings

class SensitiveCommentsRule(BaseRule):
    rule_id = "SEC-INFO-003"
    title = "Sensitive Information Leakage in HTML Comments"
    category = "Information Disclosure"
    severity = "MEDIUM"
    cwe_id = "CWE-615"

    SENSITIVE_KEYWORDS = [
        r"todo", r"fixme", r"password", r"passwd", r"secret", r"apikey",
        r"admin", r"auth_token", r"database", r"sql", r"private_key", r"internal"
    ]

    def evaluate(self, url: str, response_headers: Dict[str, str], response_body: str, cookies: List[Dict[str, Any]]) -> List[Finding]:
        if not response_body:
            return []

        findings = []
        soup = BeautifulSoup(response_body, "html.parser")
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))

        pattern = re.compile(r"\b(" + "|".join(self.SENSITIVE_KEYWORDS) + r")\b", re.IGNORECASE)

        for comment in comments:
            clean_comment = comment.strip()
            if pattern.search(clean_comment):
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=self.severity,
                        category=self.category,
                        description="HTML comments in the page source contain potentially sensitive developer notes, credentials, or internal references.",
                        url=url,
                        evidence=f"HTML Comment: <!-- {clean_comment[:150]} -->",
                        remediation="Remove sensitive developer comments, credentials, and internal notes before deploying to production.",
                        cwe_id=self.cwe_id
                    )
                )
                break  # Cap to 1 finding per page for comments
        return findings
