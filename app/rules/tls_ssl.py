from typing import List, Dict, Any
from urllib.parse import urlparse
from app.rules.base import BaseRule, Finding

class UnencryptedHTTPRule(BaseRule):
    rule_id = "SEC-TLS-001"
    title = "Unencrypted Plaintext HTTP Target"
    category = "Transport Layer Security"
    severity = "HIGH"
    cwe_id = "CWE-319"

    def evaluate(self, url: str, response_headers: Dict[str, str], response_body: str, cookies: List[Dict[str, Any]]) -> List[Finding]:
        parsed = urlparse(url)
        headers_lower = {k.lower(): v for k, v in response_headers.items()}
        redirect_loc = headers_lower.get("location", "")

        # If the URL is plain HTTP and doesn't redirect to HTTPS, flag unencrypted traffic
        if parsed.scheme == "http" and parsed.hostname not in ["localhost", "127.0.0.1"]:
            if redirect_loc.startswith("https://"):
                return []  # Safely redirected HTTP -> HTTPS
            return [
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.severity,
                    category=self.category,
                    description="The target communicates over cleartext HTTP without automatic redirection to HTTPS. Traffic can be eavesdropped, intercepted, or modified via Man-in-the-Middle (MitM) attacks.",
                    url=url,
                    evidence=f"URL scheme is '{parsed.scheme}'. No TLS encryption or automatic HTTPS redirect enabled.",
                    remediation="Migrate the service to HTTPS and configure HTTP-to-HTTPS (301) redirects with valid SSL certificates.",
                    cwe_id=self.cwe_id
                )
            ]
        return []
