from typing import List, Dict, Any
from app.rules.base import BaseRule, Finding

class InsecureCORSRule(BaseRule):
    rule_id = "SEC-CORS-001"
    title = "Insecure CORS Policy (Wildcard Origin with Credentials)"
    category = "Cross-Origin Resource Sharing"
    severity = "HIGH"
    cwe_id = "CWE-942"

    def evaluate(self, url: str, response_headers: Dict[str, str], response_body: str, cookies: List[Dict[str, Any]]) -> List[Finding]:
        headers_lower = {k.lower(): v for k, v in response_headers.items()}
        allow_origin = headers_lower.get("access-control-allow-origin", "")
        allow_credentials = headers_lower.get("access-control-allow-credentials", "").lower()

        if allow_origin == "*" and allow_credentials == "true":
            return [
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.severity,
                    category=self.category,
                    description="The server returns Access-Control-Allow-Origin: * along with Access-Control-Allow-Credentials: true. Browsers block this by default, but misconfigurations can lead to unauthorized data theft.",
                    url=url,
                    evidence=f"Access-Control-Allow-Origin: {allow_origin} | Access-Control-Allow-Credentials: {allow_credentials}",
                    remediation="Specify explicit trusted domain origins in Access-Control-Allow-Origin instead of wildcard '*'.",
                    cwe_id=self.cwe_id
                )
            ]
        elif allow_origin == "*":
            return [
                Finding(
                    rule_id="SEC-CORS-002",
                    title="Wildcard Cross-Origin Access Allowed",
                    severity="LOW",
                    category=self.category,
                    description="The server allows any origin (Access-Control-Allow-Origin: *) to read response data via CORS.",
                    url=url,
                    evidence=f"Access-Control-Allow-Origin: {allow_origin}",
                    remediation="Restrict Access-Control-Allow-Origin to specific trusted origins if sensitive data is served.",
                    cwe_id="CWE-942"
                )
            ]
        return []
