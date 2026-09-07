import logging
from typing import List
import httpx
from app.db.models import Scan, FindingModel

logger = logging.getLogger(__name__)

class NotificationManager:
    @staticmethod
    def send_webhook_alert(webhook_url: str, scan: Scan, findings: List[FindingModel]) -> bool:
        """
        Sends formatted JSON payload to a Webhook URL (Slack/Discord/Teams/Custom HTTP Endpoint).
        """
        if not webhook_url:
            return False

        critical_findings = [f for f in findings if f.severity.upper() == "CRITICAL"]
        high_findings = [f for f in findings if f.severity.upper() == "HIGH"]

        payload = {
            "text": f"🚨 *SECURITY AUDIT ALERT*: `{scan.target_url}`",
            "attachments": [
                {
                    "color": "#DC2626" if scan.critical_count > 0 else "#EA580C",
                    "fields": [
                        {"title": "Scan ID", "value": str(scan.id), "short": True},
                        {"title": "Security Score", "value": f"{scan.security_score:.1f} / 100", "short": True},
                        {"title": "Total Findings", "value": str(scan.total_findings), "short": True},
                        {"title": "Critical", "value": str(scan.critical_count), "short": True},
                        {"title": "High", "value": str(scan.high_count), "short": True},
                        {"title": "Medium", "value": str(scan.medium_count), "short": True}
                    ],
                    "text": "\n".join([f"• *[{f.severity}]* {f.title} (`{f.url}`)" for f in (critical_findings + high_findings)[:5]])
                }
            ]
        }

        try:
            with httpx.Client(timeout=5.0) as client:
                res = client.post(webhook_url, json=payload)
                return res.status_code in [200, 201, 204]
        except Exception as exc:
            logger.warning(f"Webhook alert delivery failed for {webhook_url}: {exc}")
            return False
