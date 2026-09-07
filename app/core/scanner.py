import time
import logging
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.http_client import SecurityHTTPClient
from app.core.crawler import AsyncCrawler
from app.core.risk_engine import RiskEngine
from app.core.notifications import NotificationManager
from app.rules.base import BaseRule, Finding
from app.rules.headers import (
    MissingCSPRule, MissingHSTSRule, MissingXFrameOptionsRule,
    MissingXContentTypeOptionsRule, MissingReferrerPolicyRule, MissingPermissionsPolicyRule
)
from app.rules.cookies import CookieSecurityRule
from app.rules.tls_ssl import UnencryptedHTTPRule
from app.rules.info_disclosure import ServerHeaderDisclosureRule, SensitiveCommentsRule
from app.rules.cors import InsecureCORSRule
import app.db.crud as crud

logger = logging.getLogger(__name__)

class ScannerEngine:
    def __init__(self, db: Session, scan_id: int, max_depth: int = 3, max_pages: int = 50, webhook_url: Optional[str] = None):
        self.db = db
        self.scan_id = scan_id
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.webhook_url = webhook_url
        self.client = SecurityHTTPClient()
        
        # Load rule instances
        self.rules: List[BaseRule] = [
            MissingCSPRule(),
            MissingHSTSRule(),
            MissingXFrameOptionsRule(),
            MissingXContentTypeOptionsRule(),
            MissingReferrerPolicyRule(),
            MissingPermissionsPolicyRule(),
            CookieSecurityRule(),
            UnencryptedHTTPRule(),
            ServerHeaderDisclosureRule(),
            SensitiveCommentsRule(),
            InsecureCORSRule()
        ]

        # Common sensitive endpoints to audit
        self.sensitive_paths = [
            (".env", "Exposed Environment File (.env)", "CRITICAL", "CWE-552", "Exposed .env configuration file containing sensitive secrets/database credentials."),
            (".git/HEAD", "Exposed Git Repository Metadata (.git/HEAD)", "HIGH", "CWE-538", "Exposed .git directory allowing full source code extraction."),
            ("robots.txt", "Robots.txt Reconnaissance File", "INFO", "CWE-200", "Public robots.txt revealing internal administrative directory structure."),
            ("backup.sql", "Exposed Database Backup File", "CRITICAL", "CWE-530", "Exposed database dump file containing raw data."),
            ("wp-config.php", "Exposed WordPress Configuration File", "CRITICAL", "CWE-552", "Exposed WordPress database configuration file."),
            ("phpinfo.php", "Exposed PHP Info Page", "HIGH", "CWE-200", "phpinfo() page exposes server configuration, PHP version, loaded extensions and environment variables."),
            ("server-status", "Exposed Apache Server Status Page", "MEDIUM", "CWE-200", "Apache mod_status exposes live request logs and server resource usage."),
            ("web.config", "Exposed IIS Web Configuration File", "CRITICAL", "CWE-552", "web.config file may contain database connection strings, encryption keys, or application secrets."),
            ("config.php", "Exposed PHP Configuration File", "HIGH", "CWE-552", "config.php file may contain plaintext database credentials or API keys."),
        ]

    async def execute_scan(self, target_url: str):
        """
        Executes complete security scanning pipeline.
        """
        start_time = time.time()
        crud.update_scan_status(self.db, self.scan_id, "crawling")

        all_findings: List[Finding] = []
        crawled_pages: List[Dict[str, Any]] = []

        try:
            # 1. Execute Async Crawl
            crawler = AsyncCrawler(
                target_url=target_url,
                max_depth=self.max_depth,
                max_pages=self.max_pages,
                http_client=self.client
            )
            crawled_pages = await crawler.crawl()

            # Record Crawled URLs in DB in a single bulk transaction
            crud.add_crawled_urls_bulk(self.db, self.scan_id, crawled_pages)

            crud.update_scan_status(self.db, self.scan_id, "scanning")

            # 2. Evaluate Rules on Crawled Pages
            visited_rule_keys = set()

            for page in crawled_pages:
                url = page["url"]
                headers = page.get("headers", {})
                body = page.get("body", "")
                cookies = page.get("cookies", [])

                for rule in self.rules:
                    rule_findings = rule.evaluate(url, headers, body, cookies)
                    for f in rule_findings:
                        key = (f.rule_id, f.url)
                        if key not in visited_rule_keys:
                            visited_rule_keys.add(key)
                            all_findings.append(f)

            # 3. Audit Sensitive Path Exposures on Host Root (use only scheme+netloc)
            from urllib.parse import urlparse as _urlparse
            parsed_target = _urlparse(target_url)
            base_root_url = f"{parsed_target.scheme}://{parsed_target.netloc}"

            for path, title, sev, cwe, desc in self.sensitive_paths:
                found, resp = await self.client.check_sensitive_endpoint(base_root_url, path)
                if found and resp:
                    finding = Finding(
                        rule_id=f"SEC-EXP-{path.replace('/', '_').replace('.', '').upper()}",
                        title=title,
                        severity=sev,
                        category="Information Exposure",
                        description=desc,
                        url=str(resp.url),
                        evidence=f"HTTP 200 OK returned for endpoint '{path}'. Content preview: {resp.text[:100]}",
                        remediation=f"Restrict public web access to '{path}' in web server configuration.",
                        cwe_id=cwe
                    )
                    key = (finding.rule_id, finding.url)
                    if key not in visited_rule_keys:
                        visited_rule_keys.add(key)
                        all_findings.append(finding)

            # 4. Save Findings to DB in a single bulk transaction
            saved_findings = crud.add_findings_bulk(self.db, self.scan_id, all_findings)

            # 5. Compute Risk Score & Summary Stats
            score = RiskEngine.calculate_score(all_findings)
            counts = RiskEngine.count_by_severity(all_findings)
            duration = round(time.time() - start_time, 2)

            scan = crud.complete_scan(
                db=self.db,
                scan_id=self.scan_id,
                security_score=score,
                total_urls=len(crawled_pages),
                counts=counts,
                duration=duration
            )

            # 6. Trigger Notification Alert if configured
            if self.webhook_url and scan:
                NotificationManager.send_webhook_alert(self.webhook_url, scan, saved_findings)

        except Exception as exc:
            logger.error(f"Scan failed for scan_id={self.scan_id}: {exc}", exc_info=True)
            crud.update_scan_status(self.db, self.scan_id, "failed", error_message=str(exc))
