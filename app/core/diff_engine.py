from typing import Dict, Any, List
from app.db.models import Scan, FindingModel

class ScanDiffEngine:
    @staticmethod
    def compare_scans(base_scan: Scan, target_scan: Scan) -> Dict[str, Any]:
        """
        Compares a baseline scan (Scan A) against a newer scan (Scan B).
        Returns comparison details including score delta, fixed findings, new findings, and persistent findings.
        """
        base_score = base_scan.security_score if base_scan.security_score is not None else 100.0
        target_score = target_scan.security_score if target_scan.security_score is not None else 100.0
        score_delta = round(target_score - base_score, 1)

        # Unique key incorporating (rule_id, title, url) to correctly track page-level findings
        base_map = { (f.rule_id, f.title, f.url): f for f in base_scan.findings }
        target_map = { (f.rule_id, f.title, f.url): f for f in target_scan.findings }

        base_keys = set(base_map.keys())
        target_keys = set(target_map.keys())

        fixed_keys = base_keys - target_keys
        new_keys = target_keys - base_keys
        persistent_keys = base_keys & target_keys

        fixed_findings = [base_map[k] for k in fixed_keys]
        new_findings = [target_map[k] for k in new_keys]
        persistent_findings = [target_map[k] for k in persistent_keys]

        return {
            "base_scan_id": base_scan.id,
            "target_scan_id": target_scan.id,
            "base_target_url": base_scan.target_url,
            "target_target_url": target_scan.target_url,
            "base_score": base_score,
            "target_score": target_score,
            "score_delta": score_delta,
            "total_fixed": len(fixed_findings),
            "total_new": len(new_findings),
            "total_persistent": len(persistent_findings),
            "fixed_findings": [
                {
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "severity": f.severity,
                    "category": f.category,
                    "url": f.url,
                    "remediation": getattr(f, "remediation", "") or ""
                } for f in fixed_findings
            ],
            "new_findings": [
                {
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "severity": f.severity,
                    "category": f.category,
                    "url": f.url,
                    "remediation": getattr(f, "remediation", "") or ""
                } for f in new_findings
            ],
            "persistent_findings": [
                {
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "severity": f.severity,
                    "category": f.category,
                    "url": f.url,
                    "remediation": getattr(f, "remediation", "") or ""
                } for f in persistent_findings
            ]
        }
