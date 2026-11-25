from typing import List, Dict
from app.rules.base import Finding

class RiskEngine:
    # Heuristic deduction points by severity (not a CVSS calculation).
    SEVERITY_DEDUCTIONS = {
        "CRITICAL": 25.0,
        "HIGH": 15.0,
        "MEDIUM": 8.0,
        "LOW": 3.0,
        "INFO": 0.0
    }

    @classmethod
    def calculate_score(cls, findings: List[Finding]) -> float:
        """
        Calculates Security Health Score on a scale from 0.0 (Severe) to 100.0 (Pristine).
        Each rule contributes its highest severity once, regardless of how many
        pages or cookies produced the finding. All occurrences remain in the
        report; only the score is deduplicated.
        """
        deductions_by_rule = {}
        for finding in findings:
            deduction = cls.SEVERITY_DEDUCTIONS.get(finding.severity.upper(), 0.0)
            deductions_by_rule[finding.rule_id] = max(
                deductions_by_rule.get(finding.rule_id, 0.0), deduction
            )

        return max(0.0, round(100.0 - sum(deductions_by_rule.values()), 1))

    @classmethod
    def count_by_severity(cls, findings: List[Finding]) -> Dict[str, int]:
        """
        Returns counts grouped by severity level.
        """
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for finding in findings:
            sev = finding.severity.upper()
            if sev in counts:
                counts[sev] += 1
            else:
                counts["INFO"] += 1
        return counts
