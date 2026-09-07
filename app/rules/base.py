from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str
    description: str
    url: str
    evidence: str
    remediation: str
    cwe_id: Optional[str] = None

class BaseRule(ABC):
    rule_id: str
    title: str
    category: str
    severity: str
    cwe_id: Optional[str] = None

    @abstractmethod
    def evaluate(self, url: str, response_headers: Dict[str, str], response_body: str, cookies: List[Dict[str, Any]]) -> List[Finding]:
        """
        Evaluate a target URL's HTTP response against the rule logic.
        """
        pass
