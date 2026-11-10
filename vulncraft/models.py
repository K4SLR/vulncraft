from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Finding:
    """Represents a validated security vulnerability finding."""

    id: str
    title: str
    endpoint: str
    vuln_type: str
    cwe_id: str
    cvss_vector: str
    cvss_score: float
    severity_label: str
    description: str
    impact: str
    status: str
    in_scope: bool = True
    steps_to_reproduce: List[str] = field(default_factory=list)
    redacted_request: str = ""
    redacted_response: str = ""
    remediation_summary: str = ""
    remediation_code: str = ""
    remediation_lang: str = "text"

    def to_dict(self) -> Dict[str, Any]:
        """Serializes finding data to a clean dictionary (never exposes raw unsanitized secrets)."""
        return {
            "id": self.id,
            "title": self.title,
            "endpoint": self.endpoint,
            "vuln_type": self.vuln_type,
            "cwe_id": self.cwe_id,
            "cvss_vector": self.cvss_vector,
            "cvss_score": self.cvss_score,
            "severity_label": self.severity_label,
            "description": self.description,
            "impact": self.impact,
            "status": self.status,
            "in_scope": self.in_scope,
            "steps_to_reproduce": list(self.steps_to_reproduce),
            "redacted_request": self.redacted_request,
            "redacted_response": self.redacted_response,
            "remediation_summary": self.remediation_summary,
            "remediation_code": self.remediation_code,
            "remediation_lang": self.remediation_lang,
        }


@dataclass
class ScopeRule:
    """Target scope configuration containing explicit allow and deny patterns."""

    program_name: str
    in_scope: List[str] = field(default_factory=list)
    out_of_scope: List[str] = field(default_factory=list)
    rules: List[str] = field(default_factory=list)