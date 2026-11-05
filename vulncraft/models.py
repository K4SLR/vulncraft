from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any


@dataclass
class ScopeConfig:
    program_name: str
    in_scope: List[str]
    out_of_scope: List[str]
    rules: List[str] = field(default_factory=list)


@dataclass
class Finding:
    id: str
    title: str
    endpoint: str
    vuln_type: str
    cvss_vector: str
    description: str
    steps_to_reproduce: List[str]
    raw_http_request: str = ""
    raw_http_response: str = ""
    impact: str = ""
    status: str = "OPEN"
    cvss_score: float = 0.0
    severity_label: str = "INFO"
    in_scope: bool = True
    cwe_id: str = ""
    remediation_lang: str = "text"
    remediation_summary: str = ""
    remediation_code: str = ""
    redacted_request: str = ""
    redacted_response: str = ""

    def to_dict(self, include_raw: bool = False) -> Dict[str, Any]:
        data = asdict(self)
        if not include_raw:
            data.pop("raw_http_request", None)
            data.pop("raw_http_response", None)
        return data
