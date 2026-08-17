from pydantic import BaseModel
from enum import Enum
from typing import Optional

class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"

class FindingType(str, Enum):
    hardcoded_secret = "hardcoded_secret"
    missing_auth = "missing_auth"
    wildcard_cors = "wildcard_cors"
    unsafe_eval = "unsafe_eval"
    sql_injection_pattern = "sql_injection_pattern"
    missing_rate_limit = "missing_rate_limit"
    xss_risk = "xss_risk"

class Finding(BaseModel):
    id: str
    type: FindingType
    severity: Severity
    confidence: float
    title: str
    description: str
    evidence: str
    location: Optional[str] = None
    remediation: Optional[str] = None