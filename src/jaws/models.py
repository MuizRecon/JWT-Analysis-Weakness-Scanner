"""Data models for JWT analysis."""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    """A single security finding from JWT analysis."""
    severity: Severity
    title: str
    detail: str
    recommendation: str
    field: Optional[str] = None


@dataclass
class DecodedToken:
    """Container for a decoded JWT."""
    raw: str
    header: Dict[str, Any]
    payload: Dict[str, Any]
    signature: Optional[str] = None
    is_valid: bool = True


@dataclass
class AnalysisResult:
    """Complete result of analyzing a JWT."""
    token: DecodedToken
    findings: List[Finding] = field(default_factory=list)
    secret_recovered: Optional[str] = None
    cracking_time: Optional[float] = None

    @property
    def has_critical(self) -> bool:
        return any(f.severity == Severity.CRITICAL for f in self.findings)

    @property
    def summary(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts
