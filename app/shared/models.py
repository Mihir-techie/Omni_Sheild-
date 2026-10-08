"""Plain data types shared by the detection modules and the XAI engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Finding:
    """One triggered indicator. `code` selects the plain-language template in the XAI engine."""

    code: str
    points: int
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class ModuleResult:
    module: str  # "phishing" | "deepfake" | "ato"
    findings: list[Finding]
    evidence: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    @property
    def score(self) -> int:
        """Raw module anomaly score on a 0-100 scale."""
        return max(0, min(100, sum(f.points for f in self.findings)))
