"""Common verification verdict dataclass across SQL, Lean 4, and protocol checkers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class VerifyVerdict:
    """Unified mechanical gate decision across all `lab-verify` domains."""

    passed: bool
    layer: str | None
    reason: str
    diagnostics: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "layer": self.layer,
            "reason": self.reason,
            "diagnostics": list(self.diagnostics),
        }


Verdict = VerifyVerdict
