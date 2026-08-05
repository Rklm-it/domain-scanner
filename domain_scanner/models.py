"""Core data structures shared by every check."""

from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from typing import Any

# Severity -> risk points contributed to the total score.
SEVERITY_WEIGHTS: dict[str, int] = {
    "info": 0,
    "low": 5,
    "medium": 12,
    "high": 22,
    "critical": 35,
}

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


@dataclass
class Finding:
    """A single observation about a domain.

    ``code`` is a stable identifier (documented in the README glossary) so that
    findings can be grepped, filtered and compared across scans.
    """

    code: str
    severity: str
    message: str
    detail: dict[str, Any] = field(default_factory=dict)
    weight: int | None = None

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_WEIGHTS:
            raise ValueError(f"unknown severity: {self.severity}")
        if self.weight is None:
            self.weight = SEVERITY_WEIGHTS[self.severity]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CheckResult:
    """Outcome of one check for one domain."""

    name: str
    status: str = "ok"  # ok | error | skipped
    findings: list[Finding] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    duration_ms: int = 0
    # Why a skipped check was skipped: "config" (an optional API key is not
    # set -- expected), "transport" (this machine could not reach it) or
    # "timeout" (the domain ran out of its time budget first). Only "config"
    # is a deliberate opt-out; the others are genuine gaps in coverage.
    skip_kind: str | None = None

    def add(
        self,
        code: str,
        severity: str,
        message: str,
        detail: dict[str, Any] | None = None,
        weight: int | None = None,
    ) -> Finding:
        finding = Finding(code, severity, message, detail or {}, weight)
        self.findings.append(finding)
        return finding

    def fail(self, error: str) -> "CheckResult":
        self.status = "error"
        self.error = error
        return self

    def skip(self, reason: str, kind: str = "config") -> "CheckResult":
        self.status = "skipped"
        self.error = reason
        self.skip_kind = kind
        return self

    @property
    def risk_points(self) -> int:
        return sum(f.weight or 0 for f in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "error": self.error,
            "skip_kind": self.skip_kind,
            "duration_ms": self.duration_ms,
            "risk_points": self.risk_points,
            "findings": [f.to_dict() for f in self.findings],
            "data": self.data,
        }


@dataclass
class DomainReport:
    """Aggregated result for a single domain."""

    domain: str
    raw_input: str
    checks: list[CheckResult] = field(default_factory=list)
    score: int = 0
    verdict: str = "UNKNOWN"
    scanned_at: float = field(default_factory=time.time)
    duration_ms: int = 0

    @property
    def findings(self) -> list[Finding]:
        out: list[Finding] = []
        for check in self.checks:
            out.extend(check.findings)
        return out

    def check(self, name: str) -> CheckResult | None:
        for c in self.checks:
            if c.name == name:
                return c
        return None

    def data(self, check_name: str, key: str, default: Any = None) -> Any:
        c = self.check(check_name)
        if c is None:
            return default
        return c.data.get(key, default)

    def top_findings(self, limit: int = 6) -> list[Finding]:
        ranked = sorted(
            self.findings,
            key=lambda f: (-(f.weight or 0), SEVERITY_ORDER.index(f.severity) * -1),
        )
        return [f for f in ranked if (f.weight or 0) > 0][:limit]

    @property
    def failed_checks(self) -> list[str]:
        return [c.name for c in self.checks if c.status == "error"]

    @property
    def unavailable_checks(self) -> list[str]:
        """Checks that produced no data.

        Failed checks, and checks skipped for any reason other than the user
        opting out of them ("config"): no transport to reach them, or no time
        left in the domain's budget.
        """
        return [
            c.name for c in self.checks
            if c.status == "error"
            or (c.status == "skipped" and c.skip_kind != "config")
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "input": self.raw_input,
            "score": self.score,
            "verdict": self.verdict,
            "scanned_at": self.scanned_at,
            "duration_ms": self.duration_ms,
            "failed_checks": self.failed_checks,
            "unavailable_checks": self.unavailable_checks,
            "checks": [c.to_dict() for c in self.checks],
        }
