from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    INFO = 10
    LOW = 20
    MEDIUM = 30
    HIGH = 40
    CRITICAL = 50

    @classmethod
    def from_str(cls, s: str) -> Severity:
        s = s.strip().upper()
        return getattr(cls, s)


@dataclass(frozen=True)
class Finding:
    service: str
    resource_id: str
    title: str
    severity: Severity
    detail: str
    recommendation: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class CheckResult:
    service: str
    name: str
    findings: list[Finding]
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    skipped: bool = False

    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {sev.name: 0 for sev in Severity}
        for f in self.findings:
            counts[f.severity.name] += 1
        return counts


@dataclass
class Report:
    account_id: str
    regions: list[str]
    findings: list[Finding]
    checks: list[CheckResult]

    def summary(self) -> dict[str, Any]:
        counts: dict[str, int] = {sev.name: 0 for sev in Severity}
        for f in self.findings:
            counts[f.severity.name] += 1
        total = len(self.findings)
        worst = max((f.severity for f in self.findings), default=Severity.INFO)
        by_service: dict[str, int] = {}
        for f in self.findings:
            by_service[f.service] = by_service.get(f.service, 0) + 1
        warnings = [
            {"service": c.service, "name": c.name, "warning": w}
            for c in self.checks
            for w in c.warnings
        ]
        errors = [
            {"service": c.service, "name": c.name, "error": e}
            for c in self.checks
            for e in c.errors
        ]
        skipped = [{"service": c.service, "name": c.name} for c in self.checks if c.skipped]
        return {
            "total": total,
            "counts": counts,
            "worst": worst.name,
            "by_service": by_service,
            "warnings": warnings,
            "errors": errors,
            "skipped": skipped,
        }
