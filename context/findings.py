"""Finding dataclass shared by every check, plus context-window trimming.

Checks construct Finding instances directly; nothing here calls a model.
Keeping the shape in one place is what lets checks/, the escalation rules,
and the reporters all agree on it (see schemas/finding.schema.json).
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass

SEVERITIES = ("low", "medium", "high", "critical")
CATEGORIES = ("secrets", "dependencies", "permissions")

# Lower rank = more severe. Used for sorting and trimming so the highest-
# severity findings are the ones kept/shown first, never dropped for lows.
_SEVERITY_RANK = {sev: rank for rank, sev in enumerate(reversed(SEVERITIES))}


@dataclass(frozen=True)
class Finding:
    check: str
    category: str
    severity: str
    description: str
    evidence: str
    remediation: str
    id: str = ""

    def __post_init__(self) -> None:
        if self.category not in CATEGORIES:
            raise ValueError(f"unknown category: {self.category!r}")
        if self.severity not in SEVERITIES:
            raise ValueError(f"unknown severity: {self.severity!r}")
        if not self.id:
            object.__setattr__(self, "id", _make_id(self.check, self.evidence))

    def to_dict(self) -> dict:
        return asdict(self)


def _make_id(check: str, evidence: str) -> str:
    """Deterministic id from check + evidence: re-running a scan on
    unchanged input reproduces the same finding id, which is what makes
    provenance (which check produced what) stable across runs."""
    digest = hashlib.sha256(f"{check}:{evidence}".encode()).hexdigest()[:12]
    return f"{check}-{digest}"


def sort_by_severity(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: _SEVERITY_RANK[f.severity])


def trim_findings(findings: list[Finding], max_items: int) -> list[Finding]:
    """Keep the highest-severity findings when there are more than fit in
    the model's context window. Never truncates by scan order, which could
    silently drop a critical in favor of an earlier low."""
    return sort_by_severity(findings)[:max_items]
