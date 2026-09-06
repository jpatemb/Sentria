"""Builds the structured Report dict (schemas/report.schema.json) from a
list of Findings.

The summary (counts by severity/category) is fully deterministic. The
`narrative` field is filled in by the caller (the orchestration loop in
agent/) after the model writes it from this structured summary — this
module never calls a model itself.
"""

from __future__ import annotations

from datetime import datetime, timezone

from context.findings import CATEGORIES, SEVERITIES, Finding


def build_report(target: str, findings: list[Finding], narrative: str = "") -> dict:
    by_severity = {sev: 0 for sev in SEVERITIES}
    by_category = {cat: 0 for cat in CATEGORIES}
    for finding in findings:
        by_severity[finding.severity] += 1
        by_category[finding.category] += 1

    return {
        "target": target,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "findings": [f.to_dict() for f in findings],
        "summary": {
            "total": len(findings),
            "by_severity": by_severity,
            "by_category": by_category,
        },
        "narrative": narrative,
    }
