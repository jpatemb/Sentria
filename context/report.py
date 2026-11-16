"""Builds the structured Report dict (schemas/report.schema.json) from a
list of Findings.

The summary (counts by severity/category) is fully deterministic. The
`narrative` field is filled in by the caller (the orchestration loop in
agent/) after the model writes it from this structured summary — this
module never calls a model itself.
"""

from __future__ import annotations

from datetime import datetime, timezone

from context.crypto import CryptoAsset
from context.findings import CATEGORIES, SEVERITIES, Finding


def build_report(
    target: str,
    findings: list[Finding],
    narrative: str = "",
    crypto_assets: list[CryptoAsset] | None = None,
) -> dict:
    """crypto_assets is the inventory from the same scan that produced the
    crypto findings; the CBOM reporter formats it, never rescans for it."""
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
        "crypto_assets": [a.to_dict() for a in crypto_assets or []],
    }
