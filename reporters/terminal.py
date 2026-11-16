"""Terminal reporter: formats a Report dict (schemas/report.schema.json) as
human-readable text. Pure string formatting — fully unit-testable offline.
"""

from __future__ import annotations

_SEVERITY_ORDER = ("critical", "high", "medium", "low")


def render_terminal_report(report: dict) -> str:
    lines = [
        f"Sentria security report — {report['target']}",
        f"Generated: {report['generated_at']}",
        "",
        f"Total findings: {report['summary']['total']}",
    ]
    for severity in _SEVERITY_ORDER:
        count = report["summary"]["by_severity"].get(severity, 0)
        if count:
            lines.append(f"  {severity.upper()}: {count}")
    lines.append("")

    findings = sorted(report["findings"], key=lambda f: _SEVERITY_ORDER.index(f["severity"]))
    for finding in findings:
        lines.append(f"[{finding['severity'].upper()}] {finding['category']} — {finding['description']}")
        lines.append(f"    evidence: {finding['evidence']}")
        lines.append(f"    remediation: {finding['remediation']}")
        lines.append("")

    assets = report.get("crypto_assets", [])
    if assets:
        lines.append(f"Quantum-vulnerable cryptography: {len(assets)} use(s) found")
        by_name: dict[str, int] = {}
        for asset in assets:
            by_name[asset["name"]] = by_name.get(asset["name"], 0) + 1
        for name, count in sorted(by_name.items()):
            lines.append(f"  {name}: {count}")
        lines.append("  Full inventory: CycloneDX CBOM via reporters/cbom_reporter.py")
        lines.append("")

    if report.get("narrative"):
        lines.append("Summary:")
        lines.append(report["narrative"])

    return "\n".join(lines)


def print_terminal_report(report: dict) -> None:
    print(render_terminal_report(report))
