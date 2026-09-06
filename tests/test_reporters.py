from context.findings import Finding
from context.report import build_report
from reporters.json_reporter import render_json_report
from reporters.terminal import render_terminal_report


def _sample_report():
    findings = [
        Finding(check="secrets_check", category="secrets", severity="critical",
                description="hardcoded key", evidence="a.py:1", remediation="rotate it"),
        Finding(check="permissions_check", category="permissions", severity="low",
                description="world-writable file", evidence="b.txt: mode 0o666", remediation="chmod o-w"),
    ]
    return build_report("target-dir", findings, narrative="Two findings, one critical.")


def test_terminal_report_lists_findings_highest_severity_first():
    report = _sample_report()

    text = render_terminal_report(report)

    critical_index = text.index("CRITICAL")
    low_index = text.index("LOW")
    assert critical_index < low_index
    assert "Two findings, one critical." in text


def test_terminal_report_includes_summary_counts():
    report = _sample_report()

    text = render_terminal_report(report)

    assert "Total findings: 2" in text


def test_json_report_round_trips():
    import json

    report = _sample_report()

    text = render_json_report(report)
    parsed = json.loads(text)

    assert parsed["summary"]["total"] == 2
    assert parsed["target"] == "target-dir"
