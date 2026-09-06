import pytest

from context.findings import Finding, trim_findings


def _finding(check="c", evidence="e", severity="low", category="secrets"):
    return Finding(
        check=check,
        category=category,
        severity=severity,
        description="d",
        evidence=evidence,
        remediation="r",
    )


def test_rejects_unknown_category():
    with pytest.raises(ValueError):
        Finding(check="c", category="bogus", severity="low", description="d", evidence="e", remediation="r")


def test_rejects_unknown_severity():
    with pytest.raises(ValueError):
        Finding(check="c", category="secrets", severity="bogus", description="d", evidence="e", remediation="r")


def test_id_is_deterministic_for_same_check_and_evidence():
    a = _finding(check="secrets_check", evidence="file.py:1")
    b = _finding(check="secrets_check", evidence="file.py:1")
    assert a.id == b.id


def test_id_differs_for_different_evidence():
    a = _finding(evidence="file.py:1")
    b = _finding(evidence="file.py:2")
    assert a.id != b.id


def test_trim_findings_keeps_highest_severity_first():
    low = _finding(evidence="low", severity="low")
    critical = _finding(evidence="critical", severity="critical")
    medium = _finding(evidence="medium", severity="medium")

    trimmed = trim_findings([low, critical, medium], max_items=2)

    assert trimmed == [critical, medium]


def test_trim_findings_never_drops_a_critical_for_an_earlier_low():
    critical = _finding(evidence="critical", severity="critical")
    lows = [_finding(evidence=f"low-{i}", severity="low") for i in range(5)]

    trimmed = trim_findings(lows + [critical], max_items=1)

    assert trimmed == [critical]
