from checks.dependency_check import parse_pinned_requirements, scan_dependencies

_FAKE_DB = [
    {
        "package": "examplepkg",
        "vulnerable_below": "2.0.0",
        "cve": "CVE-9999-0001",
        "cvss": 9.1,
        "description": "test vulnerability",
    }
]


def test_parses_pinned_requirements_and_ignores_unpinned():
    text = "requests==2.31.0\nflask>=2.0\n# comment\n\nnumpy==1.26.0\n"

    pins = parse_pinned_requirements(text)

    assert pins == {"requests": "2.31.0", "numpy": "1.26.0"}


def test_flags_pinned_version_below_vulnerable_threshold(tmp_path):
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("examplepkg==1.5.0\n")

    findings = scan_dependencies(manifest, db=_FAKE_DB)

    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert "CVE-9999-0001" in findings[0].description


def test_does_not_flag_version_at_or_above_threshold(tmp_path):
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("examplepkg==2.0.0\n")

    findings = scan_dependencies(manifest, db=_FAKE_DB)

    assert findings == []


def test_does_not_flag_package_not_in_db(tmp_path):
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("unrelatedpkg==0.1.0\n")

    findings = scan_dependencies(manifest, db=_FAKE_DB)

    assert findings == []


def test_bundled_db_flags_known_vulnerable_pyyaml(tmp_path):
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("pyyaml==5.3\n")

    findings = scan_dependencies(manifest)

    assert any(f.check == "dependency_check" and "pyyaml" in f.evidence for f in findings)
