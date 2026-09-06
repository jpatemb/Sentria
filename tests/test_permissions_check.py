import os
import stat

from checks.permissions_check import scan_permissions


def test_world_writable_executable_is_flagged_critical(tmp_path):
    script = tmp_path / "run.sh"
    script.write_text("#!/bin/sh\necho hi\n")
    script.chmod(0o777)

    findings = scan_permissions(tmp_path)

    assert len(findings) == 1
    assert findings[0].severity == "critical"


def test_world_writable_non_executable_file_is_flagged_low(tmp_path):
    notes = tmp_path / "notes.txt"
    notes.write_text("hello\n")
    notes.chmod(0o666)

    findings = scan_permissions(tmp_path)

    assert len(findings) == 1
    assert findings[0].severity == "low"


def test_non_world_writable_file_is_not_flagged(tmp_path):
    notes = tmp_path / "notes.txt"
    notes.write_text("hello\n")
    notes.chmod(0o644)

    findings = scan_permissions(tmp_path)

    assert findings == []


def test_evidence_includes_octal_mode(tmp_path):
    notes = tmp_path / "notes.txt"
    notes.write_text("hello\n")
    notes.chmod(0o666)

    findings = scan_permissions(tmp_path)

    assert oct(stat.S_IMODE(os.stat(notes).st_mode)) in findings[0].evidence
