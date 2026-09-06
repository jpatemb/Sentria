import os
import stat
from pathlib import Path

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


def test_unreadable_file_is_skipped_not_raised(tmp_path, monkeypatch):
    """A file that vanishes/becomes unreadable between the directory walk and
    the stat() call in scan_permissions must be skipped, not crash the scan.

    Path.is_file() and Path.is_symlink() (used by the directory walk) also
    call Path.stat() internally, so those calls for `notes` must succeed —
    only the final call, the explicit one in scan_permissions, should fail.
    """
    notes = tmp_path / "notes.txt"
    notes.write_text("hello\n")
    notes.chmod(0o666)

    real_stat = Path.stat
    calls_for_notes = 0
    calls_before_failure = 2  # is_file() + is_symlink()->lstat(), both must succeed

    def flaky_stat(self, *args, **kwargs):
        nonlocal calls_for_notes
        if self == notes:
            calls_for_notes += 1
            if calls_for_notes > calls_before_failure:
                raise PermissionError("simulated permission denied")
        return real_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", flaky_stat)

    findings = scan_permissions(tmp_path)

    assert findings == []
