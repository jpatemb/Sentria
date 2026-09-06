"""Suspicious file-permission detection: world-writable files and
overly-permissive executables.

Reads only os.stat() mode bits — never file contents — so this check has
no exposure to anything a file's content might try to say.
"""

from __future__ import annotations

import stat
from pathlib import Path

from context.escalation import permission_severity
from context.findings import Finding

_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox"}


def _iter_files(root: Path):
    for path in root.rglob("*"):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if path.is_file() and not path.is_symlink():
            yield path


def scan_permissions(root: str | Path) -> list[Finding]:
    root = Path(root)
    findings: list[Finding] = []
    for path in _iter_files(root):
        mode = path.stat().st_mode
        world_writable = bool(mode & stat.S_IWOTH)
        if not world_writable:
            continue
        is_executable = bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
        severity = permission_severity(world_writable=world_writable, is_executable=is_executable, path=str(path))
        findings.append(_make_finding(path, mode, is_executable, severity))
    return findings


def _make_finding(path: Path, mode: int, is_executable: bool, severity: str) -> Finding:
    perm_string = stat.filemode(mode)
    kind = "world-writable executable" if is_executable else "world-writable file"
    return Finding(
        check="permissions_check",
        category="permissions",
        severity=severity,
        description=f"{kind.capitalize()} found: {path.name} ({perm_string}).",
        evidence=f"{path}: mode {oct(stat.S_IMODE(mode))} ({perm_string})",
        remediation="Remove world-write permission (chmod o-w) unless the file must be "
                    "writable by any user on the system.",
    )
