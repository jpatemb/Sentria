"""Known-vulnerable dependency detection.

Parses a pinned requirements.txt-style manifest and checks each pin against
a small local CVE list (vulnerability_db.json, bundled alongside this
module) — no live CVE API call, so this stays offline and testable. Only
exact `==` pins are supported in v1; unpinned or range-specified
requirements are skipped rather than guessed at.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from context.escalation import dependency_severity
from context.findings import Finding

_DB_PATH = Path(__file__).parent / "vulnerability_db.json"
_PIN_PATTERN = re.compile(r"^([A-Za-z0-9_.\-]+)\s*==\s*([0-9][0-9A-Za-z.\-]*)")


def _load_db() -> list[dict]:
    with _DB_PATH.open(encoding="utf-8") as f:
        return json.load(f)


def _parse_version(v: str) -> tuple[int, ...]:
    """Parses the leading dotted-integer run of a version string, stopping
    at the first non-numeric component (e.g. a pre-release suffix)."""
    out = []
    for part in re.split(r"[.\-]", v):
        if not part.isdigit():
            break
        out.append(int(part))
    return tuple(out) or (0,)


def _version_lt(a: tuple[int, ...], b: tuple[int, ...]) -> bool:
    length = max(len(a), len(b))
    a = a + (0,) * (length - len(a))
    b = b + (0,) * (length - len(b))
    return a < b


def parse_pinned_requirements(text: str) -> dict[str, str]:
    pins: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = _PIN_PATTERN.match(line)
        if match:
            pins[match.group(1).lower()] = match.group(2)
    return pins


def scan_dependencies(manifest_path: str | Path, db: list[dict] | None = None) -> list[Finding]:
    manifest_path = Path(manifest_path)
    pins = parse_pinned_requirements(manifest_path.read_text(encoding="utf-8"))
    db = _load_db() if db is None else db

    findings: list[Finding] = []
    for entry in db:
        pkg = entry["package"].lower()
        pinned = pins.get(pkg)
        if pinned is None:
            continue
        if _version_lt(_parse_version(pinned), _parse_version(entry["vulnerable_below"])):
            findings.append(_make_finding(manifest_path, pkg, pinned, entry))
    return findings


def _make_finding(manifest_path: Path, pkg: str, pinned: str, entry: dict) -> Finding:
    return Finding(
        check="dependency_check",
        category="dependencies",
        severity=dependency_severity(entry.get("cvss")),
        description=f"{pkg}=={pinned} is affected by {entry['cve']}: {entry['description']}",
        evidence=f"{manifest_path}: {pkg}=={pinned} (fixed in {entry['vulnerable_below']})",
        remediation=f"Upgrade {pkg} to {entry['vulnerable_below']} or later.",
    )
