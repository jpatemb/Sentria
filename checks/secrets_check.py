"""Hardcoded-secret detection: known-credential regexes plus a high-entropy
fallback for quoted strings that don't match a recognizable prefix.

Files are scanned as opaque text. A regex match becomes Finding evidence —
it is never interpreted as an instruction, which matters because this is
exactly the kind of untrusted input a security tool must not trust.
"""

from __future__ import annotations

import math
import re
from pathlib import Path

from context.escalation import secret_severity
from context.findings import Finding

_PATTERNS = (
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("aws_secret_key", re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}")),
    ("anthropic_api_key", re.compile(r"sk-ant-[A-Za-z0-9\-_]{20,}")),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("generic_api_key", re.compile(r"(?i)(?:api[_-]?key|secret|token)\s*[=:]\s*['\"][A-Za-z0-9\-_/+=]{16,}['\"]")),
)

_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox"}

# Secrets live in source/config files, never in multi-GB binaries or data
# files. Without this cap, read_text() loads a huge file entirely into
# memory before it can even reject it as non-UTF-8, which is what OOM-kills
# a broad scan (e.g. scanning a whole home directory or filesystem root).
_MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MiB

_ENTROPY_MIN_LENGTH = 20
_ENTROPY_THRESHOLD = 4.0
_ENTROPY_CANDIDATE = re.compile(r"['\"]([A-Za-z0-9+/_\-]{20,})['\"]")


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _iter_text_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        try:
            if path.stat().st_size > _MAX_FILE_SIZE:
                continue
            path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        yield path


def scan_secrets(root: str | Path) -> list[Finding]:
    root = Path(root)
    findings: list[Finding] = []
    for path in _iter_text_files(root):
        text = path.read_text(encoding="utf-8")
        for line_no, line in enumerate(text.splitlines(), start=1):
            matched_spans: list[tuple[int, int]] = []
            for kind, pattern in _PATTERNS:
                match = pattern.search(line)
                if match:
                    findings.append(_make_finding(path, line_no, kind, match.group(0)))
                    matched_spans.append(match.span())
            for match in _ENTROPY_CANDIDATE.finditer(line):
                if any(a <= match.start() < b for a, b in matched_spans):
                    continue  # already reported by a specific pattern above
                candidate = match.group(1)
                if len(candidate) >= _ENTROPY_MIN_LENGTH and _shannon_entropy(candidate) >= _ENTROPY_THRESHOLD:
                    findings.append(_make_finding(path, line_no, "high_entropy_string", candidate))
    return findings


def _make_finding(path: Path, line_no: int, kind: str, matched: str) -> Finding:
    redacted = f"{matched[:4]}…{matched[-4:]}" if len(matched) > 8 else "…"
    return Finding(
        check="secrets_check",
        category="secrets",
        severity=secret_severity(kind),
        description=f"Possible hardcoded secret ({kind.replace('_', ' ')}) found in {path.name}.",
        evidence=f"{path}:{line_no} matched {kind} ({redacted})",
        remediation="Remove the secret from source, rotate it, and load it from an "
                    "environment variable or secrets manager instead.",
    )
