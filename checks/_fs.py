"""Shared directory walk for checks that read file contents as text."""

from __future__ import annotations

from pathlib import Path

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox"}


def iter_text_files(root: Path, max_size: int):
    """Yields (path, text) for every UTF-8 file under root.

    Files over max_size are skipped before any read: read_text() loads the
    whole file into memory before it can reject it as non-UTF-8, which is
    what OOM-kills a scan of a broad root like a home directory.
    """
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            if path.stat().st_size > max_size:
                continue
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        yield path, text
