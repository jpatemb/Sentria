"""JSON reporter: serializes a Report dict to a JSON string or file."""

from __future__ import annotations

import json
from pathlib import Path


def render_json_report(report: dict) -> str:
    return json.dumps(report, indent=2, sort_keys=True)


def write_json_report(report: dict, path: str | Path) -> None:
    Path(path).write_text(render_json_report(report), encoding="utf-8")
