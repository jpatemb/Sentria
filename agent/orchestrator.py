"""Live orchestration loop (requires ANTHROPIC_API_KEY) — not imported by
tests/. Claude picks which checks to run as tools; this module executes
them and returns raw counts as tool_results, never finding content, so the
model only ever learns "how many", not "what". Once the model stops calling
tools, its final text becomes the report's narrative, appended to the
already-built, fully deterministic summary from context/report.py.
"""

from __future__ import annotations

import json

import anthropic

from checks.dependency_check import scan_dependencies
from checks.permissions_check import scan_permissions
from checks.secrets_check import scan_secrets
from context.findings import Finding, trim_findings
from context.report import build_report

MODEL = "claude-sonnet-5"
MAX_FINDINGS_IN_CONTEXT = 50

_TOOLS = [
    {
        "name": "run_secrets_check",
        "description": "Scan a directory tree for hardcoded secrets (API keys, tokens, private keys, high-entropy strings).",
        "input_schema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Directory to scan."}},
            "required": ["path"],
        },
    },
    {
        "name": "run_dependency_check",
        "description": "Check a pinned requirements.txt-style manifest against a known-vulnerable-dependency list.",
        "input_schema": {
            "type": "object",
            "properties": {"manifest_path": {"type": "string", "description": "Path to the manifest file."}},
            "required": ["manifest_path"],
        },
    },
    {
        "name": "run_permissions_check",
        "description": "Scan a directory tree for world-writable files and overly-permissive executables.",
        "input_schema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Directory to scan."}},
            "required": ["path"],
        },
    },
]


def _dispatch(name: str, tool_input: dict) -> list[Finding]:
    if name == "run_secrets_check":
        return scan_secrets(tool_input["path"])
    if name == "run_dependency_check":
        return scan_dependencies(tool_input["manifest_path"])
    if name == "run_permissions_check":
        return scan_permissions(tool_input["path"])
    raise ValueError(f"unknown tool: {name}")


def run_scan(target_path: str, manifest_path: str, client: "anthropic.Anthropic | None" = None) -> dict:
    """Runs the agentic tool_use loop, then returns a Report dict (see
    schemas/report.schema.json)."""
    client = client or anthropic.Anthropic()
    all_findings: list[Finding] = []
    narrative = ""

    messages = [
        {
            "role": "user",
            "content": (
                f"Run every available security check against target directory "
                f"'{target_path}' (dependency manifest at '{manifest_path}'), "
                f"then summarize what you found in a few sentences."
            ),
        }
    ]

    while True:
        response = client.messages.create(
            model=MODEL,
            max_tokens=1024,
            tools=_TOOLS,
            messages=messages,
        )
        messages.append({"role": "assistant", "content": response.content})

        if response.stop_reason != "tool_use":
            narrative = "".join(block.text for block in response.content if block.type == "text")
            break

        tool_results = []
        for block in response.content:
            if block.type != "tool_use":
                continue
            findings = _dispatch(block.name, block.input)
            all_findings.extend(findings)
            tool_results.append({
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": json.dumps({"count": len(findings)}),
            })
        messages.append({"role": "user", "content": tool_results})

    trimmed = trim_findings(all_findings, MAX_FINDINGS_IN_CONTEXT)
    return build_report(target_path, trimmed, narrative=narrative)


if __name__ == "__main__":
    report = run_scan(target_path=".", manifest_path="requirements.txt")
    print(json.dumps(report, indent=2))
