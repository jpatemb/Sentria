# Sentria — AI-Assisted Security Analyzer

An AI-orchestrated security scanner built around a hard architectural rule:
**detection is deterministic Python, never the model freeform-reading raw
system data.** Three checks scan a target for hardcoded secrets,
known-vulnerable dependencies, and suspicious file permissions, each
returning structured `Finding`s with severity assigned by an explicit,
testable rulebook. The model's role is limited to orchestration (deciding
which checks to run) and writing the final narrative from that already-
structured summary — it never assigns severity and never reads raw scan
input directly, since scanned content is untrusted input and this is
exactly the kind of tool a prompt-injection attempt would target.

## Layout

| Path | Purpose |
|---|---|
| `checks/` | One module per check (`secrets_check.py`, `dependency_check.py`, `permissions_check.py`), each returning `list[Finding]`. Pure Python, fully offline. |
| `context/` | `findings.py` (the `Finding` dataclass + context-window trimming), `escalation.py` (explicit per-category severity rulebook), `report.py` (deterministic summary/report builder). |
| `schemas/` | JSON Schema for `Finding` and `Report`. |
| `agent/orchestrator.py` | Live orchestration loop: the model picks which checks to run as tools, then writes the narrative from the structured summary. Requires `ANTHROPIC_API_KEY`; never imported by tests. |
| `reporters/` | `terminal.py` and `json_reporter.py` — pure formatting of a `Report` dict. |
| `tests/` | Offline unit tests for every check, the escalation rulebook, report building, reporters, and schema conformance. |

## Escalation criteria (explicit, testable — see `context/escalation.py`)

- **Secrets**: any live-looking credential (AWS key, Anthropic key, GitHub
  token, private key) is always `critical`. A generic `api_key=...`-shaped
  match is `high`. A bare high-entropy string with no recognizable prefix
  is `medium`.
- **Dependencies**: severity follows the CVE's CVSS base score
  (`>=9.0` critical, `>=7.0` high, `>=4.0` medium, else low). A dependency
  with no published score is `medium`, not dropped.
- **Permissions**: a world-writable executable is always `critical`. A
  world-writable file under a system path (`/etc`, `/usr`, `/bin`, ...) is
  `high` even if not executable. Anything else world-writable is `low`.

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export ANTHROPIC_API_KEY=your-key-here   # only needed for agent/orchestrator.py
```

## Run

Offline (no API key needed) — covers every check, the escalation rulebook,
report building, reporters, and schema conformance:

```bash
pytest tests/ -v
```

Live orchestration loop (scans the current directory by default):

```bash
python3 -m agent.orchestrator
```

## Not in v1

- A 4th check beyond secrets/dependencies/permissions.
- `mcp_server.py` — exposing checks over MCP is a stretch goal, listed in
  the project structure but intentionally not built yet.
- Live CVE feed lookups — `checks/vulnerability_db.json` is a small bundled
  seed list, not a live API call.
