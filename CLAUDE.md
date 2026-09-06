# Sentria — project instructions

AI-assisted security analyzer. See `README.md` for layout and setup.

## Architecture principle (non-negotiable)

Detection logic is deterministic, plain-Python **checks** — never the model
reading raw system/log data and freeform-deciding what's a threat. Each
check (`checks/`) returns a `list[Finding]`. Severity is assigned by the
explicit rulebook in `context/escalation.py`, not decided ad hoc inside a
check and never left to the model. The model's job (`agent/orchestrator.py`)
is orchestration (deciding which checks to run) and writing the
human-readable narrative *from* the structured summary in
`context/report.py` — it never sees raw file/log content and never assigns
severity itself.

Reason: scanned content (file bytes, manifest text) is untrusted input and
a prompt-injection vector for a security tool specifically. A regex match
or a stat() mode bit becomes Finding evidence; it is never interpreted as
an instruction.

## V1 scope

Exactly 3 checks: hardcoded secrets, known-vulnerable dependencies,
suspicious file permissions. Ask before adding a 4th check or any live-API
integration beyond the orchestration loop already in `agent/`.
`mcp_server.py` (exposing checks over MCP) is a stretch goal, not v1 — do
not add it without being asked.

## Conventions

- `checks/*.py` never assign severity directly — they call into
  `context/escalation.py`'s per-category rulebook.
- `agent/orchestrator.py` is a live script (imports `anthropic`, calls the
  API) and is never imported by `tests/`.
- Tests run offline, no `ANTHROPIC_API_KEY` required (enforced by the
  repo-root `conftest.py`). `tests/conftest.py` puts the repo root on
  `sys.path` so test files import `from checks.secrets_check import ...`,
  `from context.escalation import ...`, etc. directly.
- The repo-root `conftest.py` and `pyproject.toml` hold offline guards
  (strips `ANTHROPIC_API_KEY`, blocks outbound sockets) and pin pytest's
  rootdir so those guards load regardless of invocation directory. Don't
  "tidy" them away — deleting `pyproject.toml` disables the guards
  *silently*: tests keep passing, unguarded.
