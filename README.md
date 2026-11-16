# Sentria — AI-Assisted Security Analyzer

An AI-orchestrated security scanner built around a hard architectural rule:
**detection is deterministic Python, never the model freeform-reading raw
system data.** Four checks scan a target for hardcoded secrets,
known-vulnerable dependencies, suspicious file permissions, and
quantum-vulnerable cryptography (RSA/ECC/DH/DSA), each
returning structured `Finding`s with severity assigned by an explicit,
testable rulebook. The model's role is limited to orchestration (deciding
which checks to run) and writing the final narrative from that already-
structured summary — it never assigns severity and never reads raw scan
input directly, since scanned content is untrusted input and this is
exactly the kind of tool a prompt-injection attempt would target.

## Layout

| Path | Purpose |
|---|---|
| `checks/` | One module per check (`secrets_check.py`, `dependency_check.py`, `permissions_check.py`, `crypto_check.py`), each returning `list[Finding]` (the crypto check also returns its CryptoAssets). Pure Python, fully offline. |
| `context/` | `findings.py` (the `Finding` dataclass + context-window trimming), `escalation.py` (explicit per-category severity rulebook), `report.py` (deterministic summary/report builder), `crypto.py` (the `CryptoAsset` record behind CBOM output). |
| `schemas/` | JSON Schema for `Finding`, `CryptoAsset` and `Report`, plus the vendored CycloneDX 1.6 schemas under `vendor/cyclonedx/`. |
| `agent/orchestrator.py` | Live orchestration loop: the model picks which checks to run as tools, then writes the narrative from the structured summary. Requires `ANTHROPIC_API_KEY`; never imported by tests. |
| `reporters/` | `terminal.py`, `json_reporter.py` and `cbom_reporter.py` (CycloneDX 1.6 CBOM) — pure formatting of a `Report` dict. |
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
- **Crypto**: ranked by harvest-now-decrypt-later exposure (NIST IR 8547).
  Quantum-vulnerable key exchange (RSA encryption, ECDH, DH, X25519) is
  `high`, since recorded traffic can be decrypted later. A key with no
  visible usage (e.g. a bare RSA or EC private key) is also `high`, since
  key establishment can't be ruled out. Signature-only use (ECDSA, Ed25519,
  DSA, RSA signing) is `medium`.

## Post-quantum crypto inventory (CBOM)

`crypto_check.py` finds RSA, ECC, DH and DSA usage in source, configs and
PEM headers. `reporters/cbom_reporter.py` turns the result into a
[CycloneDX 1.6](https://cyclonedx.org/capabilities/cbom/) Cryptographic
Bill of Materials that other PQC-migration tools can read. Every component
has `nistQuantumSecurityLevel: 0` (quantum-vulnerable). Sentria-specific
context goes in namespaced properties: `sentria:hndl-risk`,
`sentria:usage`, `sentria:nist-deprecation`,
`sentria:recommended-migration` (ML-KEM / FIPS 203 or ML-DSA / FIPS 204)
and `sentria:reference`.

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # then edit .env with your key — only needed for agent/orchestrator.py
```

`agent/orchestrator.py` loads `.env` automatically (via `python-dotenv`) if present;
`.env` is gitignored, so your key never gets committed. Setting `ANTHROPIC_API_KEY`
as a real environment variable (e.g. `export ANTHROPIC_API_KEY=...`) also still
works and takes precedence — `.env` is just a convenience for keeping the key
scoped to this project instead of your whole shell.

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

- A 5th check beyond secrets/dependencies/permissions/crypto.
- `mcp_server.py` — exposing checks over MCP is a stretch goal, listed in
  the project structure but intentionally not built yet.
- Certificate DER/OID parsing and OPENSSH-format key classification — PEM
  blocks are classified by header only. Live TLS/SSH endpoint scanning is
  left to dedicated tools like pqcscan.
- Live CVE feed lookups — `checks/vulnerability_db.json` is a small bundled
  seed list, not a live API call.
