"""Quantum-vulnerable crypto discovery: RSA, ECC, DH and DSA usage in source,
configs and PEM headers.

Scans once and returns both the Findings (for the normal Sentria report) and
the CryptoAssets they were built from (for CBOM output), so every reporter
describes the same scan. Like every check, file content is opaque text: a
match becomes evidence, never an instruction. Severity comes from
context/escalation.py; algorithm facts come from crypto_algorithms.json.

v1 classifies PEM blocks by header only; OPENSSH-format keys and DER/OID
parsing of certificates are out of scope.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from checks._fs import iter_text_files
from context.crypto import CryptoAsset
from context.escalation import crypto_severity
from context.findings import Finding

_MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MiB, same rationale as secrets_check

_DB = json.loads((Path(__file__).parent / "crypto_algorithms.json").read_text(encoding="utf-8"))

# (algorithm key in crypto_algorithms.json, usage, pattern)
_PATTERNS = (
    ("rsa", "unspecified", re.compile(r"rsa\.generate_private_key|RSA\.generate\(|\bgenrsa\b|RSA_generate_key")),
    ("rsa", "unspecified", re.compile(r"\bRSA[-_ ]?(?:1024|2048|3072|4096|7680|15360)\b")),
    ("rsa", "unspecified", re.compile(r"-----BEGIN RSA (?:PRIVATE|PUBLIC) KEY-----")),
    ("rsa", "key_exchange", re.compile(r"padding\.OAEP|PKCS1_OAEP|RSA-OAEP|RSA_PKCS1_OAEP")),
    ("rsa_signature", "signature", re.compile(r"padding\.PSS|\bpkcs1_15\b|\b(?:RS|PS)(?:256|384|512)\b|\bssh-rsa\b|sha256WithRSAEncryption")),
    ("ec_key", "unspecified", re.compile(r"-----BEGIN EC (?:PRIVATE KEY|PARAMETERS)-----")),
    ("ecdh", "key_exchange", re.compile(r"\bECDHE?\b")),
    ("x25519", "key_exchange", re.compile(r"\bX25519")),
    ("x448", "key_exchange", re.compile(r"\bX448")),
    ("ecdsa", "signature", re.compile(r"(?i)\becdsa\b|\bES(?:256|384|512)\b|\becdsa-sha2-")),
    ("ed25519", "signature", re.compile(r"(?i)\bed25519")),
    ("ed448", "signature", re.compile(r"(?i)\bed448")),
    ("dsa", "signature", re.compile(r"\bdsa\.generate_private_key|\bDSA\.generate\(|\bssh-dss\b|-----BEGIN DSA PRIVATE KEY-----")),
    ("dh", "key_exchange", re.compile(r"\bdh\.generate_parameters|DiffieHellman|\bDHE-|\bFFDHE\d+|\bdhparam\b|-----BEGIN DH PARAMETERS-----")),
)

_KEY_SIZE = re.compile(r"key_size\s*=\s*(\d{3,5})|\b(?:RSA|DSA|DH|FFDHE|genrsa|dhparam)[-_ ]?(\d{3,5})\b")

_USAGE_LABEL = {"key_exchange": "key exchange", "signature": "signature", "unspecified": "usage unspecified"}


@dataclass(frozen=True)
class CryptoScan:
    findings: list[Finding]
    assets: list[CryptoAsset]


def scan_crypto(root: str | Path) -> CryptoScan:
    root = Path(root)
    findings: list[Finding] = []
    assets: list[CryptoAsset] = []
    for path, text in iter_text_files(root, _MAX_FILE_SIZE):
        location = path.relative_to(root).as_posix()
        for line_no, line in enumerate(text.splitlines(), start=1):
            seen: set[tuple[str, str]] = set()
            for algorithm, usage, pattern in _PATTERNS:
                if (algorithm, usage) in seen or not pattern.search(line):
                    continue
                seen.add((algorithm, usage))
                finding, asset = _build(path, location, line_no, line, algorithm, usage)
                findings.append(finding)
                assets.append(asset)
    return CryptoScan(findings=findings, assets=assets)


def _build(path: Path, location: str, line_no: int, line: str, algorithm: str, usage: str) -> tuple[Finding, CryptoAsset]:
    facts = _DB["algorithms"][algorithm]
    key_size = _key_size(line) if "classical_security_by_key_size" in facts else None
    name = f"{facts['name']}-{key_size}" if key_size else facts["name"]
    severity = crypto_severity(usage)
    deprecation = _DB["nist_deprecation"]

    finding = Finding(
        check="crypto_check",
        category="crypto",
        severity=severity,
        description=f"Quantum-vulnerable {name} ({_USAGE_LABEL[usage]}) found in {path.name}.",
        evidence=f"{path}:{line_no} {name} ({usage})",
        remediation=(
            f"Plan migration to {facts['recommended_migration']}; NIST deprecates "
            f"quantum-vulnerable public-key algorithms after {deprecation} ({_DB['reference']})."
        ),
    )
    classical = facts.get("classical_security")
    if key_size:
        classical = facts["classical_security_by_key_size"].get(key_size)
    asset = CryptoAsset(
        id=finding.id,
        algorithm=algorithm,
        name=name,
        usage=usage,
        location=location,
        line=line_no,
        oid=facts["oid"],
        primitive=facts["primitive"],
        crypto_functions=tuple(facts["crypto_functions"]),
        nist_quantum_security_level=_DB["nist_quantum_security_level"],
        nist_deprecation=deprecation,
        recommended_migration=facts["recommended_migration"],
        reference=_DB["reference"],
        hndl_risk=severity,
        parameter_set=key_size,
        curve=facts.get("curve"),
        classical_security_level=classical,
    )
    return finding, asset


def _key_size(line: str) -> str | None:
    match = _KEY_SIZE.search(line)
    if not match:
        return None
    return match.group(1) or match.group(2)
