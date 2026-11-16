"""CryptoAsset: one detected use of quantum-vulnerable public-key crypto.

Produced once per scan by checks/crypto_check.py alongside the matching
Finding, then carried on the Report (context/report.py) so every reporter —
terminal, JSON, CBOM — formats the same scan. Reporters never rediscover
assets themselves.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

USAGES = ("key_exchange", "signature", "unspecified")


@dataclass(frozen=True)
class CryptoAsset:
    id: str
    algorithm: str
    name: str
    usage: str
    location: str
    line: int
    oid: str
    primitive: str
    crypto_functions: tuple[str, ...]
    nist_quantum_security_level: int
    nist_deprecation: str
    recommended_migration: str
    reference: str
    hndl_risk: str
    parameter_set: str | None = None
    curve: str | None = None
    classical_security_level: int | None = None

    def __post_init__(self) -> None:
        if self.usage not in USAGES:
            raise ValueError(f"unknown usage: {self.usage!r}")

    def to_dict(self) -> dict:
        d = asdict(self)
        d["crypto_functions"] = list(self.crypto_functions)
        return d
