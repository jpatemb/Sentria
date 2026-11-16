"""CBOM reporter: formats a Report's crypto_assets as a CycloneDX 1.6
Cryptographic Bill of Materials.

Pure formatting of the inventory already on the Report — it never scans or
imports from checks/, so the CBOM always describes the same scan as the
terminal and JSON reports. Output must validate against the vendored
schemas/vendor/cyclonedx/bom-1.6.schema.json (enforced in tests): anything
Sentria-specific goes in namespaced `properties`, never as extra keys inside
`cryptoProperties`, which the spec closes with additionalProperties: false.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path


def build_cbom(report: dict) -> dict:
    serial = uuid.uuid5(uuid.NAMESPACE_URL, f"sentria:{report['target']}:{report['generated_at']}")
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": report["generated_at"],
            "tools": {"components": [{"type": "application", "name": "Sentria"}]},
        },
        "components": [_component(asset) for asset in _ordered(report.get("crypto_assets", []))],
    }


def _ordered(assets: list[dict]) -> list[dict]:
    # Directory walk order is filesystem-dependent; sort so the same scan
    # always serializes to the same document.
    return sorted(assets, key=lambda a: (a["location"], a["line"], a["name"]))


def _component(asset: dict) -> dict:
    algorithm_properties = {"primitive": asset["primitive"]}
    if asset["parameter_set"]:
        algorithm_properties["parameterSetIdentifier"] = asset["parameter_set"]
    if asset["curve"]:
        algorithm_properties["curve"] = asset["curve"]
    # A static scan can't tell where the code will execute.
    algorithm_properties["executionEnvironment"] = "unknown"
    algorithm_properties["cryptoFunctions"] = asset["crypto_functions"]
    if asset["classical_security_level"] is not None:
        algorithm_properties["classicalSecurityLevel"] = asset["classical_security_level"]
    algorithm_properties["nistQuantumSecurityLevel"] = asset["nist_quantum_security_level"]

    return {
        "type": "cryptographic-asset",
        "bom-ref": asset["id"],
        "name": asset["name"],
        "cryptoProperties": {
            "assetType": "algorithm",
            "oid": asset["oid"],
            "algorithmProperties": algorithm_properties,
        },
        "properties": [
            {"name": "sentria:hndl-risk", "value": asset["hndl_risk"]},
            {"name": "sentria:usage", "value": asset["usage"]},
            {"name": "sentria:nist-deprecation", "value": asset["nist_deprecation"]},
            {"name": "sentria:recommended-migration", "value": asset["recommended_migration"]},
            {"name": "sentria:reference", "value": asset["reference"]},
        ],
        "evidence": {"occurrences": [{"location": asset["location"], "line": asset["line"]}]},
    }


def render_cbom(report: dict) -> str:
    return json.dumps(build_cbom(report), indent=2)


def write_cbom(report: dict, path: str | Path) -> None:
    Path(path).write_text(render_cbom(report), encoding="utf-8")
