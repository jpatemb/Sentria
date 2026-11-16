import json
from pathlib import Path

import jsonschema
from referencing import Registry, Resource

from checks.crypto_check import scan_crypto
from context.findings import Finding
from context.report import build_report

SCHEMAS_DIR = Path(__file__).resolve().parent.parent / "schemas"


def _load_schema(name: str) -> dict:
    return json.loads((SCHEMAS_DIR / name).read_text(encoding="utf-8"))


def _report_validator() -> jsonschema.Draft7Validator:
    registry = Registry().with_resources(
        (name, Resource.from_contents(_load_schema(name)))
        for name in ("finding.schema.json", "crypto_asset.schema.json")
    )
    return jsonschema.Draft7Validator(_load_schema("report.schema.json"), registry=registry)


def test_finding_conforms_to_schema():
    finding = Finding(
        check="secrets_check",
        category="secrets",
        severity="high",
        description="d",
        evidence="e",
        remediation="r",
    )

    jsonschema.validate(finding.to_dict(), _load_schema("finding.schema.json"))


def test_report_conforms_to_schema():
    findings = [
        Finding(check="secrets_check", category="secrets", severity="critical",
                description="d", evidence="e", remediation="r"),
    ]
    report = build_report("target-dir", findings, narrative="summary text")

    _report_validator().validate(report)


def test_report_with_crypto_assets_conforms_to_schema(tmp_path):
    (tmp_path / "keys.py").write_text("rsa.generate_private_key(key_size=2048)\nec.ECDSA(h)\n")
    result = scan_crypto(tmp_path)
    report = build_report(str(tmp_path), result.findings, crypto_assets=result.assets)

    assert len(report["crypto_assets"]) == 2
    _report_validator().validate(report)
