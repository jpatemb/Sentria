import json
from pathlib import Path

import jsonschema
import pytest
from referencing import Registry, Resource

from checks.crypto_check import scan_crypto
from context.report import build_report
from reporters.cbom_reporter import build_cbom
from reporters.terminal import render_terminal_report

VENDOR_DIR = Path(__file__).resolve().parent.parent / "schemas" / "vendor" / "cyclonedx"
GOLDEN = Path(__file__).resolve().parent / "golden" / "cbom_basic.json"
FIXED_TIMESTAMP = "2026-11-16T00:00:00+00:00"


def _validator() -> jsonschema.Draft7Validator:
    # bom-1.6 $refs spdx.schema.json and jsf-0.82.schema.json. Both must be
    # registered: a CBOM with no license or signature fields validates
    # without them, then fails the first time either field appears.
    schemas = {
        name: json.loads((VENDOR_DIR / name).read_text(encoding="utf-8"))
        for name in ("bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json")
    }
    registry = Registry().with_resources(
        (schema["$id"], Resource.from_contents(schema)) for schema in schemas.values()
    )
    return jsonschema.Draft7Validator(schemas["bom-1.6.schema.json"], registry=registry)


def _fixture_repo(root: Path) -> None:
    (root / "config").mkdir()
    (root / "config" / "tls.conf").write_text("listen 443;\nssl_ciphers ECDHE-RSA-AES256-GCM-SHA384;\n")
    (root / "keys.py").write_text("key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n")
    (root / "sign.py").write_text("signer = ec.ECDSA(hashes.SHA256())\n")
    (root / "dh.pem").write_text("-----BEGIN DH PARAMETERS-----\n")


def _report_for(root: str | Path) -> dict:
    result = scan_crypto(root)
    report = build_report(str(root), result.findings, crypto_assets=result.assets)
    report["generated_at"] = FIXED_TIMESTAMP
    return report


def test_emitted_cbom_validates_against_cyclonedx_1_6(tmp_path):
    _fixture_repo(tmp_path)

    cbom = build_cbom(_report_for(tmp_path))

    _validator().validate(cbom)


def test_validator_rejects_unknown_key_in_crypto_properties(tmp_path):
    _fixture_repo(tmp_path)
    cbom = build_cbom(_report_for(tmp_path))
    cbom["components"][0]["cryptoProperties"]["quantumVulnerability"] = {"vulnerable": True}

    with pytest.raises(jsonschema.ValidationError, match="quantumVulnerability"):
        _validator().validate(cbom)


def test_validator_resolves_spdx_and_jsf_refs(tmp_path):
    _fixture_repo(tmp_path)
    cbom = build_cbom(_report_for(tmp_path))
    cbom["components"][0]["licenses"] = [{"license": {"id": "Apache-2.0"}}]
    # JSF's algorithm is oneOf(enum of names, string with format: uri). Without
    # a format checker a name like "ES256" satisfies both branches and fails
    # oneOf, so use the URI form, which matches exactly one.
    cbom["signature"] = {"algorithm": "https://example.com/sig-alg", "value": "abc"}

    _validator().validate(cbom)

    bad_license = json.loads(json.dumps(cbom))
    bad_license["components"][0]["licenses"] = [{"license": {"id": "NOT-A-REAL-SPDX-ID"}}]
    with pytest.raises(jsonschema.ValidationError):
        _validator().validate(bad_license)

    bad_signature = json.loads(json.dumps(cbom))
    del bad_signature["signature"]["value"]
    with pytest.raises(jsonschema.ValidationError):
        _validator().validate(bad_signature)


def test_findings_and_cbom_components_come_from_the_same_scan(tmp_path):
    _fixture_repo(tmp_path)

    report = _report_for(tmp_path)
    cbom = build_cbom(report)

    assert len(report["findings"]) == len(cbom["components"]) == 4
    assert {f["id"] for f in report["findings"]} == {c["bom-ref"] for c in cbom["components"]}
    assert "Quantum-vulnerable cryptography: 4 use(s) found" in render_terminal_report(report)


def test_full_cbom_matches_golden_file(tmp_path, monkeypatch):
    _fixture_repo(tmp_path)
    monkeypatch.chdir(tmp_path)

    cbom = build_cbom(_report_for("."))

    assert cbom == json.loads(GOLDEN.read_text(encoding="utf-8"))


def test_report_without_crypto_assets_yields_empty_valid_cbom():
    report = build_report("empty", [])
    report["generated_at"] = FIXED_TIMESTAMP

    cbom = build_cbom(report)

    assert cbom["components"] == []
    _validator().validate(cbom)
