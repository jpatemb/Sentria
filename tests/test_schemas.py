import json
from pathlib import Path

import jsonschema

from context.findings import Finding
from context.report import build_report

SCHEMAS_DIR = Path(__file__).resolve().parent.parent / "schemas"


def _load_schema(name: str) -> dict:
    return json.loads((SCHEMAS_DIR / name).read_text(encoding="utf-8"))


def _resolver():
    finding_schema = _load_schema("finding.schema.json")
    store = {"finding.schema.json": finding_schema}
    return jsonschema.RefResolver.from_schema(finding_schema, store=store)


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

    report_schema = _load_schema("report.schema.json")
    resolver = _resolver()

    jsonschema.validate(report, report_schema, resolver=resolver)
