import json
from pathlib import Path
import jsonschema
import pytest
from command_inspector import Analyzer, AnalyzerConfig, Level
from command_inspector.local_evidence import DisabledEvidenceProvider, MemoryEvidenceProvider

CASES = json.loads((Path(__file__).parents[1] / "fixtures").joinpath("behavior.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["name"])
def test_behavior(case):
    provider = MemoryEvidenceProvider(case.get("files", {})) if case.get("local_evidence", True) else DisabledEvidenceProvider()
    analyzer = Analyzer(AnalyzerConfig.from_mapping(case.get("config", {})), evidence=provider)
    report = analyzer.analyze_report(case["command"], case.get("cwd", "/work/project"), shell=case.get("shell", "bash"), env=case.get("env"))
    expected = case["expect"]
    assert sorted(f.rule for f in report.findings) == sorted(expected["rules"])
    assert report.num_findings == expected["count"]
    assert report.level.name == expected["level"]
    wire = report.to_dict()
    jsonschema.validate(wire, analyzer.report_schema())
    if not expected["count"]:
        assert wire == {}
        assert analyzer.analyze_json(case["command"], "/work/project", shell=case.get("shell", "bash"), env=case.get("env")) == "{}"
    else:
        assert len(wire["findings"]) == wire["num_findings"]
        assert Level[wire["level"]] == max(Level[f["level"]] for f in wire["findings"])
    catalog = {rule["rule"]: rule for rule in analyzer.rule_catalog()["rules"]}
    for finding in report.findings:
        assert finding.level.name in catalog[finding.rule]["levels"]
        jsonschema.validate(finding.to_dict()["data"], catalog[finding.rule]["data_schema"])
    if "target" in expected:
        assert any(f.data.get("target") == expected["target"] for f in report.findings)
