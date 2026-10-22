"""Windows cases migrated from the previous implementation's corpus.

Provenance
----------
The source is the same earlier judge's suite as ``legacy_corpus.json``
(``MUST_FLAG`` / ``MUST_STAY_QUIET`` / ``MAY_WARN``), restricted to the cases whose
commands are Windows-shaped. Each keeps its original label, expected rule ids and
decision in ``legacy`` so the claim stays traceable. Regenerate with
``python /home/user/Projects/Temp/tools/migrate_legacy_corpus.py``; that tool rewrites
this fixture on every run but refuses to rewrite ``legacy_corpus.json`` unless asked,
because that one has since been hand-reviewed. This Windows fixture is now also
hand-reviewed: preserve its review_note, target_rules and forbidden_rules when
importing future changes rather than overwriting it with generated mappings.

What is asserted
----------------
This fixture states a **goal, not a snapshot**, and generation never consults the
analyzer. An expectation copied from the implementation cannot report a defect, so a
case the implementation does not satisfy is meant to **fail** here and stay failing
until the detection exists. There is deliberately no ``expect`` block:

``target_rules``
    For each old detector, the current rules that would satisfy it. The new detectors
    are shaped differently, so any member of the set counts. A missing detection fails
    the case with the old rule, the candidate rules and the actual findings.
``target_max_level``
    The old quiet groups declare no rules, only "the old suite raised no card". Against
    the five levels that is a ceiling rather than an exact match: ``must-stay-quiet``
    never went past a line, ``may-warn`` tolerated a warning. A benign command levelled
    above its ceiling fails, which is how over-levelling becomes visible.

Two caveats the fixtures encode deliberately:

* Evidence is disabled, so these are lexical results only. The old suite ran against a
  real Windows filesystem, so content and stat answers cannot be reproduced here. Old
  detectors whose only candidate rules need such a read are recorded in
  ``legacy_needs_evidence`` and are **not** asserted, since they would fail by
  construction.
* No ``env`` is supplied, exactly as in the Bash migration. ``$HOME`` and
  ``%USERPROFILE%`` cases are therefore unresolved by construction; supplying
  ``UserProfile`` would exercise a different path and belongs in its own fixture.

The old suite was host-adaptive and declared a POSIX cwd on this host, so a Windows
counterpart is not knowable from the cases themselves. Regeneration substitutes the
suite's own host constants and uses its ``WIN_CWD``; cases that reference a path with
no Windows counterpart are not migrated at all.
"""
import json
import re
from pathlib import Path
import jsonschema
import pytest
from command_inspector import Analyzer, AnalyzerConfig, Level
from command_inspector.catalog import RULES
from command_inspector.local_evidence import DisabledEvidenceProvider

CASES = json.loads((Path(__file__).parents[1] / "fixtures").joinpath("windows_legacy_corpus.json").read_text(encoding="utf-8"))
WINDOWS_CWD = re.compile(r"^[A-Za-z]:\\")
ORDER = {level.name: rank for rank, level in enumerate(Level)}


def findings_of(case):
    analyzer = Analyzer(AnalyzerConfig.from_mapping(case.get("config", {})), evidence=DisabledEvidenceProvider())
    report = analyzer.analyze_report(case["command"], case["cwd"], shell=case["shell"], env=case.get("env"))
    return analyzer, report, sorted(f.rule for f in report.findings)


def test_fixture_states_goals_not_snapshots():
    """A snapshot copied from the implementation would make every case vacuous."""
    offenders = [case["name"] for case in CASES if "expect" in case]
    assert not offenders, f"these cases carry an implementation snapshot instead of a goal: {offenders}"
    assert len(CASES) > 50, "the Windows corpus should not silently shrink"
    assert any(case.get("target_rules") for case in CASES)


def test_fixture_is_windows_shaped():
    """A bad regeneration would quietly turn these into POSIX cases."""
    for case in CASES:
        assert case["shell"] in {"cmd", "powershell"}, case["name"]
        assert WINDOWS_CWD.match(case["cwd"]), f"{case['name']}: cwd {case['cwd']!r} is not a Windows path"


def test_target_annotations_reference_real_rules():
    """A typo in a target would make its assertion vacuous."""
    for case in CASES:
        for field in ("target_rules", "legacy_needs_evidence"):
            for legacy_rule, candidates in case.get(field, {}).items():
                unknown = set(candidates) - RULES.keys()
                assert not unknown, (
                    f"{case['name']}: '{legacy_rule}' names rules outside the catalog: {sorted(unknown)}")
                assert candidates, f"{case['name']}: '{legacy_rule}' has an empty candidate set"
        assert not set(case.get("forbidden_rules", [])) - RULES.keys(), case["name"]


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["name"])
def test_windows_legacy_corpus(case):
    analyzer, report, emitted = findings_of(case)
    legacy = case["legacy"]
    assert not set(emitted) & set(case.get("forbidden_rules", [])), case["name"]

    unmet = []
    for legacy_rule, candidates in case.get("target_rules", {}).items():
        if not set(emitted) & set(candidates):
            unmet.append(f"legacy '{legacy_rule}' expects one of {sorted(candidates)}")
    assert not unmet, (
        f"{case['name']} ({legacy['label']!r}, old decision {legacy['decision']}) is not met:\n  "
        + "\n  ".join(unmet)
        + f"\n  actual findings: {emitted or ['<none>']} at level {report.level.name}")

    ceiling = case.get("target_max_level")
    if ceiling:
        assert ORDER[report.level.name] <= ORDER[ceiling], (
            f"{case['name']} ({legacy['label']!r}) is a {legacy['group']} case but reached "
            f"{report.level.name}, above its {ceiling} ceiling; findings: {emitted}")

    wire = report.to_dict()
    jsonschema.validate(wire, analyzer.report_schema())
    if report.findings:
        assert Level[wire["level"]] == max(Level[f["level"]] for f in wire["findings"])
    else:
        assert wire == {}
