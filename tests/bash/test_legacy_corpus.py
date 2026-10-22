"""Behavioral cases migrated from the previous implementation's corpus.

Provenance
----------
The source was the earlier judge's suite (``MUST_FLAG`` / ``MUST_STAY_QUIET`` /
``MAY_WARN``). Each case keeps its original label, expected rule ids and decision
in ``legacy`` so the claim stays traceable.

What is asserted
----------------
``expect`` started as implementation output at migration time. Reviewed corrections
(for example npm i being an install) replace those snapshots with contract results;
do not regenerate them from analyzer output to make a failing test pass.
The migrated subset is command-only, primarily POSIX-shaped,
runs with evidence disabled, and therefore asserts **lexical** results: the old
corpus read a real filesystem belonging to the previous implementation, so its
evidence answers cannot be reproduced here.

Legacy expectations this implementation does not meet are recorded as a mapping
from the old rule id to the current rules that would satisfy it:

``legacy_unmet``
    A genuine coverage gap: no detection for that shape exists yet.
``legacy_needs_evidence``
    The rule needs a content or stat read these fixtures deliberately disable, so
    its absence is expected rather than a gap.

Both are asserted absent, so the case fails as soon as one of the listed rules is
reported and the fixture must be moved forward instead of letting a closed gap
disappear. Some listed candidates are not reachable for a particular command
(for example a write-side injection case will never emit the read-side rule); such
an entry is inert rather than wrong, and closing that gap by adding a *new* rule
still requires a human to update the fixture.

``legacy_untracked`` is provenance only: old rule ids with no successor in the
current catalog, plus current-catalog ids this slice has not implemented.

``legacy_out_of_scope`` preserves expectations explicitly excluded by product
decisions (authored instruction text and staging without remote publication).
Those cases retain current positive/silent expectations; they are not gaps.

Not migrated: 67 cases that targeted non-shell tools (``write``, ``read``,
``web_fetch``, ``glob``, …), which a command-only API does not accept. The
Windows-shaped cases, which had no frontend at migration time, now live in
``windows_legacy_corpus.json`` and run under ``test_windows_legacy_corpus.py``.
"""
import json
from pathlib import Path
import jsonschema
import pytest
from command_inspector import Analyzer, AnalyzerConfig, Level
from command_inspector.catalog import RULES
from command_inspector.local_evidence import DisabledEvidenceProvider

CASES = json.loads((Path(__file__).parents[1] / "fixtures").joinpath("legacy_corpus.json").read_text(encoding="utf-8"))


def _candidates(case, field):
    for legacy_rule, candidates in case.get(field, {}).items():
        yield legacy_rule, sorted(candidates)


def test_gap_annotations_reference_real_rules():
    """A typo in a recorded gap would make its assertion vacuous."""
    for case in CASES:
        for field in ("legacy_unmet", "legacy_needs_evidence"):
            for legacy_rule, candidates in _candidates(case, field):
                unknown = set(candidates) - RULES.keys()
                assert not unknown, (
                    f"{case['name']}: '{legacy_rule}' names rules outside the catalog: {sorted(unknown)}")


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["name"])
def test_legacy_corpus(case):
    analyzer = Analyzer(AnalyzerConfig.from_mapping(case.get("config", {})), evidence=DisabledEvidenceProvider())
    report = analyzer.analyze_report(case["command"], case.get("cwd", "/srv/app"),
                                     shell=case.get("shell", "bash"), env=case.get("env"))
    expected = case["expect"]
    assert sorted(f.rule for f in report.findings) == sorted(expected["rules"]), (
        f"{case['name']} (legacy: {case['legacy']['label']})")
    assert report.num_findings == expected["count"]
    assert report.level.name == expected["level"]

    emitted = {f.rule for f in report.findings}
    for field, advice in (("legacy_unmet", "move it into expect.rules and remove it from legacy_unmet"),
                          ("legacy_needs_evidence", "update this fixture")):
        for legacy_rule, candidates in _candidates(case, field):
            hit = sorted(emitted & set(candidates))
            assert not hit, (
                f"{case['name']}: legacy '{legacy_rule}' is now satisfied by {hit}; {advice}")

    wire = report.to_dict()
    jsonschema.validate(wire, analyzer.report_schema())
    if expected["count"]:
        assert Level[wire["level"]] == max(Level[f["level"]] for f in wire["findings"])
    else:
        assert wire == {}
