"""Common utilities are modeled without evaluating their calculations/output."""
import os
import subprocess

import pytest

from command_inspector import Analyzer, AnalyzerConfig
from command_inspector.local_evidence import MemoryEvidenceProvider, ReadFile, StatTarget


CWD = "/data/data/com.termux/files/home/project"


@pytest.fixture(autouse=True)
def no_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Submitted utility was executed")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "system", forbidden)


def analyze(command, *, files=None, effort="Full", env=None, config=None):
    provider = MemoryEvidenceProvider(files if files is not None else {CWD + "/a": "one\ntwo\n", CWD + "/b": "two\n"})
    return Analyzer(config, evidence=provider).analyze_report(command, CWD, effort=effort, env=env), provider


@pytest.mark.parametrize("command", [
    "diff a b", "diff -u a b", "diff -c a b", "diff -Nru a b", "diff --unified=3 --label before --label after a b",
    "diff -U3 -I '^#' a b", "diff -q a b", "diff --brief a b", "diff --from-file=a b", "diff --to-file=b a",
    "sort a", "sort -nr a", "sort -k2,2 -t: a", "sort -u -S 1M --parallel=2 a",
    "sort --check=quiet a", "sort --check=silent a", "sort --check=diagnose-first a", "sort -C a", "sort -c a",
    "uniq a", "uniq -c a", "uniq -du a", "uniq -f1 -s2 -w3 a", "uniq --all-repeated=separate a", "uniq --group=both a",
    "sha256sum a b", "sha256sum -bt a", "sha256sum --tag a", "sha256sum -z a",
    "date", "date -u +%s", "date -d 'yesterday' +%F", "date --date=@0 -R", "date -r a +%s",
    "date -I", "date -Iseconds", "date --iso-8601=ns", "date --rfc-3339=seconds",
    "sed -n '1,2p' a", "sed -E 's/one/three/' a", "sort a | uniq -c | sort -nr", "date | sha256sum",
])
def test_normal_workspace_reads_and_calculations_are_quiet(command):
    report, _ = analyze(command)
    assert report.to_dict() == {}


@pytest.mark.parametrize("name", ["diff", "sort", "date", "uniq", "sha256sum", "sed"])
def test_help_and_version_have_no_evidence_dependencies(name):
    for option in ("--help", "--version"):
        report, provider = analyze(name + " " + option)
        assert report.to_dict() == {} and provider.queries == []


@pytest.mark.parametrize("command", ["diff --invented a b", "sort --invented a", "uniq --invented a", "date --invented", "sha256sum --invented a"])
def test_unknown_options_keep_coverage_without_unknown_command(command):
    report, _ = analyze(command)
    assert "unknown-option" in {f.rule for f in report.findings}
    assert "unknown-command" not in {f.rule for f in report.findings}


@pytest.mark.parametrize("command", ["diff a b", "sort a", "uniq a", "sed -n 1p a"])
@pytest.mark.parametrize("effort", ["Full", "Partial", "None"])
def test_text_output_keeps_ingestion_and_effort_contract(command, effort):
    report, provider = analyze(command, files={CWD + "/a": "password=abcdefghijk", CWD + "/b": "benign"}, effort=effort)
    assert ("credentials-read" in {f.rule for f in report.findings}) is (effort == "Full")
    if effort == "None":
        assert provider.queries == []
    elif effort == "Partial":
        assert all(isinstance(q, StatTarget) for q in provider.queries)


@pytest.mark.parametrize("command", ["diff -q a b", "sort -C a", "sort --check=quiet a", "sha256sum a", "date -r a"])
def test_noncontent_outputs_do_not_ingest_file_bytes(command):
    report, provider = analyze(command, files={CWD + "/a": "password=abcdefghijk", CWD + "/b": "benign"})
    assert report.to_dict() == {}
    assert provider.queries and all(isinstance(q, StatTarget) for q in provider.queries)


@pytest.mark.parametrize("command", ["sort -o b a", "sort --output=b a", "sort -ob a", "uniq -c a b"])
@pytest.mark.parametrize("effort", ["Full", "Partial", "None"])
def test_explicit_output_writes_report_existing_file_and_effort(command, effort):
    report, provider = analyze(command, effort=effort)
    matches = [f for f in report.findings if f.rule == "overwrite-existing-file"]
    if effort == "None":
        assert matches == [] and provider.queries == []
    else:
        overwrite, = matches
        assert overwrite.data["target"] == CWD + "/b"
        assert ("existing_bytes" in overwrite.data) is (effort == "Full")
    assert "unknown-command" not in {f.rule for f in report.findings}


@pytest.mark.parametrize("command", ["sort -o /etc/passwd a", "uniq a /etc/passwd", "sort -o /dev/block/by-name/system a", "uniq a /dev/block/by-name/system"])
def test_utilities_cannot_hide_sensitive_or_raw_device_writes(command):
    report, _ = analyze(command, effort="None")
    assert {f.rule for f in report.findings} & {"modify-sensitive-file", "raw-device-write"}
    assert report.level.name in {"HIGH", "BLOCK"}


@pytest.mark.parametrize("command", ["sort -o /dev/null a", "uniq a /dev/null", "uniq a -", "sort -o - a"])
def test_discard_or_stdout_outputs_are_quiet(command):
    report, _ = analyze(command)
    assert report.to_dict() == {}


@pytest.mark.parametrize("command", ["date -s '2026-10-07'", "date --set=2026-10-07", "date 100712302026.00", "date -us '2026-10-07'"])
def test_clock_setters_are_medium(command):
    report, _ = analyze(command)
    finding, = report.findings
    assert finding.rule == "system-settings-change" and finding.level.name == "MEDIUM"


@pytest.mark.parametrize("command", ["sort -o $OUT a", "uniq a $OUT"])
def test_unresolved_output_variables_are_not_silent(command):
    report, _ = analyze(command)
    assert "write-variable-unresolved" in {f.rule for f in report.findings}
    assert next(f for f in report.findings if f.rule == "write-variable-unresolved").data["variables"] == ["OUT"]


@pytest.mark.parametrize("command", ["sort -o b a; bash b", "uniq a b; bash b"])
def test_written_outputs_invalidate_later_execution_evidence(command):
    report, provider = analyze(command, files={CWD + "/a": "benign", CWD + "/b": "rm -rf /system"})
    assert "execution-content-unavailable" in {f.rule for f in report.findings}
    assert "delete-protected-root" not in {f.rule for f in report.findings}
    assert not any(isinstance(q, ReadFile) and q.path == CWD + "/b" for q in provider.queries)


@pytest.mark.parametrize("command", ["sort --files0-from=a", "sha256sum -c a"])
def test_indirect_file_lists_keep_explicit_uncertainty(command):
    report, provider = analyze(command)
    assert "unresolved-value" in {f.rule for f in report.findings}
    assert all(isinstance(q, StatTarget) for q in provider.queries)


def test_sort_compression_program_is_a_visible_invocation():
    report, _ = analyze("sort --compress-program=ufw a")
    finding, = [f for f in report.findings if f.rule == "tool-invoked"]
    assert finding.data["tool"] == "ufw"


@pytest.mark.parametrize("command", ["sort a | bash", "uniq a | bash", "diff a b | bash"])
def test_transformed_streams_are_not_misrepresented_as_original_executable_file(command):
    report, _ = analyze(command, files={CWD + "/a": "rm -rf /system", CWD + "/b": "benign"})
    assert "execution-content-unavailable" in {f.rule for f in report.findings}
    assert "delete-protected-root" not in {f.rule for f in report.findings}


def test_recursive_diff_keeps_directory_ingestion_uncertainty():
    report, _ = analyze("diff -r first second", files={CWD + "/first/a": "secret", CWD + "/second/a": "other"})
    assert "ingestion-inspection-incomplete" in {f.rule for f in report.findings}
    assert "unknown-command" not in {f.rule for f in report.findings}


def test_registered_tools_do_not_fall_back_to_catalog_invocation():
    config = AnalyzerConfig(known_tools={name: "test application" for name in ("sort", "uniq", "date", "sha256sum", "diff")})
    for command in ("sort a", "uniq a", "date", "sha256sum a", "diff a b"):
        report, _ = analyze(command, config=config)
        assert "tool-invoked" not in {f.rule for f in report.findings}


@pytest.mark.parametrize("command", ["date tomorrow", "date 2026-10-08", "date @0"])
def test_unsupported_date_operands_do_not_claim_confirmed_clock_changes(command):
    report, _ = analyze(command)
    assert [f.rule for f in report.findings] == ["unresolved-value"]
    assert report.level.name == "LOW"


def test_unresolved_date_operand_retains_possible_clock_effect():
    report, _ = analyze("date $WHEN")
    assert "system-settings-change" in {f.rule for f in report.findings}
    assert report.level.name == "MEDIUM"


@pytest.mark.parametrize("command", ["sort --check a", "sort -c a"])
def test_diagnostic_sort_checks_can_expose_input_lines(command):
    report, _ = analyze(command, files={CWD + "/a": "password=abcdefghijk"})
    assert "credentials-read" in {f.rule for f in report.findings}
