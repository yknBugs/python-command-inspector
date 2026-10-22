"""Filesystem effort is a hard ceiling across adapters and nested sources."""
import builtins
import json
import os
import subprocess

import pytest

from command_inspector import Analyzer, AnalyzerConfig, EvidenceEffort, InputError, analyze, analyze_json
from command_inspector.local_evidence import (
    CachedEvidenceProvider, EvidenceAnswer, EvidenceStatus, MatchTargets,
    LocalEvidenceProvider, MemoryEvidenceProvider, ReadFile, StatTarget, SummarizeDeletion,
)


@pytest.fixture(autouse=True)
def no_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Submitted command was executed")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "system", forbidden)


def check(command, files=None, *, effort="Full", shell="bash", config=None, env=None):
    provider = MemoryEvidenceProvider(files or {})
    cwd = "/work" if shell == "bash" else r"C:\work"
    report = Analyzer(config, evidence=provider).analyze_report(command, cwd, shell=shell, effort=effort, env=env)
    return report, provider


def entries(report, rule):
    return [f for f in report.findings if f.rule == rule]


SOURCES = [
    ("bash", "bash evil.txt", "/work/evil.txt", "rm -rf /etc"),
    ("bash", "cat evil.txt | bash", "/work/evil.txt", "rm -rf /etc"),
    ("bash", "bash < evil.txt", "/work/evil.txt", "rm -rf /etc"),
    ("bash", "cat evil.txt | timeout 2 env -i bash", "/work/evil.txt", "rm -rf /etc"),
    ("powershell", "Get-Content evil.txt | pwsh -Command -", r"C:\work\evil.txt", "Remove-Item -Recurse -Force C:\\"),
    ("powershell", "Get-Content -Raw evil.txt | pwsh -File -", r"C:\work\evil.txt", "Remove-Item -Recurse -Force C:\\"),
    ("powershell", "pwsh -File evil.ps1", r"C:\work\evil.ps1", "Remove-Item -Recurse -Force C:\\"),
    ("powershell", "Get-Content evil.txt | python -", r"C:\work\evil.txt", "import os; os.remove('C:/victim')"),
    ("cmd", "type evil.txt | cmd", r"C:\work\evil.txt", "rd /s /q C:\\"),
    ("cmd", "type evil.txt | pwsh -Command -", r"C:\work\evil.txt", "Remove-Item -Recurse -Force C:\\"),
    ("cmd", "type evil.txt | python -", r"C:\work\evil.txt", "import os; os.remove('C:/victim')"),
    ("cmd", "evil.cmd", r"C:\work\evil.cmd", "rd /s /q C:\\"),
]


@pytest.mark.parametrize("shell,command,path,content", SOURCES)
@pytest.mark.parametrize("effort", list(EvidenceEffort))
def test_direct_and_stream_sources_share_effort(shell, command, path, content, effort):
    report, provider = check(command, {path: content}, shell=shell, effort=effort)
    if effort is EvidenceEffort.FULL:
        assert entries(report, "delete-protected-root") or entries(report, "delete-outside-workspace")
        assert [q.path for q in provider.queries if isinstance(q, ReadFile)] == [path]
        assert not entries(report, "execution-content-unavailable")
    else:
        assert entries(report, "execution-content-unavailable")
        assert not any(f.rule.startswith("delete-") for f in report.findings)
        assert not any(isinstance(q, ReadFile) for q in provider.queries)
        assert all(isinstance(q, StatTarget) for q in provider.queries)
        assert bool(provider.queries) is (effort is EvidenceEffort.PARTIAL)
    assert entries(report, "uses-interpreter")
    assert not entries(report, "unsupported-syntax")


@pytest.mark.parametrize("shell,command,path,content", SOURCES)
@pytest.mark.parametrize("effort", list(EvidenceEffort))
def test_missing_execution_sources_require_evidence(shell, command, path, content, effort):
    report, provider = check(command, shell=shell, effort=effort)
    assert entries(report, "execution-content-unavailable")
    assert bool(entries(report, "execute-target-missing")) is (effort is not EvidenceEffort.NONE)
    if effort is EvidenceEffort.NONE:
        assert provider.queries == []


@pytest.mark.parametrize("shell,command,path,content", [
    ("bash", "cat entry.txt | bash", "/work/entry.txt", "bash nested.sh > out.log"),
    ("powershell", "Get-Content entry.txt | pwsh -Command -", r"C:\work\entry.txt", "pwsh -File nested.ps1 > out.log"),
    ("cmd", "type entry.txt | cmd", r"C:\work\entry.txt", "nested.cmd > out.log"),
])
def test_file_contents_degrade_to_partial_for_nested_dependencies(shell, command, path, content):
    directory = "/work/" if shell == "bash" else "C:\\work\\"
    nested = directory + ("nested.sh" if shell == "bash" else "nested.ps1" if shell == "powershell" else "nested.cmd")
    report, provider = check(command, {path: content, nested: "echo benign", directory + "out.log": "old log"}, shell=shell)
    assert [q.path for q in provider.queries if isinstance(q, ReadFile)] == [path]
    assert entries(report, "execution-content-unavailable")[0].data["effort"] == "Partial"
    overwrite, = entries(report, "overwrite-existing-file")
    assert "existing_bytes" not in overwrite.data
    assert {q.path for q in provider.queries if isinstance(q, StatTarget)} >= {nested, directory + "out.log"}
    assert not entries(report, "delete-protected-root")


@pytest.mark.parametrize("shell,command,path", [
    ("bash", "echo hello > existing", "/work/existing"),
    ("powershell", "Write-Output hello > existing", r"C:\work\existing"),
    ("cmd", "echo hello > existing", r"C:\work\existing"),
])
@pytest.mark.parametrize("effort", list(EvidenceEffort))
def test_overwrite_details_depend_on_effort(shell, command, path, effort):
    report, provider = check(command, {path: "old content"}, shell=shell, effort=effort)
    if effort is EvidenceEffort.NONE:
        assert not entries(report, "overwrite-existing-file")
        assert provider.queries == []
    else:
        overwrite, = entries(report, "overwrite-existing-file")
        assert ("existing_bytes" in overwrite.data) is (effort is EvidenceEffort.FULL)
        if effort is EvidenceEffort.FULL:
            assert overwrite.data["existing_bytes"] == len("old content")


@pytest.mark.parametrize("command", ["cat $ENV/readme.md | less", "cat $ENV/readme.md | less -R", "cd /tmp && mkdir test"])
@pytest.mark.parametrize("effort", list(EvidenceEffort))
def test_metadata_only_consumers_never_read_content(command, effort):
    report, provider = check(command, {"/work/docs/readme.md": "password=abcdefghij"}, effort=effort, env={"ENV": "/work/docs"})
    assert not entries(report, "credentials-read")
    assert all(isinstance(q, StatTarget) for q in provider.queries)
    assert bool(provider.queries) is (effort is not EvidenceEffort.NONE)
    assert not entries(report, "unknown-command")


@pytest.mark.parametrize("shell,command,path", [
    ("bash", "cat data", "/work/data"),
    ("powershell", "Get-Content data", r"C:\work\data"),
    ("cmd", "type data", r"C:\work\data"),
])
@pytest.mark.parametrize("effort", list(EvidenceEffort))
def test_ingestion_follows_same_content_ceiling(shell, command, path, effort):
    report, provider = check(command, {path: "password=abcdefghij"}, shell=shell, effort=effort)
    assert bool(entries(report, "credentials-read")) is (effort is EvidenceEffort.FULL)
    assert bool(entries(report, "ingestion-inspection-incomplete")) is (effort is not EvidenceEffort.FULL)
    if effort is EvidenceEffort.NONE:
        assert provider.queries == []


@pytest.mark.parametrize("shell,command,path", [
    ("bash", "python script.py > output.log && cat output.log | less", "/work/output.log"),
    ("powershell", "python script.py > output.log; Get-Content output.log | pwsh -Command -", r"C:\work\output.log"),
    ("cmd", "python script.py > output.log & type output.log | cmd", r"C:\work\output.log"),
])
@pytest.mark.parametrize("effort", list(EvidenceEffort))
def test_dirty_files_never_use_stale_metadata_or_contents(shell, command, path, effort):
    report, provider = check(command, {path: "rm -rf /etc"}, shell=shell, effort=effort)
    assert not entries(report, "delete-protected-root")
    assert not any(isinstance(q, ReadFile) and q.path == path for q in provider.queries)
    assert len([q for q in provider.queries if isinstance(q, StatTarget) and q.path == path]) <= 1
    assert not any(f.rule == "execute-target-missing" and f.data["target"] == path for f in report.findings)


@pytest.mark.parametrize("query", [ReadFile("/work/x", 10), StatTarget("/work/x"),
                                      MatchTargets("/work", "*", 10), SummarizeDeletion("/work/x", 10)])
def test_cache_policy_cannot_leak_richer_answers(query):
    provider = MemoryEvidenceProvider({"/work/x": "password=secret"})
    cache = CachedEvidenceProvider(provider, 100, 100)
    cache.answer(query)
    queries = list(provider.queries)
    none = cache.answer(query, effort="None")
    assert none.reason == "effort_none" and none.data == {}
    partial = cache.answer(query, effort="Partial")
    assert "bytes" not in partial.data and "size" not in partial.data
    if isinstance(query, ReadFile):
        assert partial.reason == "effort_partial" and partial.data == {}
    assert "logical_bytes" not in partial.data
    assert provider.queries == queries


WILDCARD_DELETIONS = [
    ("bash", "rm -rf cache/*", "/work/cache/", 1),
    ("powershell", r"Remove-Item -Recurse .\cache\*", "C:\\work\\cache\\", 1),
    ("cmd", r"del /s cache\*", "C:\\work\\cache\\", 0),
]


def assert_no_byte_evidence(value):
    if isinstance(value, dict):
        assert not {"bytes", "size", "logical_bytes", "existing_bytes"} & value.keys()
        for item in value.values():
            assert_no_byte_evidence(item)
    elif isinstance(value, (tuple, list)):
        for item in value:
            assert_no_byte_evidence(item)


@pytest.mark.parametrize("shell,command,base,directories", WILDCARD_DELETIONS)
@pytest.mark.parametrize("effort", list(EvidenceEffort))
def test_wildcard_selection_and_counts_are_metadata(shell, command, base, directories, effort):
    files = {base + "a": "a", base + "sub" + ("/" if shell == "bash" else "\\") + "b": "bb"}
    report, provider = check(command, files, shell=shell, effort=effort)
    if effort is EvidenceEffort.NONE:
        assert provider.queries == []
        assert entries(report, "delete-variable-unresolved")
        return
    deletion, = entries(report, "delete-inside-workspace")
    assert deletion.data["files"] == 2 and deletion.data["directories"] == directories
    assert deletion.data["match_count"] == 2 and deletion.data["matches_complete"]
    assert deletion.data["counts_complete"] and deletion.data["affected_paths_complete"]
    assert set(files) <= set(deletion.data["affected_paths"])
    assert any(isinstance(q, MatchTargets) for q in provider.queries)
    assert any(isinstance(q, SummarizeDeletion) for q in provider.queries)
    assert not any(isinstance(q, ReadFile) for q in provider.queries)
    if effort is EvidenceEffort.PARTIAL:
        assert_no_byte_evidence(report.to_dict())
    else:
        assert deletion.data["logical_bytes"] == 3


def test_partial_root_wildcard_reports_concrete_targets_without_bytes():
    report, provider = check("rm /*", {"/a": "abc", "/b": "xy"}, effort="Partial")
    deletion, = entries(report, "delete-outside-workspace")
    assert deletion.data["matched_targets"] == ["/a", "/b"]
    assert deletion.data["files"] == 2 and deletion.data["directories"] == 0
    assert_no_byte_evidence(report.to_dict())
    assert not any(isinstance(q, ReadFile) for q in provider.queries)


@pytest.mark.parametrize("query", [MatchTargets("/work", "*", 100), SummarizeDeletion("/work/tree", 100, recursive=True)])
def test_partial_cached_enumeration_preserves_paths_counts_and_completeness(query):
    provider = MemoryEvidenceProvider({"/work/tree/a": "secret"})
    cache = CachedEvidenceProvider(provider, 100, 100)
    full = cache.answer(query, effort="Full")
    queries = list(provider.queries)
    partial = cache.answer(query, effort="Partial")
    assert partial.status == full.status and partial.complete == full.complete
    assert partial.reason == full.reason
    expected = {key: value for key, value in full.data.items() if key != "logical_bytes"}
    assert partial.data == expected
    assert provider.queries == queries
    assert_no_byte_evidence(partial.data)


def test_partial_dirty_wildcard_base_cannot_enumerate_stale_targets():
    report, provider = check("echo changed > cache/a; rm cache/*", {"/work/cache/a": "old"}, effort="Partial")
    deletion, = entries(report, "delete-variable-unresolved")
    assert deletion.data["reason"] == "may_have_changed_earlier"
    assert not deletion.data["matches_complete"]
    assert not any(isinstance(q, MatchTargets) for q in provider.queries)
    assert_no_byte_evidence(report.to_dict())


@pytest.mark.parametrize("config,reason", [
    (AnalyzerConfig(wildcard_matches=1), "match_limit"),
    (AnalyzerConfig(directory_entries=2), "entry_limit"),
])
def test_partial_wildcard_keeps_incomplete_selection_explicit(config, reason):
    report, _ = check("rm *.tmp", {f"/work/{i}.tmp": "abc" for i in range(5)}, effort="Partial", config=config)
    deletion, = entries(report, "delete-variable-unresolved")
    assert deletion.data["matched_targets"]
    assert deletion.data["reason"] == reason
    assert not deletion.data["matches_complete"] and not deletion.data["counts_complete"]
    assert_no_byte_evidence(report.to_dict())


def test_nested_script_keeps_partial_wildcard_selection():
    report, provider = check("bash entry.sh", {"/work/entry.sh": "rm -rf cache/*", "/work/cache/a": "secret"})
    deletion, = entries(report, "delete-inside-workspace")
    assert deletion.data["matched_targets"] == ["/work/cache/a"]
    assert deletion.data["files"] == 1 and deletion.data["counts_complete"]
    assert_no_byte_evidence(deletion.data)
    assert [q.path for q in provider.queries if isinstance(q, ReadFile)] == ["/work/entry.sh"]


@pytest.mark.parametrize('shell,command', [('bash', 'rm -rf *'), ('powershell', 'Remove-Item -Recurse -Force *')])
def test_partial_local_enumeration_never_opens_file_contents(tmp_path, monkeypatch, shell, command):
    if shell == 'bash' and os.name == 'nt':
        pytest.skip('Native Windows tmp paths do not use the Bash POSIX path profile')
    (tmp_path / "a.txt").write_text("secret")
    (tmp_path / "tree").mkdir()
    (tmp_path / "tree" / "b.txt").write_text("other secret")
    def forbidden(*args, **kwargs):
        pytest.fail("Partial enumeration opened file contents")
    monkeypatch.setattr(os, "open", forbidden)
    monkeypatch.setattr(builtins, "open", forbidden)
    report = Analyzer(evidence=LocalEvidenceProvider()).analyze_report(command, str(tmp_path), shell=shell, effort="Partial")
    deletion, = entries(report, "delete-inside-workspace")
    assert deletion.data["files"] == 2 and deletion.data["directories"] == 1
    assert deletion.data["counts_complete"]
    assert_no_byte_evidence(report.to_dict())


@pytest.mark.parametrize("effort", ["Full", "Partial", "None"])
@pytest.mark.parametrize("command,rule", [("echo hello", None), ("pip install torch", "package-install"),
                                          ('python -c "import torch"', "uses-interpreter"),
                                          ("echo 'rm -rf /etc' > authored.sh", "delete-protected-root")])
def test_syntax_and_authored_code_checks_do_not_require_evidence(command, rule, effort):
    report, provider = check(command, effort=effort)
    if rule:
        assert entries(report, rule)
    else:
        assert report.to_dict() == {}
    if effort == "None" or " > " not in command:
        assert provider.queries == []


@pytest.mark.parametrize("value", [None, 0, True, "", "maximum", [], {}])
def test_invalid_effort_is_input_error(value):
    with pytest.raises(InputError):
        check("true", effort=value)


def test_default_full_and_public_api_forwarding(monkeypatch):
    provider = MemoryEvidenceProvider({"/work/evil.txt": "rm -rf /etc"})
    analyzer = Analyzer(evidence=provider)
    assert analyzer.analyze("cat evil.txt | bash", "/work")["level"] == "BLOCK"
    assert analyzer.analyze("cat evil.txt | bash", "/work", effort="partial")["level"] == "MEDIUM"
    assert json.loads(analyzer.analyze_json("cat evil.txt | bash", "/work", effort="NONE"))["level"] == "MEDIUM"
    def forbidden(*args, **kwargs):
        pytest.fail("None effort accessed the filesystem")
    monkeypatch.setattr(os, "lstat", forbidden)
    assert analyze("cat evil.txt | bash", "/work", shell="bash", effort="None")["level"] == "MEDIUM"
    assert json.loads(analyze_json("cat evil.txt | bash", "/work", shell="bash", effort=EvidenceEffort.NONE))["level"] == "MEDIUM"


@pytest.mark.parametrize('shell,command', [('bash', 'cat evil.txt | bash'), ('powershell', 'Get-Content evil.txt | pwsh -Command -')])
def test_none_and_partial_never_open_local_files(monkeypatch, tmp_path, shell, command):
    if shell == 'bash' and os.name == 'nt':
        pytest.skip('Native Windows tmp paths do not use the Bash POSIX path profile')
    source = tmp_path / "evil.txt"
    source.write_text("rm -rf /etc")
    analyzer = Analyzer()
    def forbidden(*args, **kwargs):
        pytest.fail("Reduced effort opened file content")
    monkeypatch.setattr(os, "open", forbidden)
    monkeypatch.setattr(builtins, "open", forbidden)
    for effort in ("Partial", "None"):
        report = analyzer.analyze_report(command, str(tmp_path), shell=shell, effort=effort)
        assert entries(report, "execution-content-unavailable")
        assert not entries(report, "delete-protected-root")


@pytest.mark.parametrize("existing,dangerous", [("", True), ("echo safe\n", True),
                                                ("cat <<'EOF'\n", False), ("echo '\n", False)])
def test_full_append_inspects_exact_prefix_and_suffix(existing, dangerous):
    report, provider = check("echo 'rm -rf /etc' >> script.sh", {"/work/script.sh": existing})
    assert bool(entries(report, "delete-protected-root")) is dangerous
    assert [q.path for q in provider.queries if isinstance(q, ReadFile)] == ["/work/script.sh"]


@pytest.mark.parametrize("effort", ["Partial", "None"])
def test_reduced_append_does_not_parse_unknown_final_script_as_suffix(effort):
    report, provider = check("echo 'rm -rf /etc' >> script.sh", {"/work/script.sh": ""}, effort=effort)
    assert not entries(report, "delete-protected-root")
    assert entries(report, "unresolved-value")[0].data["reason"] == "effort_" + effort.lower()
    assert not any(isinstance(q, ReadFile) for q in provider.queries)


@pytest.mark.parametrize("operator,blocked", [(">>", False), (">", True)])
def test_user_append_and_overwrite_distinction_inside_file(operator, blocked):
    report, provider = check("bash write.sh", {"/work/write.sh": f"echo 'rm -rf /etc' {operator} script.sh",
                                             "/work/script.sh": ""})
    assert bool(entries(report, "delete-protected-root")) is blocked
    assert [q.path for q in provider.queries if isinstance(q, ReadFile)] == ["/work/write.sh"]
    assert any(isinstance(q, StatTarget) and q.path == "/work/script.sh" for q in provider.queries)


@pytest.mark.parametrize("effort", ["Full", "Partial"])
def test_append_to_confirmed_missing_file_has_complete_literal_content(effort):
    report, _ = check("echo 'rm -rf /etc' >> new.sh", effort=effort)
    assert entries(report, "delete-protected-root")


def test_dirty_append_cannot_read_preceding_disk_contents():
    report, provider = check("echo safe > script.sh; echo 'rm -rf /etc' >> script.sh",
                             {"/work/script.sh": "echo old\n"})
    assert not entries(report, "delete-protected-root")
    assert entries(report, "unresolved-value")[0].data["reason"] == "changed_earlier"
    assert not any(isinstance(q, ReadFile) and q.path == "/work/script.sh" for q in provider.queries)


@pytest.mark.parametrize("shell,command,path,prefix", [
    ("powershell", "Add-Content script.ps1 'Remove-Item -Recurse -Force C:\\'", r"C:\work\script.ps1", ""),
    ("cmd", "echo rd /s /q C:\\ >> script.cmd", r"C:\work\script.cmd", ""),
])
@pytest.mark.parametrize("effort", list(EvidenceEffort))
def test_windows_append_uses_combined_source_only_with_full_evidence(shell, command, path, prefix, effort):
    report, provider = check(command, {path: prefix}, shell=shell, effort=effort)
    assert bool(entries(report, "delete-protected-root")) is (effort is EvidenceEffort.FULL)
    assert bool([q for q in provider.queries if isinstance(q, ReadFile)]) is (effort is EvidenceEffort.FULL)


@pytest.mark.parametrize("effort", list(EvidenceEffort))
@pytest.mark.parametrize("command", ["bash < /dev/null", "cat /dev/null | bash", "echo 'rm -rf /etc' | bash < /dev/null"])
def test_known_empty_device_stdin_needs_no_evidence(command, effort):
    report, provider = check(command, effort=effort)
    assert [f.rule for f in report.findings] == ["uses-interpreter"]
    assert provider.queries == []


@pytest.mark.parametrize("command", ["rm -rf /etc", "rm file", "rm *.txt", "mv source dest", "git clone https://example.invalid/repo.git"])
@pytest.mark.parametrize("effort", list(EvidenceEffort))
def test_all_evidence_kinds_obey_ceiling(command, effort):
    report, provider = check(command, {"/work/file": "data", "/work/a.txt": "data", "/work/dest": "old"}, effort=effort)
    if effort is EvidenceEffort.NONE:
        assert provider.queries == []
    elif effort is EvidenceEffort.PARTIAL:
        assert not any(isinstance(q, ReadFile) for q in provider.queries)
    if command == "rm -rf /etc":
        assert entries(report, "delete-protected-root")


def test_earlier_full_read_does_not_enable_later_nested_content_read():
    report, provider = check("bash nested.sh; bash entry.sh", {"/work/nested.sh": "echo benign", "/work/entry.sh": "bash nested.sh"})
    assert [q.path for q in provider.queries if isinstance(q, ReadFile)] == ["/work/nested.sh", "/work/entry.sh"]
    unavailable, = entries(report, "execution-content-unavailable")
    assert unavailable.data["target"] == "/work/nested.sh" and unavailable.data["effort"] == "Partial"


def test_separate_original_invocations_keep_full_effort():
    report, provider = check("bash entry.sh; bash nested.sh", {"/work/entry.sh": "bash nested.sh", "/work/nested.sh": "rm -rf /etc"})
    assert entries(report, "delete-protected-root")
    assert [q.path for q in provider.queries if isinstance(q, ReadFile)] == ["/work/entry.sh", "/work/nested.sh"]


@pytest.mark.parametrize("command", ["cat a b | bash", "cat a b | python -"])
def test_multiple_file_streams_are_concatenated_in_operand_order(command):
    files = {"/work/a": "rm -rf ", "/work/b": "/etc"} if command.endswith("bash") else {
        "/work/a": "import os; os.remove(", "/work/b": "'/etc/passwd')"}
    report, _ = check(command, files)
    assert entries(report, "delete-protected-root") or entries(report, "delete-outside-workspace")


@pytest.mark.parametrize("command", ["cat -n evil.txt | bash", "cat evil.txt | sed 's/rm/echo/' | bash",
                                      "echo 'rm -rf /etc' | bash -c true", "cat evil.txt | bash safe.sh"])
def test_transformation_and_explicit_program_boundaries_are_retained(command):
    report, _ = check(command, {"/work/evil.txt": "rm -rf /etc", "/work/safe.sh": "echo benign"})
    assert not entries(report, "delete-protected-root")


@pytest.mark.parametrize("command", ["psql -f script.sql", "cat script.sql | psql"])
@pytest.mark.parametrize("effort", list(EvidenceEffort))
def test_sql_sources_obey_same_file_effort(command, effort):
    report, provider = check(command, {"/work/script.sql": "DROP TABLE users"}, effort=effort)
    assert bool(entries(report, "sql-drop-object")) is (effort is EvidenceEffort.FULL)
    assert bool(entries(report, "sql-unresolved")) is (effort is not EvidenceEffort.FULL)
    if effort is EvidenceEffort.NONE:
        assert provider.queries == []


@pytest.mark.parametrize("content", [b"\x00binary", b"\xffbad", b"echo hello\n" * 30])
def test_binary_and_truncated_sources_remain_unavailable(content):
    report, _ = check("cat evil.txt | bash", {"/work/evil.txt": content}, config=AnalyzerConfig(file_bytes=32))
    assert entries(report, "execution-content-unavailable")


def test_effort_degradation_saturates_at_none():
    assert EvidenceEffort.FULL.lower() is EvidenceEffort.PARTIAL
    assert EvidenceEffort.PARTIAL.lower() is EvidenceEffort.NONE
    assert EvidenceEffort.NONE.lower() is EvidenceEffort.NONE


@pytest.mark.parametrize("text", ["Get-Content source | pwsh -Command -", "# 非ASCII\nGet-Content source | python -"])
def test_powershell_stdin_dash_recovery_preserves_spans_and_budget(text):
    from command_inspector.pwsh.syntax import PowerShellFrontend
    from command_inspector.bash.syntax import ParseBudgetExceeded
    frontend = PowerShellFrontend()
    parsed = frontend.parse(text)
    assert not parsed.diagnostics
    pending = [parsed.root]
    while pending:
        node = pending.pop()
        assert node.text == text[node.span.start:node.span.end]
        pending.extend(node.children)
    with pytest.raises(ParseBudgetExceeded):
        frontend.parse(text, 10)


@pytest.mark.parametrize("status,reason", [(EvidenceStatus.UNAVAILABLE, "filesystem_access_failed"),
                                         (EvidenceStatus.UNAVAILABLE, "not_regular_file"),
                                         (EvidenceStatus.TRUNCATED, "total_read_budget")])
def test_unavailable_stream_evidence_never_establishes_missing(status, reason):
    provider = MemoryEvidenceProvider(answers={ReadFile("/work/source", 524288): EvidenceAnswer(status, reason=reason, complete=False)})
    report = Analyzer(evidence=provider).analyze_report("cat source | bash", "/work")
    assert entries(report, "execution-content-unavailable")[0].data["reason"] == reason
    assert not entries(report, "execute-target-missing")


def test_inline_reference_checks_do_not_mutate_caller_evidence():
    report, provider = check("echo 'bash nested.sh' > authored.sh; cat notes",
                             {"/work/nested.sh": "echo replaced > notes", "/work/notes": "password=abcdefghij"})
    assert entries(report, "credentials-read")
    assert ReadFile("/work/notes", 524288) in provider.queries


def test_authored_script_mutations_invalidate_its_own_future_reads():
    report, provider = check("cat <<'EOF' > authored.sh\necho safe > nested.sh; bash nested.sh\nEOF",
                             {"/work/nested.sh": "rm -rf /etc"})
    assert not entries(report, "delete-protected-root")
    assert entries(report, "execution-content-unavailable")[0].data["reason"] == "changed_earlier"
    assert not any(isinstance(q, ReadFile) and q.path == "/work/nested.sh" for q in provider.queries)


@pytest.mark.parametrize("options", ["-ReadCount 2", "-Delimiter END", "-AsByteStream", "-Encoding ascii", "-Wait", "-TotalCount 1"])
def test_powershell_selected_or_reencoded_streams_do_not_become_original_source(options):
    report, _ = check(f"Get-Content {options} evil.txt | pwsh -Command -",
                      {r"C:\work\evil.txt": "Remove-Item -Recurse -Force C:\\"}, shell="powershell")
    assert entries(report, "execution-content-unavailable")
    assert not entries(report, "delete-protected-root")


@pytest.mark.parametrize("command", ["cat evil.txt | bash", "bash evil.txt", "psql -f evil.txt"])
@pytest.mark.parametrize("effort", ["Full", "Partial", "None"])
def test_disabled_evidence_remains_disabled(command, effort):
    report, _ = check(command, config=AnalyzerConfig(local_evidence=False), effort=effort)
    assert not entries(report, "delete-protected-root")
    # Explicit fixture providers preserve the existing injection contract; a
    # default disabled analyzer must not access the host at any selected effort.
    result = Analyzer(AnalyzerConfig(local_evidence=False)).analyze_report(command, "/work", effort=effort)
    assert entries(result, "execution-content-unavailable") or entries(result, "sql-unresolved")
