"""Hand-specified wildcard contracts; command text is never executed."""
import json
import os
import stat
import subprocess
from dataclasses import replace
from types import SimpleNamespace

import jsonschema
import pytest

from command_inspector import Analyzer, AnalyzerConfig, ConfigurationError
from command_inspector.local_evidence import (
    CachedEvidenceProvider, DisabledEvidenceProvider, EvidenceStatus,
    LocalEvidenceProvider, MatchTargets, MemoryEvidenceProvider, ReadFile,
    SummarizeDeletion,
)


@pytest.fixture(autouse=True)
def no_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Wildcard analysis attempted command execution")
    monkeypatch.setattr(os, "system", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


def analyze(command, files, *, shell="bash", cwd="/work", config=None, provider=None):
    provider = provider if provider is not None else MemoryEvidenceProvider(files)
    analyzer = Analyzer(config, evidence=provider)
    report = analyzer.analyze(command, cwd, shell=shell)
    jsonschema.validate(report, analyzer.report_schema())
    return report, provider


def finding(report, rule=None):
    findings = report.get("findings", [])
    if rule:
        findings = [f for f in findings if f["rule"] == rule]
    assert len(findings) == 1, report
    return findings[0]


@pytest.mark.parametrize("pattern,expected", [
    ("*.txt", ["a.txt", "b.txt"]),
    ("?.txt", ["a.txt", "b.txt"]),
    ("[ab].txt", ["a.txt", "b.txt"]),
    ("[a-b]*", ["a.txt", "b.txt"]),
    ("[!a]*.txt", ["b.txt"]),
    (".*.txt", [".hidden.txt"]),
    ("A*.TXT", ["A.TXT"]),
])
def test_bash_profile_and_observed_counts(pattern, expected):
    files = {"/work/" + name: "123" for name in ["a.txt", "b.txt", "A.TXT", ".hidden.txt", "other.log"]}
    report, _ = analyze("rm " + pattern, files)
    f = finding(report, "delete-inside-workspace")
    paths = ["/work/" + p for p in expected]
    assert f["data"]["matched_targets"] == paths
    assert f["data"]["affected_paths"] == paths
    assert f["data"]["files"] == len(expected)
    assert f["data"]["logical_bytes"] == 3 * len(expected)
    assert f["data"]["matches_complete"] and f["data"]["counts_complete"]
    assert f["data"]["affected_paths_complete"]
    assert f["data"]["scope"] == "inside"
    assert f["level"] == "LOW"


@pytest.mark.parametrize("command,selected", [
    ("rm '*.txt'", "/work/*.txt"),
    (r"rm a\*b*", "/work/a*b-one"),
    ('rm "a*b"*', "/work/a*b-one"),
    ("rm 'a?b'*", "/work/a?b-one"),
    (r"rm 'dir with spaces'/*.txt", "/work/dir with spaces/a.txt"),
])
def test_bash_quoted_and_escaped_wildcards(command, selected):
    files = {selected: "x", "/work/axxb-other": "x", "/work/acb-other": "x"}
    report, provider = analyze(command, files)
    f = finding(report, "delete-inside-workspace")
    if "matched_targets" in f["data"]:
        assert f["data"]["matched_targets"] == [selected]
    else:
        assert f["data"]["target"] == selected
        assert not any(isinstance(q, MatchTargets) for q in provider.queries)


def test_component_matching_and_trailing_directory_separator():
    files = {"/work/cache-a/a.tmp": "aaa", "/work/cache-b/b.tmp": "bb", "/work/no/c.tmp": "x"}
    report, _ = analyze("rm cache-*/*.tmp", files)
    assert finding(report)["data"]["matched_targets"] == ["/work/cache-a/a.tmp", "/work/cache-b/b.tmp"]
    report, _ = analyze("rm -r cache-*/", files)
    f = finding(report)
    assert f["data"]["matched_targets"] == ["/work/cache-a", "/work/cache-b"]
    assert f["data"]["files"] == 2 and f["data"]["directories"] == 2
    assert f["data"]["counts_complete"]


def test_recursive_affected_paths_include_unmatched_children():
    files = {"/work/cache/a.txt": "a", "/work/cache/tree/.hidden": "xx", "/work/cache/tree/nested/inner": "xxx"}
    report, _ = analyze("rm -rf cache/*", files)
    f = finding(report)
    assert f["data"]["matched_targets"] == ["/work/cache/a.txt", "/work/cache/tree"]
    assert f["data"]["affected_paths"] == sorted([*files, "/work/cache/tree", "/work/cache/tree/nested"])
    assert f["data"]["files"] == 3 and f["data"]["directories"] == 2
    assert f["data"]["logical_bytes"] == 6


def test_nonrecursive_directory_does_not_claim_descendants():
    report, _ = analyze("rm tree*", {"/work/tree/inner": "abc"})
    data = finding(report)["data"]
    assert data["matched_targets"] == ["/work/tree"]
    assert data["files"] == 0
    assert not data["counts_complete"] and not data["affected_paths_complete"]
    assert "/work/tree/inner" not in data["affected_paths"]


@pytest.mark.parametrize("pattern,expected_scope,level", [
    ("/outside/*.tmp", "outside", "MEDIUM"),
    ("/w*/*.tmp", "mixed", "MEDIUM"),
    ("../outside/*.tmp", "outside", "MEDIUM"),
])
def test_matched_scope_uses_components(pattern, expected_scope, level):
    files = {"/work/a.tmp": "x", "/work-other/b.tmp": "x", "/outside/c.tmp": "x"}
    report, _ = analyze("rm " + pattern, files)
    f = finding(report, "delete-outside-workspace")
    assert f["data"]["scope"] == expected_scope and f["level"] == level


def test_additional_workspace_roots_apply_to_matches():
    report, _ = analyze("rm /outside/*.tmp", {"/outside/a.tmp": "a"},
                        config=AnalyzerConfig(additional_paths=("/outside",)))
    assert finding(report)["rule"] == "delete-inside-workspace"


def test_matched_workspace_root_retains_high_level():
    report, _ = analyze("rm -rf /wor*", {"/work/a": "a"})
    assert finding(report, "delete-workspace-root")["level"] == "HIGH"


@pytest.mark.parametrize("provider", [DisabledEvidenceProvider(), MemoryEvidenceProvider({"/etc/a": "a"})])
def test_protected_base_retained_with_or_without_evidence(provider):
    report, _ = analyze("rm -rf /etc/*", {}, provider=provider)
    assert finding(report, "delete-protected-root")["level"] == "BLOCK"


def test_partial_critical_match_keeps_block():
    report, _ = analyze("rm -rf /e*", {"/etc/a": "x", "/extra/a": "x"},
                        config=AnalyzerConfig(wildcard_matches=1))
    f = finding(report)
    assert f["rule"] == "delete-protected-root" and f["level"] == "BLOCK"
    assert not f["data"]["matches_complete"]


@pytest.mark.parametrize("pattern", ["*.missing", "absent/*.txt"])
def test_complete_empty_selection_is_not_unknown(pattern):
    report, _ = analyze("rm " + pattern, {"/work/a.log": "x"})
    f = finding(report, "delete-target-missing")
    assert f["data"]["matched_targets"] == [] and f["data"]["matches_complete"]


def test_matching_entry_and_result_limits_are_distinct():
    files = {f"/work/{i}.tmp": "xxx" for i in range(5)}
    report, _ = analyze("rm *.tmp", files, config=AnalyzerConfig(wildcard_matches=2))
    data = finding(report, "delete-variable-unresolved")["data"]
    assert len(data["matched_targets"]) == 2 and data["reason"] == "match_limit"
    assert not data["matches_complete"] and not data["counts_complete"]
    report, provider = analyze("rm *.tmp", files, config=AnalyzerConfig(directory_entries=3))
    f = finding(report, "delete-variable-unresolved")
    assert len(f["data"]["matched_targets"]) == 2
    assert f["data"]["reason"] == "entry_limit"
    assert not f["data"]["counts_complete"]
    assert not any(isinstance(q, SummarizeDeletion) for q in provider.queries)


def test_affected_path_list_cap_does_not_falsify_complete_counts():
    files = {f"/work/tree/{i}": "x" for i in range(5)}
    report, _ = analyze("rm -rf tree*", files, config=AnalyzerConfig(wildcard_matches=2))
    data = finding(report)["data"]
    assert data["match_count"] == 1 and data["matches_complete"]
    assert data["files"] == 5 and data["counts_complete"]
    assert len(data["affected_paths"]) == 2 and not data["affected_paths_complete"]


def test_call_wide_entry_budget_and_identical_request_cache():
    provider = MemoryEvidenceProvider({"/work/a.tmp": "a", "/work/b.log": "b"})
    cache = CachedEvidenceProvider(provider, 100, total_entries=3)
    request = MatchTargets("/work", "*.tmp", 100)
    assert cache.answer(request).complete
    assert cache.answer(request) == cache.answer(request)
    assert len(provider.queries) == 1
    answer = cache.answer(replace(request, pattern="*.log"))
    assert answer.reason == "total_entry_budget" and not answer.complete
    assert len(provider.queries) == 1


@pytest.mark.parametrize("command", ["rm **/*.txt", "rm */../*.txt", "rm ~/work/*.txt", "rm $UNKNOWN/*.txt"])
def test_unmodeled_patterns_never_become_complete(command):
    report, _ = analyze(command, {"/work/a.txt": "x"})
    assert finding(report, "delete-variable-unresolved")["level"] == "MEDIUM"


def test_earlier_write_prevents_speculative_selection():
    report, provider = analyze("echo new > a.tmp; rm *.tmp", {"/work/a.tmp": "old"})
    f = finding(report, "delete-variable-unresolved")
    assert f["data"]["reason"] == "may_have_changed_earlier"
    assert not any(isinstance(q, MatchTargets) for q in provider.queries)


@pytest.mark.parametrize("shell,command", [
    ("powershell", "Remove-Item '*.TXT'"),
    ("cmd", "del /q *.TXT"),
])
def test_windows_case_insensitive_matching_on_linux(shell, command):
    report, _ = analyze(command, {r"D:\work\a.txt": "a", r"D:\work\b.log": "x"}, shell=shell, cwd=r"D:\work")
    assert finding(report)["data"]["matched_targets"] == [r"D:\work\a.txt"]


@pytest.mark.parametrize("command,paths", [
    ("del /q *.*", [r"D:\work\a.txt", r"D:\work\README"]),
    ("del /s /q *.txt", [r"D:\work\a.txt", r"D:\work\sub\b.txt"]),
])
def test_cmd_all_names_and_recursive_extension_filter(command, paths):
    files = {r"D:\work\README": "r", r"D:\work\a.txt": "a", r"D:\work\sub\b.txt": "bb", r"D:\work\sub\other.log": "x"}
    report, _ = analyze(command, files, shell="cmd", cwd=r"D:\work")
    data = finding(report)["data"]
    assert data["matched_targets"] == paths
    assert data["affected_paths"] == paths and data["directories"] == 0


@pytest.mark.parametrize("command", ["Remove-Item -Path '[ab].txt'", "Remove-Item -Path @('a*.txt','b*.txt')"])
def test_powershell_classes_and_arrays(command):
    report, _ = analyze(command, {r"D:\work\a.txt": "a", r"D:\work\b.txt": "b"}, shell="powershell", cwd=r"D:\work")
    paths = sorted(p for f in report["findings"] for p in f["data"]["matched_targets"])
    assert paths == [r"D:\work\a.txt", r"D:\work\b.txt"]


def test_powershell_literalpath_does_not_request_matches():
    report, provider = analyze("Remove-Item -LiteralPath '*.txt'", {r"D:\work\*.txt": "x"}, shell="powershell", cwd=r"D:\work")
    assert finding(report)["data"]["target"] == r"D:\work\*.txt"
    assert not any(isinstance(q, MatchTargets) for q in provider.queries)


@pytest.mark.parametrize("shell,command", [
    ("powershell", "Remove-Item '*.txt' -Exclude keep.txt"),
    ("powershell", "Remove-Item '*.txt' -Filter a*"),
    ("powershell", "Remove-Item '?.txt'"),
    ("powershell", "Remove-Item '*.txt' -Recurse"),
    ("cmd", "del ?.txt"),
    ("cmd", "copy a+b out"),
])
def test_windows_unsupported_selection_keeps_uncertainty(shell, command):
    report, _ = analyze(command, {r"D:\work\a.txt": "x"}, shell=shell, cwd=r"D:\work")
    assert any(f["rule"] in {"delete-variable-unresolved", "unresolved-value"} for f in report["findings"])


@pytest.mark.parametrize("shell,command,cwd,path", [
    ("bash", "cat *.txt", "/work", "/work/a.txt"),
    ("bash", "grep -F password *.txt", "/work", "/work/a.txt"),
    ("powershell", "Get-Content '*.txt'", r"D:\work", r"D:\work\a.txt"),
    ("cmd", "type *.txt", r"D:\work", r"D:\work\a.txt"),
])
def test_selected_ingestion_is_scanned_with_shared_read_cache(shell, command, cwd, path):
    report, provider = analyze(command + ("; " if shell != "cmd" else " & ") + command,
                                {path: "password=abcdefgh\n", cwd + ("\\" if shell != "bash" else "/") + "other.log": "hello"}, shell=shell, cwd=cwd)
    assert finding(report, "credentials-read")["data"]["target"] == path
    assert len([q for q in provider.queries if isinstance(q, MatchTargets)]) == 1
    assert len([q for q in provider.queries if isinstance(q, ReadFile)]) == 1


def test_partial_ingestion_selection_is_reported_without_invented_credentials():
    report, _ = analyze("cat *.txt", {"/work/a.txt": "hello", "/work/b.txt": "hello"}, config=AnalyzerConfig(wildcard_matches=1))
    assert not any(f["rule"] == "credentials-read" for f in report["findings"])
    assert finding(report, "ingestion-inspection-incomplete")["data"]["reason"] == "match_limit"


def test_consumed_read_output_does_not_eagerly_match_or_read():
    report, provider = analyze("cat *.txt > copy", {"/work/a.txt": "password=secret"})
    assert not any(isinstance(q, (MatchTargets, ReadFile)) for q in provider.queries)
    assert not any(f["rule"] == "credentials-read" for f in report["findings"])


def test_powershell_content_write_operates_on_matches():
    report, provider = analyze("Set-Content '*.txt' hello", {r"D:\work\a.txt": "old", r"D:\work\b.log": "old"}, shell="powershell", cwd=r"D:\work")
    assert finding(report, "overwrite-existing-file")["data"]["target"] == r"D:\work\a.txt"
    assert any(isinstance(q, MatchTargets) for q in provider.queries)


def test_reports_redact_sensitive_path_names():
    token = "ghp_" + "a" * 30
    report, _ = analyze("rm *.txt", {f"/work/{token}.txt": "a"})
    assert token not in json.dumps(report)


@pytest.mark.parametrize("value", [0, -1, True, "10"])
def test_wildcard_limit_validation(value):
    with pytest.raises(ConfigurationError):
        AnalyzerConfig(wildcard_matches=value)
    with pytest.raises(ConfigurationError):
        AnalyzerConfig.from_mapping({"limits": {"wildcard_matches": value}})


def test_local_selection_and_counts_use_metadata_only(tmp_path, monkeypatch):
    (tmp_path / "a.txt").write_bytes(b"abc")
    (tmp_path / "b.log").write_bytes(b"x")
    def no_content(*args, **kwargs):
        pytest.fail("Matching or counting attempted content I/O")
    monkeypatch.setattr(os, "open", no_content)
    provider = LocalEvidenceProvider()
    request = MatchTargets(str(tmp_path), "*.txt", 100, profile="powershell" if os.name == "nt" else "bash", windows=os.name == "nt")
    answer = provider.answer(request)
    assert answer.complete and answer.data["paths"] == [str(tmp_path / "a.txt")]
    summary = provider.answer(SummarizeDeletion(str(tmp_path), 100))
    assert summary.complete and summary.data["files"] == 2 and summary.data["logical_bytes"] == 4


def make_link(link, target):
    try:
        link.symlink_to(target, target_is_directory=target.is_dir())
    except (OSError, NotImplementedError):
        pytest.skip("Host cannot create test symlinks")


def test_local_matching_and_summary_do_not_follow_directory_links(tmp_path):
    target = tmp_path / "actual"
    target.mkdir()
    (target / "a.txt").write_bytes(b"abc")
    link = tmp_path / "linked"
    make_link(link, target)
    provider = LocalEvidenceProvider()
    style = {"profile": "powershell" if os.name == "nt" else "bash", "windows": os.name == "nt"}
    answer = provider.answer(MatchTargets(str(tmp_path), "link*/*.txt", 100, **style))
    assert not answer.complete and not answer.data["paths"]
    answer = provider.answer(MatchTargets(str(link), "*.txt", 100, **style))
    assert not answer.complete and answer.reason == "directory_link_not_followed"
    summary = provider.answer(SummarizeDeletion(str(link), 100))
    assert summary.data["files"] == 1 and summary.data["logical_bytes"] == 0
    assert summary.data["affected_paths"] == [str(link)]


def test_local_permission_failure_is_partial(tmp_path, monkeypatch):
    def denied(path):
        raise PermissionError(path)
    monkeypatch.setattr(os, "scandir", denied)
    answer = LocalEvidenceProvider().answer(MatchTargets(str(tmp_path), "*", 100, windows=os.name == "nt"))
    assert not answer.complete and answer.status == EvidenceStatus.TRUNCATED
    assert answer.reason == "filesystem_access_failed"


@pytest.mark.parametrize("path", [r"\\server\share", r"\\.\PhysicalDrive0", "//server/share"])
def test_nonlocal_matching_never_probes_host(path, monkeypatch):
    def no_probe(*args, **kwargs):
        pytest.fail("Nonlocal matching probed host")
    monkeypatch.setattr(os, "lstat", no_probe)
    answer = LocalEvidenceProvider().answer(MatchTargets(path, "*", 100, windows=True))
    assert answer.status == EvidenceStatus.UNAVAILABLE


def test_reparse_point_is_not_traversed(monkeypatch):
    monkeypatch.setattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 1024, raising=False)
    monkeypatch.setattr(os, "lstat", lambda p: SimpleNamespace(st_mode=stat.S_IFDIR, st_size=0, st_file_attributes=1024))
    assert LocalEvidenceProvider.info("junction")[0] == "symlink"


def test_no_default_shell_is_needed_for_explicit_matching():
    report, _ = analyze("rm *.txt", {"/work/a.txt": "x"}, config=AnalyzerConfig(shell=None))
    assert finding(report)["data"]["matches_complete"]


def test_local_report_contains_current_observed_paths_and_counts(tmp_path):
    (tmp_path / "a.txt").write_bytes(b"123")
    (tmp_path / "b.log").write_bytes(b"x")
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    shell, command = ("powershell", "Remove-Item '*.txt'") if os.name == "nt" else ("bash", "rm *.txt")
    report, _ = analyze(command, {}, provider=LocalEvidenceProvider(), shell=shell, cwd=str(tmp_path))
    data = finding(report)["data"]
    assert data["matched_targets"] == data["affected_paths"] == [str(tmp_path / "a.txt")]
    assert data["files"] == 1 and data["logical_bytes"] == 3
    assert data["matches_complete"] and data["counts_complete"]
    assert before == {p.name: p.read_bytes() for p in tmp_path.iterdir()}


def test_local_entry_and_result_limits(tmp_path):
    for i in range(10):
        (tmp_path / f"{i}.txt").write_bytes(b"x")
    provider = LocalEvidenceProvider()
    request = MatchTargets(str(tmp_path), "*.txt", 100, max_matches=2, windows=os.name == "nt")
    answer = provider.answer(request)
    assert not answer.complete and answer.reason == "match_limit"
    assert len(answer.data["paths"]) == 2
    answer = provider.answer(replace(request, max_entries=3))
    assert not answer.complete and answer.reason == "entry_limit"
    assert answer.data["examined_entries"] <= 3


def test_matching_is_not_cached_across_calls():
    provider = MemoryEvidenceProvider({"/work/a.txt": "a"})
    analyzer = Analyzer(evidence=provider)
    assert finding(analyzer.analyze("rm *.txt", "/work", shell="bash"))["data"]["match_count"] == 1
    provider.files["/work/b.txt"] = "b"
    assert finding(analyzer.analyze("rm *.txt", "/work", shell="bash"))["data"]["match_count"] == 2
    assert len([q for q in provider.queries if isinstance(q, MatchTargets)]) == 2


def test_unicode_and_quoted_parent_wildcards():
    path = "/work/literal*/文档.txt"
    report, _ = analyze("rm 'literal*'/*.txt", {path: "hello", "/work/literal-other/other.txt": "no"})
    assert finding(report)["data"]["matched_targets"] == [path]


def test_named_recursive_target_also_has_bounded_affected_paths():
    report, _ = analyze("rm -rf tree", {"/work/tree/a": "aa", "/work/tree/sub/b": "bbb"})
    f = finding(report, "delete-inside-workspace")
    counts = next(e for e in f["evidence"] if "affected_paths" in e)
    assert counts["complete"] and counts["affected_paths_complete"]
    assert counts["files"] == 2 and counts["directories"] == 2 and counts["logical_bytes"] == 5
    assert counts["affected_paths"] == ["/work/tree", "/work/tree/a", "/work/tree/sub", "/work/tree/sub/b"]


def test_nonrecursive_cmd_directory_selection_counts_immediate_files_only():
    files = {r"D:\work\tree\a": "aa", r"D:\work\tree\sub\b": "bbb"}
    report, _ = analyze("del /q tree", files, shell="cmd", cwd=r"D:\work")
    counts = next(e for e in finding(report)["evidence"] if "affected_paths" in e)
    assert counts["files"] == 1 and counts["directories"] == 0 and counts["logical_bytes"] == 2
    assert counts["complete"] and counts["affected_paths"] == [r"D:\work\tree\a"]
    assert counts["examined_entries"] == 3  # Includes the examined, excluded child directory.


def test_windows_host_path_mismatch_never_probes_local_disk(monkeypatch):
    from types import SimpleNamespace
    import command_inspector.local_evidence as module
    def no_probe(*args, **kwargs):
        pytest.fail("Foreign path style probed disk")
    monkeypatch.setattr(module, "os", SimpleNamespace(name="posix", path=SimpleNamespace(isabs=lambda p: True), lstat=no_probe))
    answer = LocalEvidenceProvider().answer(MatchTargets(r"D:\work", "*", 100, windows=True))
    assert answer.reason == "host_path_style_mismatch"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="Host has no FIFO support")
def test_matched_special_file_is_never_opened(tmp_path):
    fifo = tmp_path / "pipe.txt"
    os.mkfifo(fifo)
    report, _ = analyze("cat *.txt", {}, provider=LocalEvidenceProvider(), cwd=str(tmp_path))
    assert finding(report, "ingestion-inspection-incomplete")["data"]["reason"] == "not_regular_file"


def test_powershell_escaped_path_and_literal_write():
    report, _ = analyze("Remove-Item 'file`[1`].txt'", {r"D:\work\file[1].txt": "x", r"D:\work\file1.txt": "x"}, shell="powershell", cwd=r"D:\work")
    assert finding(report)["data"]["matched_targets"] == [r"D:\work\file[1].txt"]
    report, provider = analyze("Set-Content -LiteralPath '*.txt' hello", {r"D:\work\*.txt": "old"}, shell="powershell", cwd=r"D:\work")
    assert finding(report)["data"]["target"] == r"D:\work\*.txt"
    assert not any(isinstance(q, MatchTargets) for q in provider.queries)


def test_matcher_does_not_probe_outside_its_literal_base(tmp_path, monkeypatch):
    base = tmp_path / "cache"
    base.mkdir()
    (base / "a.txt").write_bytes(b"x")
    real_scandir = os.scandir
    scanned = []
    def scan(path):
        scanned.append(str(path))
        assert str(path).startswith(str(base))
        return real_scandir(path)
    monkeypatch.setattr(os, "scandir", scan)
    answer = LocalEvidenceProvider().answer(MatchTargets(str(base), "*.txt", 100, windows=os.name == "nt"))
    assert answer.complete and scanned == [str(base)]


def test_link_prefix_is_rejected_before_probing_its_descendants(tmp_path, monkeypatch):
    actual = tmp_path / "actual"
    actual.mkdir()
    (actual / "child").mkdir()
    link = tmp_path / "link"
    make_link(link, actual)
    real_lstat = os.lstat
    def no_link_descendants(path):
        assert not str(path).startswith(str(link) + os.sep)
        return real_lstat(path)
    monkeypatch.setattr(os, "lstat", no_link_descendants)
    answer = LocalEvidenceProvider().answer(MatchTargets(str(link / "child"), "*", 100, windows=os.name == "nt"))
    assert answer.reason == "directory_link_not_followed"


def test_native_cmd_alias_uncertainty_preserves_observed_names(tmp_path, monkeypatch):
    import command_inspector.local_evidence as module
    (tmp_path / "a.txt").write_bytes(b"a")
    # Metadata traversal is portable; simulate the Windows host gate while
    # retaining this host's temporary-path APIs, without starting CMD.
    monkeypatch.setattr(module, "os", SimpleNamespace(name="nt", path=os.path, lstat=os.lstat, scandir=os.scandir))
    answer = LocalEvidenceProvider().answer(MatchTargets(str(tmp_path), "*.txt", 100, windows=True, profile="cmd"))
    assert answer.data["paths"] == [str(tmp_path / "a.txt")]
    assert not answer.complete and answer.reason == "cmd_short_name_matching_unavailable"


def test_locale_specific_pattern_is_not_mistaken_for_empty_selection():
    report, _ = analyze("rm [[:alpha:]]*.txt", {"/work/a.txt": "x"})
    assert finding(report, "delete-variable-unresolved")["data"]["reason"] == "locale_pattern_not_modeled"


@pytest.mark.parametrize("prefix", ["rm a.tmp", "echo hello > *.tmp"])
def test_earlier_filesystem_effect_invalidates_later_matching(prefix):
    report, provider = analyze(prefix + "; rm *.tmp", {"/work/a.tmp": "old"})
    f = finding(report, "delete-variable-unresolved")
    assert f["data"]["reason"] == "may_have_changed_earlier"
    assert not any(isinstance(q, MatchTargets) for q in provider.queries)


def test_complete_deletion_invalidates_only_selected_paths_for_ingestion():
    report, provider = analyze("rm *.tmp; cat other.log", {"/work/a.tmp": "old", "/work/other.log": "password=abcdefgh"})
    assert finding(report, "credentials-read")["data"]["target"] == "/work/other.log"
    assert not any(f["rule"] == "ingestion-inspection-incomplete" for f in report["findings"])
    report, provider = analyze("rm *.tmp; cat a.tmp", {"/work/a.tmp": "password=abcdefgh"})
    assert not any(f["rule"] == "credentials-read" for f in report["findings"])
    assert not any(isinstance(q, ReadFile) for q in provider.queries)
    assert finding(report, "ingestion-inspection-incomplete")


def test_powershell_wildcard_location_does_not_invent_a_literal_cwd():
    report, provider = analyze("Set-Location 'tree*' && Remove-Item file.txt", {r"D:\work\tree-a\file.txt": "x"}, shell="powershell", cwd=r"D:\work")
    assert finding(report, "delete-variable-unresolved")
    assert not any(f["rule"] == "delete-inside-workspace" for f in report["findings"])
    assert not any(isinstance(q, MatchTargets) for q in provider.queries)


def test_powershell_new_item_keeps_wildcard_creation_mapping_unresolved():
    report, provider = analyze("New-Item -Path 'tree*' -Name new.txt", {r"D:\work\tree-a\existing.txt": "x"}, shell="powershell", cwd=r"D:\work")
    assert finding(report, "unresolved-value")
    assert not any(isinstance(q, MatchTargets) for q in provider.queries)


def test_powershell_out_file_filepath_is_not_a_wildcard_parameter():
    report, provider = analyze("'hello' | Out-File 'file[1].txt'", {r"D:\work\file[1].txt": "old"}, shell="powershell", cwd=r"D:\work")
    assert finding(report, "overwrite-existing-file")["data"]["target"] == r"D:\work\file[1].txt"
    assert not any(isinstance(q, MatchTargets) for q in provider.queries)


def test_empty_delete_operand_does_not_invalidate_later_selection():
    report, provider = analyze("rm ''; rm *.txt", {"/work/a.txt": "x"})
    assert finding(report, "delete-target-missing")
    assert finding(report, "delete-inside-workspace")["data"]["matched_targets"] == ["/work/a.txt"]
    assert len([q for q in provider.queries if isinstance(q, MatchTargets)]) == 1
