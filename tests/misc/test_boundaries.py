import json
import os
import subprocess
import builtins
import socket
from pathlib import Path
import pytest
from command_inspector import Analyzer, AnalyzerConfig, ConfigurationError, InputError
from command_inspector.local_evidence import (
    CachedEvidenceProvider, DisabledEvidenceProvider, EvidenceAnswer, EvidenceStatus,
    LocalEvidenceProvider, MemoryEvidenceProvider, ReadFile, StatTarget, SummarizeDeletion,
)


def rules(report):
    return {f["rule"] for f in report.get("findings", [])}


def test_only_one_direct_file_is_read():
    provider = MemoryEvidenceProvider({"/work/B.sh": "sudo python A.py\n", "/work/A.py": "import os; os.system('reboot')"})
    analyzer = Analyzer(evidence=provider)
    result = analyzer.analyze("bash B.sh; bash B.sh", "/work", shell="bash")
    assert rules(result) == {"uses-interpreter", "privilege-escalation", "execution-content-unavailable"}
    assert provider.queries == [ReadFile("/work/B.sh", 524288), StatTarget("/work/A.py")]


@pytest.mark.parametrize("command", ["ls", "npm run build", "make", "pytest", "pwd", "true"])
def test_no_eager_evidence(command):
    provider = MemoryEvidenceProvider()
    Analyzer(evidence=provider).analyze(command, "/work", shell="bash")
    assert provider.queries == []


def test_write_boundary_then_same_call_execution():
    provider = MemoryEvidenceProvider({"/work/B.sh": "sudo reboot"})
    result = Analyzer(evidence=provider).analyze("printf true > B.sh; bash B.sh", "/work", shell="bash")
    assert "execution-content-unavailable" in rules(result)
    assert "machine-power-change" not in rules(result)
    assert not any(isinstance(q, ReadFile) for q in provider.queries)


def test_authored_script_references_use_full_before_first_file_read():
    provider = MemoryEvidenceProvider({"/work/A.py": "import os; os.system('reboot')"})
    result = Analyzer(evidence=provider).analyze("cat <<'EOF' > B.sh\nsudo python A.py\nEOF", "/work", shell="bash")
    assert rules(result) == {"uses-interpreter", "privilege-escalation", "machine-power-change"}
    assert result["findings"][0]["title"].startswith("Written script contains")
    assert [q for q in provider.queries if isinstance(q, ReadFile)] == [ReadFile("/work/A.py", 524288)]


def test_no_state_or_evidence_cache_between_calls():
    provider = MemoryEvidenceProvider({"/work/B.sh": "true"})
    analyzer = Analyzer(evidence=provider)
    analyzer.analyze("cd .. && true", "/work", shell="bash")
    analyzer.analyze("bash B.sh", "/work", shell="bash")
    provider.files["/work/B.sh"] = "sudo true"
    result = analyzer.analyze("bash B.sh", "/work", shell="bash")
    assert "privilege-escalation" in rules(result)
    assert provider.queries == [StatTarget("/"), ReadFile("/work/B.sh", 524288), ReadFile("/work/B.sh", 524288)]


def test_conditional_directory_applies_to_direct_artifact():
    provider = MemoryEvidenceProvider({"/parent/B.sh": "true"})
    result = Analyzer(evidence=provider).analyze("cd .. && bash B.sh", "/parent/work", shell="bash")
    assert rules(result) == {"uses-interpreter", "read-outside-workspace"}
    assert provider.queries == [StatTarget("/parent"), ReadFile("/parent/B.sh", 524288)]


def test_nested_success_chain():
    result = Analyzer(evidence=DisabledEvidenceProvider()).analyze("cd .. && cd next && rm -rf x", "/parent/work", shell="bash")
    assert rules(result) == {"delete-outside-workspace", "read-outside-workspace"}
    assert result["findings"][0]["data"]["target"] == "/parent/next/x"


def test_cd_failure_keeps_sequence_uncertain():
    result = Analyzer(evidence=DisabledEvidenceProvider()).analyze("cd ..; rm -rf x", "/parent/work", shell="bash")
    assert rules(result) == {"delete-variable-unresolved", "read-outside-workspace"}


@pytest.mark.parametrize("command", ["echo $(sudo true)", "A=$(sudo true)"])
def test_visible_substitution_is_inspected(command):
    result = Analyzer(evidence=MemoryEvidenceProvider()).analyze(command, "/work", shell="bash")
    assert "privilege-escalation" in rules(result)


def test_unquoted_split_never_becomes_single_confirmed_target():
    result = Analyzer(evidence=MemoryEvidenceProvider()).analyze("rm -rf $TARGET", "/work", env={"TARGET": "/etc /work"}, shell="bash")
    assert rules(result) == {"delete-variable-unresolved"}


def test_quoted_wildcard_is_literal():
    result = Analyzer(evidence=DisabledEvidenceProvider()).analyze("rm '*'", "/work", shell="bash")
    assert result["findings"][0]["data"]["target"] == "/work/*"


def test_read_redirected_to_file_does_not_enter_model_context():
    provider = MemoryEvidenceProvider({"/work/secret": "password=very-secret"})
    result = Analyzer(evidence=provider).analyze("cat secret > copy", "/work", shell="bash")
    assert "credentials-read" not in rules(result)
    assert not any(isinstance(q, ReadFile) for q in provider.queries)


def test_python_syntax_error_at_write_boundary():
    result = Analyzer(evidence=MemoryEvidenceProvider()).analyze("printf 'def broken(:' > demo.py", "/work", shell="bash")
    assert rules(result) == {"written-source-syntax-error"}


def test_python_direct_inspection_never_imports():
    provider = MemoryEvidenceProvider({"/work/demo.py": "import dangerous\nimport subprocess\nsubprocess.run(['sudo', 'true'])"})
    result = Analyzer(evidence=provider).analyze("python demo.py", "/work", shell="bash")
    # sudo is a transparent Bash wrapper; subprocess argv uses its own model.
    assert "uses-interpreter" in rules(result)
    assert "privilege-escalation" in rules(result)
    assert not any("dangerous" in q.path for q in provider.queries)


def test_unknown_interpreter_option_does_not_read_speculative_file():
    provider = MemoryEvidenceProvider()
    result = Analyzer(evidence=provider).analyze("bash --rcfile rc B.sh", "/work", shell="bash")
    assert "unknown-option" in rules(result)
    assert "execution-content-unavailable" in rules(result)
    assert provider.queries == []


def test_prefix_binding_used_for_inline_child_without_changing_parent():
    result = Analyzer(evidence=DisabledEvidenceProvider()).analyze("TARGET=/etc bash -c 'rm -rf \"$TARGET\"'", "/work", shell="bash")
    assert "delete-protected-root" in rules(result)


def test_readonly_analysis_no_process_or_write(monkeypatch, tmp_path):
    shell = "cmd" if os.name == "nt" else "bash"
    source = tmp_path / ("B.cmd" if shell == "cmd" else "B.sh")
    source.write_text("echo hello\n" if shell == "cmd" else "sudo python A.py\n", encoding="utf-8")
    notes = tmp_path / "notes"
    notes.write_text("hello")
    analyzer = Analyzer()  # Initialize installed parser before observation.
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    real_open = os.open
    real_builtin_open = builtins.open
    def readonly_open(path, flags, *args, **kwargs):
        assert not flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)
        return real_open(path, flags, *args, **kwargs)
    def forbidden(*args, **kwargs):
        raise AssertionError("Analyzer attempted process execution or a filesystem mutation")
    def readonly_builtin_open(path, mode="r", *args, **kwargs):
        assert not any(flag in mode for flag in "wax+")
        return real_builtin_open(path, mode, *args, **kwargs)
    monkeypatch.setattr(os, "open", readonly_open)
    monkeypatch.setattr(builtins, "open", readonly_builtin_open)
    for name in ("system", "remove", "unlink", "rename", "mkdir"):
        monkeypatch.setattr(os, name, forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    command = ("B.cmd & type notes & echo hello > new & del notes & curl https://example.com" if shell == "cmd"
               else "bash B.sh; cat notes; printf hello > new; rm -rf notes; curl https://example.com")
    analyzer.analyze(command, str(tmp_path), shell=shell)
    assert before == {p.name: p.read_bytes() for p in tmp_path.iterdir()}


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="Host has no POSIX FIFO support")
def test_local_provider_avoids_special_files_and_links(tmp_path):
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    target = tmp_path / "target"
    target.write_text("hello")
    link = tmp_path / "link"
    link.symlink_to(target)
    provider = LocalEvidenceProvider()
    for path in (fifo, link):
        answer = provider.answer(ReadFile(str(path), 10))
        assert answer.status == EvidenceStatus.UNAVAILABLE
        assert answer.reason == "not_regular_file"


def test_partial_deletion_counts_and_reads(tmp_path):
    for i in range(5):
        (tmp_path / str(i)).write_text("12345")
    provider = LocalEvidenceProvider()
    answer = provider.answer(SummarizeDeletion(str(tmp_path), 3))
    assert answer.status == EvidenceStatus.TRUNCATED
    assert not answer.complete
    assert answer.data["files"] < 5
    read = provider.answer(ReadFile(str(tmp_path / "0"), 2))
    assert read.status == EvidenceStatus.TRUNCATED
    assert read.data["bytes"] == b"12"


def test_cache_and_total_budget():
    provider = MemoryEvidenceProvider({"/work/one": "1234", "/work/two": "5678"})
    cache = CachedEvidenceProvider(provider, 5)
    request = ReadFile("/work/one", 4)
    assert cache.answer(request) == cache.answer(request)
    assert provider.queries == [request]
    assert cache.answer(ReadFile("/work/two", 4)).reason == "total_read_budget"


def test_default_reports_and_repr_redact_secrets():
    secret = "ghp_" + "a" * 30
    analyzer = Analyzer(evidence=MemoryEvidenceProvider())
    report = analyzer.analyze_report("mystery_" + secret, "/work", shell="bash")
    assert secret not in json.dumps(report.to_dict())
    assert secret not in repr(report)
    assert secret not in repr(analyzer.parse("echo '" + secret + "'", shell="bash"))


@pytest.mark.parametrize("cwd", [None, "", "relative"])
def test_cwd_required(cwd):
    with pytest.raises(InputError):
        Analyzer().analyze("ls", cwd, shell="bash")


def test_does_not_use_ambient_environment(monkeypatch):
    monkeypatch.setenv("CachedDir", "/")
    result = Analyzer(evidence=MemoryEvidenceProvider()).analyze("rm -rf $CachedDir/", "/work", shell="bash")
    assert rules(result) == {"delete-variable-unresolved"}


@pytest.mark.parametrize("mapping", [
    {"limits": {"file_bytes": 0}}, {"limits": {"file_bytes": True}},
    {"workspace": {"additional_paths": ["relative"]}}, {"rules": {"mystery": {"enabled": False}}},
    {"rules": {"unknown-option": {"enabled": "no"}}}, {"level_overrides": {}},
])
def test_config_rejects_invalid_fields(mapping):
    with pytest.raises(ConfigurationError):
        AnalyzerConfig.from_mapping(mapping)


def test_disabled_specific_rule_keeps_generic():
    config = AnalyzerConfig(disabled_rules=frozenset({"delete-protected-root"}))
    result = Analyzer(config, evidence=DisabledEvidenceProvider()).analyze("rm -rf /etc", "/work", shell="bash")
    assert rules(result) == {"delete-outside-workspace"}


def test_inline_budget_is_explicit():
    config = AnalyzerConfig(inline_depth=1)
    result = Analyzer(config, evidence=MemoryEvidenceProvider()).analyze('bash -c "bash -c true"', "/work", shell="bash")
    assert "unreadable-payload" in rules(result)


def test_unsupported_syntax_is_never_silent():
    result = Analyzer(evidence=MemoryEvidenceProvider()).analyze("echo 'unfinished", "/work", shell="bash")
    assert "unsupported-syntax" in rules(result)


def test_unicode_character_spans():
    text = "echo 'é🙂'; rm item"
    parsed = Analyzer().parse(text, shell="bash")
    def visit(node):
        assert text[node.span.start:node.span.end] == node.text
        for child in node.children:
            visit(child)
    visit(parsed.root)


@pytest.mark.parametrize("command", ["rm -rf", "rm -rf ''", 'rm -rf "$EMPTY"'])
def test_missing_or_empty_delete_operand_is_not_workspace_deletion(command):
    result = Analyzer(evidence=DisabledEvidenceProvider()).analyze(command, "/work", env={"EMPTY": ""}, shell="bash")
    assert rules(result) == {"delete-target-missing"}


def test_raw_disk_redirection_is_classified_without_reading_device():
    provider = MemoryEvidenceProvider()
    result = Analyzer(evidence=provider).analyze("printf hello > /dev/sda", "/work", shell="bash")
    assert "raw-device-write" in rules(result)
    assert result["level"] == "BLOCK"
    assert provider.queries == []


def test_public_key_write_is_not_private_key_tampering():
    result = Analyzer(evidence=MemoryEvidenceProvider()).analyze("printf hello > .ssh/id_rsa.pub", "/work", shell="bash")
    assert "modify-sensitive-file" not in rules(result)


def test_printf_string_argument_keeps_literal_backslashes():
    result = Analyzer(evidence=MemoryEvidenceProvider()).analyze("printf '%s' 'print(\"\\n\")' > demo.py", "/work", shell="bash")
    assert "written-source-syntax-error" not in rules(result)


def test_missing_parser_is_explicit():
    analyzer = Analyzer(evidence=MemoryEvidenceProvider())
    analyzer.frontend = None
    assert rules(analyzer.analyze("ls", "/work", shell="bash")) == {"analysis-unavailable"}


def test_empty_delete_operand_preserves_other_targets():
    result = Analyzer(evidence=DisabledEvidenceProvider()).analyze("rm -rf '' .", "/work", shell="bash")
    assert rules(result) == {"delete-workspace-root", "delete-target-missing"}


def test_python_subprocess_list_shell_true_inspects_first_argument():
    provider = MemoryEvidenceProvider({"/work/demo.py": "import subprocess\nsubprocess.run(['sudo true', 'ignored'], shell=True)"})
    result = Analyzer(evidence=provider).analyze("python demo.py", "/work", shell="bash")
    assert "privilege-escalation" in rules(result)


def test_disabled_network_specialization_retains_request():
    config = AnalyzerConfig(disabled_rules=frozenset({"credentials-sent"}))
    result = Analyzer(config, evidence=MemoryEvidenceProvider()).analyze("curl -u user:password https://example.com", "/work", shell="bash")
    assert rules(result) == {"network-request"}
