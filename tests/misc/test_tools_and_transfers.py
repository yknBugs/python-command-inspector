"""Command-position fallback and shared copy/move evidence, never execution."""
import json
import os
import subprocess

import pytest

from command_inspector import Analyzer, AnalyzerConfig
from command_inspector.config import load_config
from command_inspector.known_tools import KNOWN_TOOLS
from command_inspector.local_evidence import MemoryEvidenceProvider, ReadFile, StatTarget, EvidenceAnswer, EvidenceStatus
from command_inspector.models import ConfigurationError


@pytest.fixture(autouse=True)
def forbid_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Analysis executed a process")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "system", forbidden)


def analyze(command, shell="bash", files=None, config=None):
    provider = MemoryEvidenceProvider(files or {})
    cwd = "/work" if shell == "bash" else r"C:\work"
    report = Analyzer(config, evidence=provider).analyze_report(command, cwd, shell=shell)
    return report, provider


def entries(report, rule):
    return [f for f in report.findings if f.rule == rule]


@pytest.mark.parametrize("shell", ["bash", "powershell", "cmd"])
@pytest.mark.parametrize("command", ["crontab -r", "iptables -F", "ufw disable", "useradd -m bob",
    "usermod -aG sudo bob", "passwd bob", "mount device target", "truncate -s 0 important.log",
    "tar -xzf x.tar.gz", "ssh-keygen", "kubectl get pods", "terraform --help"])
def test_unmodeled_tools_are_always_medium(shell, command):
    report, provider = analyze(command, shell)
    finding, = entries(report, "tool-invoked")
    assert finding.level.name == "MEDIUM"
    assert finding.data["tool"] == command.split()[0]
    assert finding.data["category"] == KNOWN_TOOLS[command.split()[0]]
    assert finding.data["behavior_modeled"] is False
    assert not entries(report, "unknown-command")
    assert provider.queries == []


@pytest.mark.parametrize("shell,command", [
    ("bash", "echo crontab"), ("bash", "printf ufw"), ("bash", "# iptables -F"),
    ("powershell", "Write-Output ufw"), ("cmd", "echo crontab"),
    ("bash", "tldr"), ("bash", "man"), ("bash", "llama-cpp"),
    ("bash", "ufw-helper disable"), ("bash", "UFW disable"),
])
def test_only_exact_command_position_matches(shell, command):
    report, _ = analyze(command, shell)
    assert not entries(report, "tool-invoked")


@pytest.mark.parametrize("shell,command", [
    ("bash", "sudo ufw disable"), ("bash", "timeout 5 ufw disable"),
    ("bash", "env X=1 ufw disable"), ("bash", "/usr/sbin/ufw disable"),
    ("bash", "bash -c 'ufw disable'"),
    ("powershell", "UFW.EXE disable"), ("cmd", "UFW.EXE disable"),
    ("powershell", r"& 'C:\tools\ufw.exe' disable"), ("cmd", r"C:\tools\ufw.exe disable"),
])
def test_wrapped_inline_and_path_tool_names(shell, command):
    report, _ = analyze(command, shell)
    assert len(entries(report, "tool-invoked")) == 1


@pytest.mark.parametrize("shell,command", [
    ("bash", "docker ps --invented"), ("bash", "docker invented"),
    ("bash", "git invented"), ("bash", "curl --invented"),
    ("bash", "mv --invented a b"), ("bash", "systemctl invented"),
    ("bash", "find --invented"), ("bash", "conda invented"),
    ("powershell", "netsh invented"), ("cmd", "netsh invented"),
    ("powershell", "Copy-Item -Invented a b"), ("cmd", "copy /invented a b"),
    ("powershell", "dotnet invented"), ("cmd", "docker invented"),
])
def test_behavior_models_win_even_with_explicit_registration(shell, command):
    config = AnalyzerConfig(known_tools={command.split()[0]: "critical"})
    report, _ = analyze(command, shell, config=config)
    assert report.findings
    assert not entries(report, "tool-invoked")


def test_config_is_copied_and_empty_mapping_disables_default_recognition():
    names = {"customctl": "deployment"}
    config = AnalyzerConfig(known_tools=names)
    names["ufw"] = "firewall"
    assert entries(analyze("customctl", config=config)[0], "tool-invoked")
    assert not entries(analyze("ufw", config=config)[0], "tool-invoked")
    assert entries(analyze("ufw", config=AnalyzerConfig(known_tools={}))[0], "unknown-command")
    with pytest.raises(TypeError):
        config.known_tools["ufw"] = "firewall"


def test_toml_config_and_rule_disabling(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text('[tools.known]\ncustomctl = "deployment"\n')
    config = load_config(path)
    assert entries(analyze("customctl", config=config)[0], "tool-invoked")
    assert entries(analyze("ufw", config=config)[0], "unknown-command")
    config = AnalyzerConfig.from_mapping({"rules": {"tool-invoked": {"enabled": False}}})
    report, _ = analyze("ufw disable", config=config)
    assert report.to_dict() == {}


@pytest.mark.parametrize("known", [[], None, {"": "x"}, {"a b": "x"}, {"/bin/ufw": "x"},
    {"a\\b": "x"}, {"ufw": ""}, {"ufw": "\x00"}, {"ufw": 1}, {1: "x"}])
def test_invalid_tool_config_is_rejected(known):
    with pytest.raises(ConfigurationError):
        AnalyzerConfig(known_tools=known)


def test_tools_keep_distinct_identity_and_hide_arguments():
    report, _ = analyze("ufw disable; crontab -r; ufw disable; passwd --secret 'password=abcdefghijk'")
    assert {f.data["tool"] for f in entries(report, "tool-invoked")} == {"ufw", "crontab", "passwd"}
    assert "abcdefghijk" not in json.dumps(report.to_dict())
    catalog = Analyzer.rule_catalog()
    assert catalog["version"] == "1.13.0"
    rule, = [r for r in catalog["rules"] if r["rule"] == "tool-invoked"]
    assert rule["introduced_in"] == "1.5.0"
    assert rule["levels"] == ["MEDIUM"]


@pytest.mark.parametrize("shell,command", [
    ("bash", "mv source.txt target.txt"), ("bash", "cp source.txt target.txt"),
    ("powershell", "Move-Item source.txt target.txt"), ("powershell", "Copy-Item source.txt target.txt"),
    ("powershell", "mv source.txt target.txt"), ("powershell", "cp source.txt target.txt"),
    ("cmd", "move source.txt target.txt"), ("cmd", "copy source.txt target.txt"),
])
@pytest.mark.parametrize("destination_directory", [False, True])
def test_transfer_overwrite_lists_concrete_files(shell, command, destination_directory):
    root = "/work/" if shell == "bash" else "C:\\work\\"
    sep = "/" if shell == "bash" else "\\"
    target = root + "target.txt" + (sep + "source.txt" if destination_directory else "")
    report, provider = analyze(command, shell, {root + "source.txt": "new", target: "old"})
    finding, = entries(report, "overwrite-existing-file")
    assert finding.data["target"] == target
    assert finding.level.name == "LOW"
    assert not entries(report, "tool-invoked")
    assert not any(isinstance(q, ReadFile) for q in provider.queries)


@pytest.mark.parametrize("shell,command,invocation,source,target", [
    ("bash", "mv other.sh old.sh;", "bash old.sh", "other.sh", "old.sh"),
    ("bash", "cp other.sh old.sh;", "bash old.sh", "other.sh", "old.sh"),
    ("powershell", "Move-Item other.ps1 old.ps1;", "pwsh -File old.ps1", "other.ps1", "old.ps1"),
    ("powershell", "Copy-Item other.ps1 old.ps1;", "pwsh -File old.ps1", "other.ps1", "old.ps1"),
    ("cmd", "move other.cmd old.cmd &", "old.cmd", "other.cmd", "old.cmd"),
    ("cmd", "copy other.cmd old.cmd &", "old.cmd", "other.cmd", "old.cmd"),
])
def test_transfer_never_reads_prewrite_script_contents(shell, command, invocation, source, target):
    root = "/work/" if shell == "bash" else "C:\\work\\"
    report, provider = analyze(command + " " + invocation, shell, {root + target: "ufw disable", root + source: "true"})
    assert entries(report, "execution-content-unavailable")
    assert not entries(report, "tool-invoked")
    assert not any(isinstance(q, ReadFile) for q in provider.queries)


@pytest.mark.parametrize("command", ["mv new.txt /etc/passwd", "cp new.txt /etc/passwd"])
def test_sensitive_transfer_destination_is_high(command):
    report, _ = analyze(command, files={"/etc/passwd": "old"})
    assert report.level.name == "HIGH"
    assert entries(report, "modify-sensitive-file")[0].data["target"] == "/etc/passwd"
    assert entries(report, "overwrite-existing-file")


@pytest.mark.parametrize("command", ["mv -t out a b", "cp --target-directory=out a b", "mv a b out"])
def test_multiple_sources_map_to_directory(command):
    report, _ = analyze(command, files={"/work/out/a": "old", "/work/out/b": "old"})
    assert {f.data["target"] for f in entries(report, "overwrite-existing-file")} == {"/work/out/a", "/work/out/b"}


@pytest.mark.parametrize("command", ["mv -n new.sh old.sh; bash old.sh", "cp --no-clobber new.sh old.sh; bash old.sh",
    "mv -n new.sh out; bash out/new.sh"])
def test_known_no_clobber_retains_file_evidence(command):
    files = {"/work/old.sh": "true", "/work/out/new.sh": "true"}
    report, provider = analyze(command, files=files)
    assert not entries(report, "overwrite-existing-file")
    assert not entries(report, "execution-content-unavailable")
    assert any(isinstance(q, ReadFile) for q in provider.queries)


@pytest.mark.parametrize("command", ["mv -T src folder", "cp --no-target-directory src folder"])
def test_directory_itself_is_not_reported_as_overwritten_file(command):
    report, _ = analyze(command, files={"/work/folder/child": "old"})
    assert not entries(report, "overwrite-existing-file")


def test_new_destination_is_not_an_existing_overwrite():
    report, _ = analyze("mv old.txt new.txt", files={"/work/old.txt": "data"})
    assert not entries(report, "overwrite-existing-file")


def test_unresolved_write_invalidates_later_evidence():
    report, provider = analyze('mv new "$DEST"; bash old.sh', files={"/work/old.sh": "ufw disable"})
    assert entries(report, "write-variable-unresolved")
    assert entries(report, "execution-content-unavailable")
    assert not any(isinstance(q, ReadFile) for q in provider.queries)


def test_unused_function_move_preserves_evidence():
    report, provider = analyze("unused() { mv other.sh old.sh; }; bash old.sh", files={"/work/old.sh": "true"})
    assert not entries(report, "execution-content-unavailable")
    assert any(isinstance(q, ReadFile) for q in provider.queries)


@pytest.mark.parametrize("shell,command", [("bash", "mv source target"),
    ("powershell", "Move-Item source target"), ("cmd", "move source target")])
@pytest.mark.parametrize("answer", [
    EvidenceAnswer(EvidenceStatus.MISSING),
    EvidenceAnswer(EvidenceStatus.UNAVAILABLE, reason="filesystem_access_failed", complete=False),
    EvidenceAnswer(EvidenceStatus.AVAILABLE, {"kind": "symlink", "exists": True}),
    EvidenceAnswer(EvidenceStatus.AVAILABLE, {"kind": "special", "exists": True}),
])
def test_nonregular_or_unavailable_metadata_never_confirms_file_overwrite(shell, command, answer):
    class Provider(MemoryEvidenceProvider):
        def answer(self, request):
            self.queries.append(request)
            return answer
    provider = Provider({})
    report = Analyzer(evidence=provider).analyze_report(command, "/work" if shell == "bash" else r"C:\work", shell=shell)
    assert not entries(report, "overwrite-existing-file")
    assert not any(isinstance(q, ReadFile) for q in provider.queries)


@pytest.mark.parametrize("shell,command", [("bash", "cp source target"),
    ("powershell", "Copy-Item source target"), ("cmd", "copy source target")])
def test_binary_destination_can_still_be_a_confirmed_overwrite(shell, command):
    root = "/work/" if shell == "bash" else "C:\\work\\"
    report, provider = analyze(command, shell, {root + "target": b"\x00\xff\x80"})
    assert entries(report, "overwrite-existing-file")
    assert not any(isinstance(q, ReadFile) for q in provider.queries)


def test_conflicting_no_clobber_flags_do_not_hide_a_possible_overwrite():
    report, _ = analyze("mv -n -f source target", files={"/work/target": "old"})
    assert entries(report, "overwrite-existing-file")


def test_unmodeled_tool_prevents_stale_execution_evidence():
    report, provider = analyze("ufw disable; bash old.sh", files={"/work/old.sh": "rm -rf /etc"})
    assert entries(report, "tool-invoked")
    assert entries(report, "execution-content-unavailable")
    assert not entries(report, "delete-protected-root")
    assert not any(isinstance(q, ReadFile) for q in provider.queries)
