"""Discard destinations, write exemptions, clone downloads and su programs."""
import os
import subprocess

import pytest

from command_inspector import Analyzer, AnalyzerConfig
from command_inspector.config import load_config
from command_inspector.local_evidence import MemoryEvidenceProvider, ReadFile, StatTarget
from command_inspector.models import ConfigurationError


@pytest.fixture(autouse=True)
def forbid_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Analysis executed a proposed command")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "system", forbidden)


def analyze(command, shell="bash", *, cwd=None, env=None, config=None, files=None):
    cwd = cwd or ("/work" if shell == "bash" else r"C:\work")
    provider = MemoryEvidenceProvider(files or {})
    report = Analyzer(config, evidence=provider).analyze_report(command, cwd, shell=shell, env=env)
    return report, provider


def entries(report, rule):
    return [f for f in report.findings if f.rule == rule]


@pytest.mark.parametrize("command", [
    'echo "text" > /dev/null', 'echo text >> /dev/null', 'echo text >| /dev/null',
    'echo text > /dev/./null', 'echo text > /dev//null',
    'DEST=/dev/null; echo text > "$DEST"', 'echo text | tee /dev/null',
    'cat /dev/null',
    'printf password=abcdefghijk > /dev/null', 'cat secret > /dev/./null',
])
def test_posix_null_device_is_quiet_without_evidence(command):
    report, provider = analyze(command, files={"/work/secret": "password=abcdefghijk"})
    assert report.to_dict() == {}
    assert provider.queries == ([StatTarget("/work/secret")] if command == 'cat secret > /dev/./null' else [])


@pytest.mark.parametrize("shell,command,cwd", [
    ("powershell", "Write-Output text > /dev/null", "/work"),
    ("powershell", "Set-Content /dev/null text", "/work"),
    ("powershell", "Write-Output text > NUL", r"C:\work"),
    ("powershell", r"Set-Content C:\work\NUL text", r"C:\work"),
    ("cmd", "echo text > NUL", r"C:\work"),
    ("cmd", r"echo text > C:\work\NUL", r"C:\work"),
    ("cmd", "type NUL", r"C:\work"),
])
def test_platform_null_devices_are_quiet(shell, command, cwd):
    report, provider = analyze(command, shell, cwd=cwd)
    assert report.to_dict() == {}
    assert provider.queries == []


@pytest.mark.parametrize("command", ["true 2>/dev/null", "true 2>/dev/./null", "true &>/dev/null"])
def test_null_stderr_keeps_error_suppression_notice(command):
    report, _ = analyze(command)
    assert {f.rule for f in report.findings} == {"errors-suppressed"}


@pytest.mark.parametrize("command", ["echo text > /dev/null.log", "echo text > /dev/null/child", "rm /dev/null"])
def test_null_exemption_does_not_cover_similar_files_or_deletion(command):
    report, _ = analyze(command)
    assert entries(report, "write-outside-workspace") or entries(report, "delete-outside-workspace")


@pytest.mark.parametrize("shell", ["powershell", "cmd"])
def test_windows_dev_null_is_an_ordinary_drive_path(shell):
    report, _ = analyze("echo text > /dev/null", shell)
    assert entries(report, "write-outside-workspace")[0].data["target"] == r"C:\dev\null"


def test_python_null_write_uses_shared_discard_handling():
    report, provider = analyze("python -c \"from pathlib import Path; Path('/dev/null').write_text('password=abcdefghijk')\"")
    assert {f.rule for f in report.findings} == {"uses-interpreter", "hardcoded-secret"}
    assert provider.queries == []


@pytest.mark.parametrize("shell,command,path", [
    ("bash", "echo text > /tmp/output", "/tmp/output"),
    ("powershell", r"Write-Output text > C:\outside\output", r"C:\outside\output"),
    ("cmd", r"echo text > C:\outside\output", r"c:\OUTSIDE\output"),
])
def test_exact_configured_write_path_suppresses_only_location(shell, command, path):
    report, _ = analyze(command, shell, config=AnalyzerConfig(allowed_write_paths=(path,)))
    assert not entries(report, "write-outside-workspace")


@pytest.mark.parametrize("path", ["/tmp/output-other", "/tmp/output/child"])
def test_allowlist_is_not_a_directory_or_prefix_exemption(path):
    report, _ = analyze("echo text > " + path, config=AnalyzerConfig(allowed_write_paths=("/tmp/output",)))
    assert entries(report, "write-outside-workspace")


def test_allowed_write_path_still_checks_content_sensitive_files_and_mutation():
    report, _ = analyze("echo password=abcdefghijk > /etc/passwd", config=AnalyzerConfig(allowed_write_paths=("/etc/passwd",)))
    assert not entries(report, "write-outside-workspace")
    assert entries(report, "modify-sensitive-file")
    assert entries(report, "credentials-written")
    report, provider = analyze("echo new > /tmp/script.sh; bash /tmp/script.sh",
                               config=AnalyzerConfig(allowed_write_paths=("/tmp/script.sh",)),
                               files={"/tmp/script.sh": "rm -rf /etc"})
    assert not entries(report, "delete-protected-root")
    assert entries(report, "execution-content-unavailable")[0].data["reason"] == "changed_earlier"
    assert not any(isinstance(q, ReadFile) for q in provider.queries)


def test_allowed_write_does_not_suppress_ingestion_or_deletion():
    config = AnalyzerConfig(allowed_write_paths=("/tmp/data",))
    report, _ = analyze("cat /tmp/data", config=config, files={"/tmp/data": "password=abcdefghijk"})
    assert entries(report, "read-outside-workspace")
    assert entries(report, "credentials-read")
    report, _ = analyze("rm /tmp/data", config=config)
    assert entries(report, "delete-outside-workspace")


@pytest.mark.parametrize("value", ["/tmp/x", None, 4, ["relative"], [4], ["/bad\x00path"]])
def test_invalid_allowed_write_config(value):
    with pytest.raises(ConfigurationError):
        AnalyzerConfig(allowed_write_paths=value)
    with pytest.raises(ConfigurationError):
        AnalyzerConfig.from_mapping({"workspace": {"allowed_write_paths": value}})


def test_allowed_write_mapping_toml_and_defensive_copy(tmp_path):
    paths = ["/tmp/output"]
    config = AnalyzerConfig(allowed_write_paths=paths)
    paths.append("/etc/passwd")
    assert config.allowed_write_paths == ("/tmp/output",)
    path = tmp_path / "config.toml"
    path.write_text('[workspace]\nallowed_write_paths = ["/tmp/output"]\n')
    assert load_config(path).allowed_write_paths == ("/tmp/output",)


@pytest.mark.parametrize("command", [
    "su -c 'rm -rf /*'", "su root -c 'rm -rf /*'", "su -c 'rm -rf /*' root",
    "su --command='rm -rf /*'", "su --session-command='rm -rf /*'", "su -C 'rm -rf /*'",
    "su -lc 'rm -rf /*'", "su - -c 'rm -rf /*'", "su --login root --command 'rm -rf /*'",
    "su -s /bin/bash -c 'rm -rf /*'", "su --shell=/bin/sh root -c 'rm -rf /*'",
    "sudo su -c 'rm -rf /*'", "timeout 2 su -c 'rm -rf /*'", "/bin/su -c 'rm -rf /*'",
    "env TARGET=/etc su -c 'rm -rf \"$TARGET\"'",
])
def test_su_shell_program_cannot_hide_destructive_operations(command):
    report, _ = analyze(command)
    assert entries(report, "delete-protected-root")[0].level.name == "BLOCK"
    assert entries(report, "privilege-escalation")
    assert not entries(report, "tool-invoked")
    assert not entries(report, "unknown-command")


@pytest.mark.parametrize("shell,command", [
    ("powershell", "su -c 'rm -rf /*'"), ("cmd", 'su -c "rm -rf /*"'),
])
def test_native_su_uses_shared_model_in_windows_profiles(shell, command):
    report, _ = analyze(command, shell)
    assert entries(report, "delete-protected-root")
    assert entries(report, "privilege-escalation")


@pytest.mark.parametrize("command", ["su -c rm -rf /*", "su -crm -rf /*", "su --command=rm -rf /*", "su -lcrm -rf /*"])
def test_invalid_unquoted_su_does_not_invent_an_rm_execution(command):
    report, _ = analyze(command)
    assert report.level.name == "HIGH"
    assert not entries(report, "delete-protected-root")
    assert not entries(report, "uses-interpreter")
    assert entries(report, "unknown-option")


@pytest.mark.parametrize("command", ["su --help", "su -h", "su --version", "su -V", "su -c 'rm -rf /*' --help"])
def test_su_queries_do_not_inspect_program_or_switch_user(command):
    assert analyze(command)[0].to_dict() == {}


@pytest.mark.parametrize("command", ["su", "su alice", "su -c \"$PROGRAM\"", "su -s /bin/customshell -c text"])
def test_su_unavailable_programs_or_shells_keep_coverage(command):
    report, _ = analyze(command)
    assert entries(report, "privilege-escalation")
    assert entries(report, "execution-content-unavailable")


def test_missing_su_command_argument_cannot_start_shell():
    report, _ = analyze("su -c")
    assert report.level.name == "HIGH"
    assert entries(report, "unknown-option")
    assert not entries(report, "uses-interpreter")


def test_su_valid_positional_arguments_are_not_reparsed_as_code():
    report, _ = analyze("su -c 'echo ok' alice 'rm -rf /*'")
    assert not entries(report, "delete-protected-root")
    assert entries(report, "privilege-escalation")[0].data["target_user"] == "alice"


@pytest.mark.parametrize("options,known", [("", False), ("-p", True), ("--preserve-environment", True), ("-lp", False)])
def test_su_environment_reset_and_preservation(options, known):
    report, _ = analyze(f"su {options} -c 'rm -rf \"$HOME\"'", env={"HOME": "/work/oldhome"})
    assert bool(entries(report, "delete-inside-workspace")) is known
    assert bool(entries(report, "delete-variable-unresolved")) is not known


@pytest.mark.parametrize("whitelist,known", [("", False), ("--whitelist-environment=TARGET", True)])
def test_login_su_environment_whitelist_is_explicit(whitelist, known):
    report, _ = analyze(f"su --login {whitelist} -c 'rm -rf \"$TARGET\"'", env={"TARGET": "/etc"})
    assert bool(entries(report, "delete-protected-root")) is known
    assert bool(entries(report, "delete-variable-unresolved")) is not known


def test_login_su_does_not_reuse_callers_working_directory():
    report, _ = analyze("su -l -c 'rm -rf local'")
    assert entries(report, "delete-variable-unresolved")
    assert not entries(report, "delete-inside-workspace")


def test_su_switch_preserves_outer_expansion_and_parent_environment():
    report, _ = analyze('su -lc "rm -rf $TARGET"', env={"TARGET": "/etc"})
    assert entries(report, "delete-protected-root")
    report, _ = analyze("su -c 'TARGET=/etc'; rm -rf \"$TARGET\"", env={"TARGET": "/work/safe"})
    assert not entries(report, "delete-protected-root")
    assert entries(report, "delete-inside-workspace")[0].data["target"] == "/work/safe"


def test_su_explicit_python_shell_uses_python_semantics():
    report, _ = analyze('su -s /usr/bin/python3 -c "import os; os.remove(\'victim\')"')
    assert entries(report, "delete-inside-workspace")
    assert entries(report, "uses-interpreter")[0].data["interpreters"] == ["python3"]
