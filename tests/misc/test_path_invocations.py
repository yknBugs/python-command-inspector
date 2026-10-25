"""Executable path notices preserve behavior and direct-source boundaries."""
import os
import subprocess
import stat
import tomllib
from pathlib import Path
from types import SimpleNamespace

import pytest

from command_inspector import Analyzer, AnalyzerConfig
from command_inspector.local_evidence import (
    DisabledEvidenceProvider, EvidenceAnswer, EvidenceStatus, LocalEvidenceProvider,
    MemoryEvidenceProvider, ReadFile, StatTarget,
)


PATH_RULES = {"command-via-path", "executable-via-path", "execute-target-missing", "execute-target-not-executable"}


@pytest.fixture(autouse=True)
def forbid_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Analysis executed a process")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "system", forbidden)


def analyze(command, shell="bash", *, files=None, answers=None, provider=None, config=None, env=None):
    provider = provider if provider is not None else MemoryEvidenceProvider(files, answers)
    report = Analyzer(config, evidence=provider).analyze_report(
        command, "/work" if shell == "bash" else r"C:\work", shell=shell, env=env)
    return report, provider


def entries(report, rule):
    return [f for f in report.findings if f.rule == rule]


@pytest.mark.parametrize("shell,command,target,path_type", [
    ("bash", "/opt/tools/git push", "/opt/tools/git", "absolute"),
    ("bash", "../tools/git push", "/tools/git", "relative"),
    ("bash", "tools/git push", "/work/tools/git", "relative"),
    ("bash", "'./Program Files/git' push", "/work/Program Files/git", "relative"),
    ("powershell", r"& 'C:\Program Files\git\GIT.EXE' push", r"C:\Program Files\git\GIT.EXE", "absolute"),
    ("powershell", r"& '..\tools\git.exe' push", r"C:\tools\git.exe", "relative"),
    ("powershell", "& './tools/git.exe' push", r"C:\work\tools\git.exe", "relative"),
    ("cmd", r'"C:\Program Files\git\git.exe" push', r"C:\Program Files\git\git.exe", "absolute"),
    ("cmd", r"..\tools\git.exe push", r"C:\tools\git.exe", "relative"),
    ("cmd", "tools/git.exe push", r"C:\work\tools\git.exe", "relative"),
    ("cmd", r"@.\tools\git.exe push", r"C:\work\tools\git.exe", "relative"),
])
def test_known_path_keeps_git_model_without_reading_binary(shell, command, target, path_type):
    report, provider = analyze(command, shell, files={target: b"\x00invalid executable"})
    assert entries(report, "git-push")[0].level.name == "MEDIUM"
    path, = entries(report, "command-via-path")
    assert path.level.name == "LOW"
    assert path.data["tool"] == "git"
    assert path.data["path_type"] == path_type
    assert path.data["target"].casefold() == target.casefold()
    assert not entries(report, "unknown-command")
    assert not entries(report, "execute-target-missing")
    assert not any(isinstance(q, ReadFile) for q in provider.queries)


@pytest.mark.parametrize("shell,command,target", [
    ("bash", "../env/python -c 'import os; os.remove(\"victim\")'", "/env/python"),
    ("powershell", r"& 'C:\Program Files\Python\python.exe' -c 'import os; os.remove(" + '"victim"' + ")'", r"C:\Program Files\Python\python.exe"),
    ("cmd", "C:\\tools\\python.exe -c \"import os; os.remove('victim')\"", r"C:\tools\python.exe"),
])
def test_known_interpreter_path_keeps_inline_semantics(shell, command, target):
    report, _ = analyze(command, shell, files={target: b"\x00"})
    assert entries(report, "command-via-path")
    assert entries(report, "uses-interpreter")
    assert entries(report, "delete-inside-workspace")


@pytest.mark.parametrize("shell,command", [
    ("bash", "./tools/docker invented"),
    ("powershell", r"& '.\tools\docker.exe' invented"),
    ("cmd", r".\tools\docker.exe invented"),
])
def test_path_modeled_but_unsupported_operation_keeps_coverage(shell, command):
    report, _ = analyze(command, shell)
    unknown, = entries(report, "unknown-command")
    assert unknown.data["reason"] == "Unsupported Docker operation"
    assert "docker" in unknown.data["command"]
    assert entries(report, "command-via-path")
    assert not entries(report, "tool-invoked")


@pytest.mark.parametrize("shell,command", [
    ("bash", "./tools/ufw disable"),
    ("powershell", r"& '.\tools\ufw.exe' disable"),
    ("cmd", r".\tools\ufw.exe disable"),
])
def test_registered_tool_path_keeps_medium_catalog_finding(shell, command):
    report, provider = analyze(command, shell)
    assert entries(report, "tool-invoked")[0].level.name == "MEDIUM"
    assert entries(report, "command-via-path")[0].data["tool"] == "ufw"
    assert not entries(report, "unknown-command")
    assert not any(isinstance(q, ReadFile) for q in provider.queries)


@pytest.mark.parametrize("shell,command", [
    ("bash", "./deployctl --help"),
    ("powershell", r"& '.\deployctl.exe' --help"),
    ("cmd", r".\deployctl.exe --help"),
])
@pytest.mark.parametrize("registered", [False, True])
def test_path_known_tools_obeys_replacement_config(shell, command, registered):
    config = AnalyzerConfig(known_tools={"deployctl": "deployment"} if registered else {})
    report, _ = analyze(command, shell, config=config)
    assert bool(entries(report, "tool-invoked")) is registered
    assert bool(entries(report, "command-via-path")) is registered
    assert bool(entries(report, "executable-via-path")) is not registered
    assert not entries(report, "unknown-command")


@pytest.mark.parametrize("shell,command,target", [
    ("bash", "/work/build/bin/compiled_output", "/work/build/bin/compiled_output"),
    ("bash", "build/bin/compiled_output", "/work/build/bin/compiled_output"),
    ("powershell", r"& '.\build\compiled_output.exe'", r"C:\work\build\compiled_output.exe"),
    ("cmd", r".\build\compiled_output.exe", r"C:\work\build\compiled_output.exe"),
])
@pytest.mark.parametrize("exists", [False, True])
def test_unknown_executable_paths_never_read_binary_or_report_unknown(shell, command, target, exists):
    report, provider = analyze(command, shell, files={target: b"\x00password=secretvalue"} if exists else {})
    assert entries(report, "executable-via-path")[0].level.name == "LOW"
    assert bool(entries(report, "execute-target-missing")) is not exists
    assert not entries(report, "unknown-command")
    assert not entries(report, "execution-content-unavailable")
    assert all(isinstance(q, StatTarget) for q in provider.queries)


@pytest.mark.parametrize("shell,command,target", [
    ("bash", "./program", "/work/program"),
    ("powershell", r"& '.\program.exe'", r"C:\work\program.exe"),
    ("cmd", r".\program.exe", r"C:\work\program.exe"),
])
@pytest.mark.parametrize("executable", [False, True, None])
def test_explicit_executable_evidence(shell, command, target, executable):
    profile = "posix" if shell == "bash" else "windows"
    answer = EvidenceAnswer(EvidenceStatus.AVAILABLE, {"kind": "file", "executable": executable})
    report, _ = analyze(command, shell, answers={StatTarget(target, profile): answer})
    assert bool(entries(report, "execute-target-not-executable")) is (executable is False)
    assert not entries(report, "execute-target-missing")


@pytest.mark.parametrize("status", [EvidenceStatus.UNAVAILABLE, EvidenceStatus.TRUNCATED])
@pytest.mark.parametrize("reason", ["permission_denied", "evidence_disabled", "host_path_style_mismatch"])
def test_unavailable_metadata_does_not_mean_missing_or_not_executable(status, reason):
    answer = EvidenceAnswer(status, {"executable": False}, reason=reason, complete=False)
    report, _ = analyze("./program", answers={StatTarget("/work/program", "posix"): answer})
    path, = entries(report, "executable-via-path")
    assert path.data["evidence_reason"] == reason
    assert not entries(report, "execute-target-missing")
    assert not entries(report, "execute-target-not-executable")


@pytest.mark.parametrize("kind,not_executable", [("directory", True), ("special", True), ("symlink", False)])
def test_nonregular_path_metadata(kind, not_executable):
    report, _ = analyze("./program", answers={StatTarget("/work/program", "posix"):
                       EvidenceAnswer(EvidenceStatus.AVAILABLE, {"kind": kind})})
    assert bool(entries(report, "execute-target-not-executable")) is not_executable


@pytest.mark.parametrize("shell,command,target,content", [
    ("bash", "./bash.sh", "/work/bash.sh", "rm -rf /etc"),
    ("bash", "../tools/bash.sh", "/tools/bash.sh", "rm -rf /etc"),
    ("bash", "./cmd.bat", "/work/cmd.bat", "rd /s /q C:\\"),
    ("bash", "./powershell.ps", "/work/powershell.ps", "Remove-Item -Recurse -Force C:\\"),
    ("powershell", r"& '.\powershell.ps'", r"C:\work\powershell.ps", "Remove-Item -Recurse -Force C:\\"),
    ("powershell", r"& '.\powershell.ps1'", r"C:\work\powershell.ps1", "Remove-Item -Recurse -Force C:\\"),
    ("powershell", r"& '.\Task.PS1'", r"C:\work\Task.PS1", "Remove-Item -Recurse -Force C:\\"),
    ("powershell", r"& '.\cmd.bat'", r"C:\work\cmd.bat", "rd /s /q C:\\"),
    ("cmd", r".\cmd.bat", r"C:\work\cmd.bat", "rd /s /q C:\\"),
    ("cmd", r".\cmd.cmd", r"C:\work\cmd.cmd", "rd /s /q C:\\"),
    ("cmd", r".\powershell.ps", r"C:\work\powershell.ps", "Remove-Item -Recurse -Force C:\\"),
])
def test_direct_script_paths_inspect_source_and_skip_new_rules(shell, command, target, content):
    report, provider = analyze(command, shell, files={target: content})
    assert any(f.rule.startswith("delete-") and f.data["context"] == "direct_artifact" for f in report.findings)
    if shell != "bash" or target.endswith(".sh"):
        assert entries(report, "delete-protected-root")
    if shell != "bash":
        assert entries(report, "uses-interpreter")
    assert not PATH_RULES & {f.rule for f in report.findings}
    assert any(isinstance(q, ReadFile) for q in provider.queries)


@pytest.mark.parametrize("shell,command", [
    ("bash", "./missing.sh"),
    ("powershell", r"& '.\missing.ps1'"),
    ("cmd", r".\missing.bat"),
])
def test_missing_script_keeps_source_unavailability(shell, command):
    report, _ = analyze(command, shell)
    assert entries(report, "execution-content-unavailable")
    assert PATH_RULES & {f.rule for f in report.findings} == {"execute-target-missing"}


@pytest.mark.parametrize("command", [
    "echo 'rm -rf /*' | /usr/bin/bash",
    "echo 'rm -rf /*' | timeout 3 /usr/bin/bash",
    "echo 'rm -rf /*' | /usr/bin/timeout 3 /usr/bin/bash",
    "echo 'rm -rf /*' | /usr/bin/env /usr/bin/bash",
])
def test_path_wrappers_preserve_literal_stdin(command):
    report, _ = analyze(command)
    assert entries(report, "delete-protected-root")
    assert entries(report, "command-via-path")


@pytest.mark.parametrize("command", [
    "timeout 3 ../tools/git push", "sudo tools/git push", "env X=1 tools/git push",
    "conda run -n test tools/git push", "/usr/bin/env -C /other tools/git push",
])
def test_wrappers_preserve_inner_path_behavior_and_cwd(command):
    report, _ = analyze(command)
    assert entries(report, "git-push")
    paths = entries(report, "command-via-path")
    assert any(f.data["tool"] == "git" for f in paths)
    if "-C /other" in command:
        assert next(f.data["target"] for f in paths if f.data["tool"] == "git") == "/other/tools/git"


@pytest.mark.parametrize("command", ["rm program; ./program", "mv other program; ./program", "ufw disable; ./program"])
def test_changed_target_never_reuses_missing_or_permission_evidence(command):
    report, provider = analyze(command)
    path, = entries(report, "executable-via-path")
    assert path.data["evidence_reason"] == "changed_earlier"
    assert not entries(report, "execute-target-missing")
    assert not entries(report, "execute-target-not-executable")
    assert StatTarget("/work/program", "posix") not in provider.queries


def test_unknown_executable_invalidates_later_source_contents():
    report, provider = analyze("./program; ./later.sh", files={"/work/program": b"\x00", "/work/later.sh": "rm -rf /etc"})
    assert not entries(report, "delete-protected-root")
    assert entries(report, "execution-content-unavailable")[0].data["reason"] == "changed_earlier"
    assert not any(isinstance(q, ReadFile) for q in provider.queries)


@pytest.mark.parametrize("missing", [True, False])
def test_confirmed_unrunnable_executable_preserves_later_source_evidence(missing):
    answer = EvidenceAnswer(EvidenceStatus.MISSING) if missing else EvidenceAnswer(
        EvidenceStatus.AVAILABLE, {"kind": "file", "executable": False})
    report, provider = analyze("./program; ./later.sh", files={"/work/later.sh": "rm -rf /etc"},
                               answers={StatTarget("/work/program", "posix"): answer})
    assert entries(report, "delete-protected-root")
    assert any(isinstance(q, ReadFile) for q in provider.queries)


@pytest.mark.parametrize("shell,command", [("powershell", r"& '.\program.xyz'"), ("cmd", r".\program.xyz")])
@pytest.mark.parametrize("pathext,not_executable", [(None, False), (".EXE;.COM", True), (".EXE;.XYZ", False)])
def test_windows_execution_uses_supplied_pathext(shell, command, pathext, not_executable):
    report, _ = analyze(command, shell, files={r"C:\work\program.xyz": b"\x00"},
                        env={"PATHEXT": pathext} if pathext is not None else {})
    assert bool(entries(report, "execute-target-not-executable")) is not_executable


@pytest.mark.parametrize("executable", [False, True])
@pytest.mark.skipif(os.name != 'posix', reason='POSIX execute bits are not available on this host')
def test_posix_local_metadata_checks_execute_permission_without_reading(tmp_path, executable):
    target = tmp_path / "program"
    target.write_bytes(b"\x00compiled binary")
    target.chmod(0o700 if executable else 0o600)
    # A relative command avoids interpreting backslashes or spaces in tmp roots.
    report = Analyzer().analyze_report('./program', str(tmp_path), shell='bash')
    assert bool(entries(report, "execute-target-not-executable")) is not executable
    assert not entries(report, "execution-content-unavailable")


def test_local_symlink_permission_is_not_inferred(tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"\x00")
    target.chmod(0o600)
    link = tmp_path / "program"
    try:
        link.symlink_to(target)
    except OSError as error:
        if getattr(error, 'winerror', None) == 1314:
            pytest.skip('Windows did not grant permission to create a symlink')
        raise
    answer = LocalEvidenceProvider().answer(StatTarget(str(link), "posix"))
    assert answer.data["kind"] == "symlink"
    assert answer.data["executable"] is None


@pytest.mark.parametrize('execution_profile', ['posix', 'windows'])
def test_windows_host_never_infers_executable_permission_from_mode_bits(tmp_path, monkeypatch, execution_profile):
    import command_inspector.local_evidence as evidence_module
    target = tmp_path / 'program'
    target.write_bytes(b'\x00')
    def forbidden(*args, **kwargs):
        pytest.fail('Windows metadata borrowed POSIX permissions or read content')
    # Replace this module's OS facade, leaving pathlib/pytest's actual host alone.
    monkeypatch.setattr(evidence_module, 'os', SimpleNamespace(name='nt', path=os.path,
                        lstat=os.lstat, access=forbidden, open=forbidden))
    answer = LocalEvidenceProvider().answer(StatTarget(str(target), execution_profile))
    assert answer.status is EvidenceStatus.AVAILABLE
    assert answer.data['kind'] == 'file'
    assert answer.data['executable'] is None


@pytest.mark.parametrize('link_kind', ['symlink', 'reparse_point'])
def test_link_metadata_does_not_need_symlink_creation_privileges(monkeypatch, link_kind):
    import command_inspector.local_evidence as evidence_module
    monkeypatch.setattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 1024, raising=False)
    info = SimpleNamespace(st_mode=stat.S_IFLNK if link_kind == 'symlink' else stat.S_IFDIR,
                           st_size=0, st_file_attributes=1024 if link_kind == 'reparse_point' else 0)
    def forbidden(*args, **kwargs):
        pytest.fail('Link metadata followed the target or read its content')
    monkeypatch.setattr(evidence_module, 'os', SimpleNamespace(name='nt', path=SimpleNamespace(isabs=lambda _: True),
                        lstat=lambda _: info, access=forbidden, open=forbidden))
    answer = LocalEvidenceProvider().answer(StatTarget(r'C:\work\link', 'windows'))
    assert answer.status is EvidenceStatus.AVAILABLE
    assert answer.data['kind'] == 'symlink'
    assert answer.data['executable'] is None


def test_disabled_evidence_and_rule_disabling():
    report, _ = analyze("./program", provider=DisabledEvidenceProvider())
    assert {f.rule for f in report.findings} == {"executable-via-path"}
    config = AnalyzerConfig(disabled_rules=frozenset(PATH_RULES))
    report, _ = analyze("./program", config=config)
    assert report.to_dict() == {}


def test_catalog_path_rules_are_low_and_introduced_in_1_6():
    catalog = Analyzer.rule_catalog()
    assert catalog["version"] == "1.16.0"
    for rule in catalog["rules"]:
        if rule["rule"] in PATH_RULES:
            assert rule["levels"] == ["LOW"]
            assert rule["introduced_in"] == "1.6.0"


def test_package_report_and_catalog_versions_match():
    project = tomllib.loads((Path(__file__).parents[2] / "pyproject.toml").read_text())
    report, _ = analyze("./program")
    assert project["project"]["version"] == report.analyzer_version == report.rule_catalog_version == "1.16.0"


@pytest.mark.parametrize("shell,command", [
    ("bash", "git status; echo /opt/tools/git"),
    ("powershell", r"'C:\tools\git.exe'; Write-Output '.\program.exe'"),
    ("cmd", r"echo .\program.exe"),
])
def test_only_command_position_paths_get_notices(shell, command):
    report, _ = analyze(command, shell)
    assert not PATH_RULES & {f.rule for f in report.findings}


@pytest.mark.parametrize("shell,command", [
    ("bash", "BIN=./tools/git; \"$BIN\" push"),
    ("powershell", r"$exe = '.\tools\git.exe'; & $exe push"),
    ("cmd", "set exe=.\\tools\\git.exe\n%exe% push"),
])
def test_resolved_command_variables_use_path_model(shell, command):
    report, _ = analyze(command, shell)
    assert entries(report, "git-push")
    assert entries(report, "command-via-path")


def test_direct_script_retains_prefix_environment():
    report, _ = analyze("TARGET=/etc ./cleanup.sh", files={"/work/cleanup.sh": 'rm -rf "$TARGET"'})
    assert entries(report, "delete-protected-root")
    assert not PATH_RULES & {f.rule for f in report.findings}


def test_linux_name_matching_is_case_sensitive():
    report, _ = analyze("./tools/GIT push")
    assert entries(report, "executable-via-path")
    assert not entries(report, "command-via-path")
    assert not entries(report, "git-push")


@pytest.mark.parametrize("shell,command", [
    ("bash", "./one; ./two"),
    ("powershell", r"& '.\one.exe'; & '.\two.exe'"),
    ("cmd", r".\one.exe & .\two.exe"),
])
def test_distinct_executable_paths_survive_deduplication(shell, command):
    report, _ = analyze(command, shell)
    assert len(entries(report, "executable-via-path")) == 2
