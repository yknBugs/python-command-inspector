"""Unknown commands retain their names through grouping and tool promotion."""
import json

import pytest

from command_inspector import Analyzer
from command_inspector.local_evidence import MemoryEvidenceProvider


def analyze(command, shell="bash"):
    cwd = "/work" if shell == "bash" else r"C:\work"
    return Analyzer(evidence=MemoryEvidenceProvider({})).analyze_report(command, cwd, shell=shell)


@pytest.mark.parametrize("shell,separator", [("bash", ";"), ("powershell", ";"), ("cmd", "&")])
def test_distinct_unknown_commands_survive_deduplication(shell, separator):
    report = analyze(f"mysteryone {separator} mysterytwo {separator} mysteryone", shell)
    findings = [f for f in report.findings if f.rule == "unknown-command"]
    assert len(findings) == 2
    assert {f.data["command"] for f in findings} == {"mysteryone", "mysterytwo"}
    for finding in findings:
        assert finding.level.name == "LOW"
        assert finding.data["command_resolved"] is True
        assert finding.data["command"] in finding.title


@pytest.mark.parametrize("shell,command", [("bash", "docker invented; mysteryone"),
    ("powershell", "docker invented; mysteryone"), ("cmd", "docker invented & mysteryone")])
def test_unsupported_modeled_operation_retains_application_name(shell, command):
    findings = [f for f in analyze(command, shell).findings if f.rule == "unknown-command"]
    assert {f.data["command"] for f in findings} == {"docker", "mysteryone"}
    docker, = [f for f in findings if f.data["command"] == "docker"]
    assert docker.data["reason"] == "Unsupported Docker operation"


@pytest.mark.parametrize("shell,command", [("bash", "ufw disable; mysteryone"),
    ("powershell", "ufw disable; mysteryone"), ("cmd", "ufw disable & mysteryone")])
def test_tool_promotion_preserves_command_identity_and_other_unknowns(shell, command):
    findings = analyze(command, shell).findings
    tool, = [f for f in findings if f.rule == "tool-invoked"]
    assert tool.level.name == "MEDIUM"
    assert tool.data["command"] == "ufw"
    assert tool.data["tool"] == "ufw"
    assert tool.data["category"]
    unknown, = [f for f in findings if f.rule == "unknown-command"]
    assert unknown.data["command"] == "mysteryone"


@pytest.mark.parametrize("command", ["timeout 3 mysteryone; timeout 3 mysterytwo",
    "sudo mysteryone; sudo mysterytwo", "bash -c 'mysteryone; mysterytwo'",
    "find . -exec mysteryone {} \\; -exec mysterytwo {} \\;"])
def test_wrappers_and_inline_code_report_inner_command_names(command):
    findings = [f for f in analyze(command).findings if f.rule == "unknown-command"]
    assert {f.data["command"] for f in findings} == {"mysteryone", "mysterytwo"}


@pytest.mark.parametrize("shell,command", [("bash", "$MISSING"), ("powershell", "& $missing"), ("cmd", "%MISSING%")])
def test_dynamic_names_are_explicitly_unresolved(shell, command):
    unknown, = [f for f in analyze(command, shell).findings if f.rule == "unknown-command"]
    assert unknown.data["command"] is None
    assert unknown.data["command_resolved"] is False


@pytest.mark.parametrize("shell,command,expected", [
    ("bash", "/usr/sbin/ufw disable", "/usr/sbin/ufw"),
    ("powershell", "ufw.exe disable", "ufw.exe"),
    ("cmd", "ufw.exe disable", "ufw.exe"),
    ("powershell", r"& 'C:\tools\ufw.exe' disable", r"c:\tools\ufw.exe"),
    ("cmd", r"C:\tools\ufw.exe disable", r"c:\tools\ufw.exe"),
])
def test_promoted_paths_preserve_invocation_and_catalog_name(shell, command, expected):
    tool, = [f for f in analyze(command, shell).findings if f.rule == "tool-invoked"]
    assert tool.data["command"] == expected
    assert tool.data["tool"] == "ufw"


def test_unknown_python_modules_keep_distinct_module_identity():
    report = analyze("python -m mysteryone; python -m mysterytwo")
    findings = [f for f in report.findings if f.rule == "unknown-command"]
    assert len(findings) == 2
    assert {f.data["module"] for f in findings} == {"mysteryone", "mysterytwo"}
    assert {f.data["command"] for f in findings} == {"python"}


def test_command_identity_does_not_export_arguments():
    report = analyze("mysteryone --password 'do-not-export-this-argument'")
    assert "do-not-export-this-argument" not in json.dumps(report.to_dict())
