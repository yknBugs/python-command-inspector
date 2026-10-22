"""Model registration contracts: facts flow through existing detectors safely."""
import os
import subprocess

import pytest

from command_inspector import Analyzer, AnalyzerConfig
from command_inspector.local_evidence import MemoryEvidenceProvider
from command_inspector.models import Fact, Value
from command_inspector.shared import builtins
from command_inspector.shared.commands import describe
from command_inspector.shared.options import CommandSpec, parse_options
from command_inspector.shared.registry import CommandInvocation, CommandModel, CommandRegistry


@pytest.fixture(autouse=True)
def forbid_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Command model executed submitted text")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "system", forbidden)


def install(monkeypatch, model):
    registry = CommandRegistry((*builtins.command_registry().models, model))
    monkeypatch.setattr(builtins, "command_registry", lambda: registry)
    return registry


def deletion(invocation):
    return [Fact("delete", "delete", values=invocation.args, flags=frozenset({"-r", "-f"}))]


@pytest.mark.parametrize("shell", ["bash", "powershell", "cmd"])
def test_registered_model_reaches_all_adapters_and_existing_detectors(monkeypatch, shell):
    install(monkeypatch, CommandModel({"fixture-delete"}, deletion))
    cwd = "/work" if shell == "bash" else r"C:\work"
    target = "/etc" if shell == "bash" else "C:\\"
    report = Analyzer(evidence=MemoryEvidenceProvider({})).analyze_report(f"fixture-delete {target}", cwd, shell=shell, effort="None")
    finding, = report.findings
    assert finding.rule == "delete-protected-root" and finding.level.name == "BLOCK"
    assert finding.data["target"] == target


@pytest.mark.parametrize("shell,command", [
    ("bash", "./fixture-delete /etc"),
    ("powershell", "& '.\\fixture-delete.exe' C:\\"),
    ("cmd", ".\\fixture-delete.exe C:\\"),
])
def test_registered_executable_paths_retain_behavior_and_path_notice(monkeypatch, shell, command):
    install(monkeypatch, CommandModel({"fixture-delete"}, deletion, {shell}))
    report = Analyzer(evidence=MemoryEvidenceProvider({})).analyze_report(command, "/work" if shell == "bash" else r"C:\work", shell=shell, effort="None")
    assert {f.rule for f in report.findings} == {"command-via-path", "delete-protected-root"}


@pytest.mark.parametrize("shell", ["bash", "powershell", "cmd"])
def test_registered_quiet_model_never_uses_tool_fallback(monkeypatch, shell):
    observed = []
    def quiet(invocation):
        observed.append(invocation)
        return []
    install(monkeypatch, CommandModel({"fixture-query"}, quiet, {shell}))
    analyzer = Analyzer(AnalyzerConfig(known_tools={"fixture-query": "test application"}), evidence=MemoryEvidenceProvider({}))
    cwd = "/work" if shell == "bash" else r"C:\work"
    assert analyzer.analyze("fixture-query --status", cwd, shell=shell) == {}
    assert observed == [CommandInvocation("fixture-query", (Value("--status"),), cwd, shell)]


def test_supported_shells_do_not_broaden_direct_native_dispatch(monkeypatch):
    install(monkeypatch, CommandModel({"fixture-delete"}, deletion, {"bash"}))
    for shell in ("powershell", "cmd"):
        report = Analyzer(evidence=MemoryEvidenceProvider({})).analyze_report("fixture-delete C:\\", r"C:\work", shell=shell)
        assert [f.rule for f in report.findings] == ["unknown-command"]
        assert report.findings[0].data["command"] == "fixture-delete"


@pytest.mark.parametrize("command", ["timeout 2 fixture-delete /etc", "conda run -n test fixture-delete /etc"])
def test_registered_models_work_inside_existing_wrappers(monkeypatch, command):
    install(monkeypatch, CommandModel({"fixture-delete"}, deletion))
    report = Analyzer(evidence=MemoryEvidenceProvider({})).analyze_report(command, "/work", effort="None")
    assert [f.rule for f in report.findings] == ["delete-protected-root"]


def test_registry_passes_values_context_and_preserves_empty_vs_unknown():
    observed = []
    def handler(invocation):
        observed.append(invocation)
        return ()
    registry = CommandRegistry([CommandModel({"fixture-query"}, handler, {"powershell"})])
    args = (Value(None, "missing_variable", ("TARGET",)), Value("*.txt", pattern=True))
    invocation = CommandInvocation("fixture-query", args, None, "powershell")
    assert registry.describe(invocation) == []
    assert observed == [invocation]
    assert registry.describe(CommandInvocation("unknown", (), None, "powershell")) is None
    assert registry.describe(CommandInvocation("fixture-query", (), None, "bash")) is None


def test_explicit_wrapper_profile_fallback_retains_original_shell():
    observed = []
    registry = CommandRegistry([CommandModel({"fixture-query"}, lambda call: observed.append(call) or [], {"bash"})])
    invocation = CommandInvocation("fixture-query", (), r"C:\work", "powershell")
    assert registry.describe(invocation, fallback_shell="bash") == []
    assert observed == [invocation]
    assert not registry.supports("fixture-query", "powershell")


def test_duplicate_registration_is_rejected_but_distinct_shells_are_allowed():
    bash = CommandModel({"fixture-query"}, lambda call: [], {"bash"})
    with pytest.raises(ValueError, match="Duplicate command model"):
        CommandRegistry([bash, bash])
    windows = CommandModel({"fixture-query"}, lambda call: [], {"cmd"})
    registry = CommandRegistry([bash, windows])
    assert registry.supports("fixture-query", "bash") and registry.supports("fixture-query", "cmd")
    with pytest.raises(TypeError):
        registry._entries[("bash", "new")] = bash


@pytest.mark.parametrize("names,shells,handler", [
    (set(), {"bash"}, deletion), ("tool", {"bash"}, deletion),
    ({"/path/tool"}, {"bash"}, deletion), ({r"path\tool"}, {"cmd"}, deletion),
    ({""}, {"bash"}, deletion), ({3}, {"bash"}, deletion),
    ({"tool"}, set(), deletion), ({"tool"}, "bash", deletion),
    ({"tool"}, {"fish"}, deletion), ({"tool"}, {"bash"}, None),
])
def test_invalid_model_declarations_are_rejected(names, shells, handler):
    with pytest.raises(ValueError):
        CommandModel(names, handler, shells)


def test_registration_copies_mutable_name_and_shell_sets():
    names, shells = {"tool"}, {"bash"}
    model = CommandModel(names, deletion, shells)
    names.add("other")
    shells.add("cmd")
    assert model.names == {"tool"} and model.shells == {"bash"}


def test_model_output_must_be_facts():
    registry = CommandRegistry([CommandModel({"tool"}, lambda call: ["silent"])])
    with pytest.raises(TypeError, match="Fact records"):
        registry.describe(CommandInvocation("tool", (), "/work", "bash"))


def test_new_model_can_use_shared_option_parser_without_dispatch_changes(monkeypatch):
    def reader(invocation):
        operands, flags, _, unknown = parse_options(invocation.args, CommandSpec("n", ("--number", "--")))
        facts = [Fact("unresolved", "unknown-option", payload=option) for option in unknown]
        values = (Value(None, "unknown_option_operand_binding"),) if unknown else tuple(operands)
        return [*facts, Fact("read", "ingest", values=values, flags=flags)]
    install(monkeypatch, CommandModel({"fixture-read"}, reader))
    for shell in ("bash", "powershell", "cmd"):
        cwd = "/work" if shell == "bash" else r"C:\work"
        path = cwd + ("/" if shell == "bash" else "\\") + "data"
        analyzer = Analyzer(evidence=MemoryEvidenceProvider({path: "password=abcdefghijk"}))
        report = analyzer.analyze_report("fixture-read -n data", cwd, shell=shell)
        assert [f.rule for f in report.findings] == ["credentials-read"]
        invalid = analyzer.analyze_report("fixture-read --invented data", cwd, shell=shell)
        assert "unknown-option" in {f.rule for f in invalid.findings}
        assert "credentials-read" not in {f.rule for f in invalid.findings}


def test_unknown_model_and_unsupported_operation_keep_command_identity():
    assert describe("unknown-app", (), "/work") == [Fact("unresolved", "unknown-command", payload="unknown-app", command_name="unknown-app")]
    facts = describe("docker", (Value("invented"),), "/work")
    assert facts and all(f.command_name == "docker" for f in facts if f.operation == "unknown-command")
