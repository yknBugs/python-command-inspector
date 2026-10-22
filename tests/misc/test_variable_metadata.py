"""Variable names are structured metadata, independent of diagnostic prose."""
import json

import pytest

from command_inspector import Analyzer
from command_inspector.local_evidence import MemoryEvidenceProvider


def analyze(command, shell="bash", env=None):
    cwd = "/work" if shell == "bash" else r"C:\work"
    return Analyzer(evidence=MemoryEvidenceProvider({})).analyze_report(command, cwd, shell=shell, env=env)


@pytest.mark.parametrize("shell,command,rule,names", [
    ("bash", 'echo "$MISSING"', "unresolved-value", ["MISSING"]),
    ("bash", 'cat "$MISSING"', "unresolved-value", ["MISSING"]),
    ("bash", 'echo x > "$MISSING"', "write-variable-unresolved", ["MISSING"]),
    ("bash", 'rm "$MISSING"', "delete-variable-unresolved", ["MISSING"]),
    ("bash", '$EXECUTABLE', "unknown-command", ["EXECUTABLE"]),
    ("bash", 'bash "$SCRIPT"', "execution-content-unavailable", ["SCRIPT"]),
    ("powershell", 'Get-Content $Missing', "unresolved-value", ["missing"]),
    ("powershell", 'Set-Content $Missing x', "write-variable-unresolved", ["missing"]),
    ("powershell", 'Remove-Item $Missing', "delete-variable-unresolved", ["missing"]),
    ("powershell", '& $Executable', "unknown-command", ["executable"]),
    ("powershell", 'pwsh -File $Script', "execution-content-unavailable", ["script"]),
    ("cmd", 'type %MISSING%', "unresolved-value", ["missing"]),
    ("cmd", 'echo x > %MISSING%', "write-variable-unresolved", ["missing"]),
    ("cmd", 'del %MISSING%', "delete-variable-unresolved", ["missing"]),
    ("cmd", '%EXECUTABLE%', "unknown-command", ["executable"]),
    ("cmd", 'cmd /c "echo %VALUE%"', "execution-content-unavailable", ["value"]),
])
def test_unresolved_values_export_names_without_shell_syntax(shell, command, rule, names):
    findings = [f for f in analyze(command, shell).findings if f.rule == rule]
    assert findings
    assert all(f.data["variables"] == names for f in findings)


@pytest.mark.parametrize("shell,command,names", [
    ("bash", 'echo "$Z/$A/$Z"', ["A", "Z"]),
    ("powershell", 'Get-Content "$Z/$A/$Z"', ["a", "z"]),
    ("cmd", 'type %Z%-%A%-%Z%', ["a", "z"]),
    ("cmd", 'type !Z!-!A!-!Z!', ["a", "z"]),
])
def test_composite_values_keep_all_names_sorted_and_unique(shell, command, names):
    finding, = [f for f in analyze(command, shell).findings if f.rule == "unresolved-value"]
    assert finding.data["variables"] == names


def test_different_variable_dependencies_survive_deduplication():
    findings = [f for f in analyze('echo "$FIRST" "$SECOND" "$FIRST"').findings if f.rule == "unresolved-value"]
    assert sorted(f.data["variables"] for f in findings) == [["FIRST"], ["SECOND"]]


def test_merged_interpreter_notices_union_variable_names():
    finding, = [f for f in analyze('bash "$FIRST"; bash "$SECOND"').findings if f.rule == "uses-interpreter"]
    assert finding.data["variables"] == ["FIRST", "SECOND"]


@pytest.mark.parametrize("command,names", [
    ('for item in a b; do cat "$item"; done', ["item"]),
    ('echo "${ROOT%/*}"', ["ROOT"]),
    ('echo "$(echo $INNER)"', ["INNER"]),
    ('bash <<EOF\necho $INPUT\nEOF', ["INPUT"]),
])
def test_loop_and_unsupported_expansion_metadata(command, names):
    findings = [f for f in analyze(command).findings if f.rule == "unresolved-value"]
    if command.startswith('for item'):
        assert not findings
        reads = [f for f in analyze(command).findings if f.rule == 'ingestion-inspection-incomplete']
        assert reads and all(f.data['possible'] for f in reads)
    else:
        assert findings
        assert all(f.data["variables"] == names for f in findings)


@pytest.mark.parametrize("command,rule,names", [
    ('[IO.Directory]::Delete("C:\\work\\folder", $Recursive)', "delete-recursion-unresolved", ["recursive"]),
    ('[IO.File]::WriteAllText("file.txt", $Content)', "unresolved-value", ["content"]),
    ('Set-Content file.txt -Value $Content', "unresolved-value", ["content"]),
    ('$Object.Mystery($Argument)', "unresolved-value", ["argument", "object"]),
    ('Move-Item $Source $Destination', "unresolved-value", ["destination", "source"]),
    ('Invoke-WebRequest -Uri $Address', "unresolved-value", ["address"]),
    ('Invoke-WebRequest -Uri "https://example.invalid" -Body @{one=$First;two=$Second}', "unresolved-value", ["first", "second"]),
])
def test_powershell_nonpath_arguments_preserve_metadata(command, rule, names):
    findings = [f for f in analyze(command, "powershell").findings if f.rule == rule]
    assert any(f.data["variables"] == names for f in findings)
    if rule == "delete-recursion-unresolved":
        assert not any(f.rule == "delete-variable-unresolved" for f in analyze(command, "powershell").findings)


def test_no_identifiable_variable_is_an_empty_list():
    finding, = [f for f in analyze('echo "$(pwd)"').findings if f.rule == "unresolved-value"]
    assert finding.data["variables"] == []


@pytest.mark.parametrize("shell,command", [("bash", "echo '$LITERAL'"),
    ("powershell", "Write-Output '$Literal'"), ("cmd", "echo literal")])
def test_literal_text_does_not_invent_variables(shell, command):
    assert not any(f.data.get("variables") for f in analyze(command, shell).findings)


def test_variable_values_are_not_exported():
    report = analyze('echo $SECRET', env={"SECRET": "private value with spaces"})
    finding, = [f for f in report.findings if f.rule == "unresolved-value"]
    assert finding.data["variables"] == ["SECRET"]
    assert "private value" not in json.dumps(report.to_dict())
