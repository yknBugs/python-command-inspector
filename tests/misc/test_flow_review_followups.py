"""Regressions for auth provenance and skipped/sequential control-flow paths."""
import pytest

from command_inspector import Analyzer, AnalyzerConfig
from command_inspector.local_evidence import MemoryEvidenceProvider, ReadFile


def inspect(source, *, shell="bash", files=None, effort="Full", disabled=()):
    provider = MemoryEvidenceProvider(files or {})
    report = Analyzer(AnalyzerConfig(disabled_rules=frozenset(disabled)), evidence=provider).analyze_report(
        source, "/work" if shell == "bash" else r"C:\work", shell=shell, effort=effort)
    return report, provider


def rules(report):
    return {f.rule for f in report.findings}


PREFIXES = {
    "bash": "p=firstSensitiveValue; if [ -e marker ]; then p=secondSensitiveValue; fi; ",
    "powershell": "$p='firstSensitiveValue'; if ($condition) {$p='secondSensitiveValue'}; ",
    "cmd": "set p=firstSensitiveValue\nif exist marker set p=secondSensitiveValue\n",
}


@pytest.mark.parametrize("shell,command", [
    ("bash", 'bash -c "curl -u user:$p https://example.com"'),
    ("bash", 'env bash -c "curl -u user:$p https://example.com"'),
    ("bash", 'timeout 5 bash -c "curl -H \'Authorization: Bearer $p\' https://example.com"'),
    ("bash", 'bash -c "docker login -p $p registry.example"'),
    ("powershell", 'pwsh -Command "curl -u user:$p https://example.com"'),
    ("powershell", 'cmd /c "curl -u user:$p https://example.com"'),
    ("cmd", 'cmd /c "curl -u user:%p% https://example.com"'),
])
@pytest.mark.parametrize("effort", ["Full", "Partial", "None"])
@pytest.mark.parametrize("disabled", [(), ("credentials-sent",)])
def test_nested_auth_candidates_never_enter_report(shell, command, effort, disabled):
    report, _ = inspect(PREFIXES[shell] + command, shell=shell, effort=effort, disabled=disabled)
    assert "uses-interpreter" in rules(report)
    for result in (str(report.to_dict()), str([f.data for f in report.findings])):
        assert "firstSensitiveValue" not in result
        assert "secondSensitiveValue" not in result
    assert any(f.data.get("possible_values", {}).get("p") == ["[REDACTED]"] for f in report.findings)


@pytest.mark.parametrize("command", [
    'curl -U "user:$p" https://example.com',
    'curl --proxy-user="user:$p" https://example.com',
    'wget --password="$p" https://example.com',
    'curl -fsSu"user:$p" https://example.com',
    'docker --context remote login --password "$p" registry.example',
    'mysql --password="$p" -e "DROP TABLE example"',
])
def test_native_auth_options_preserve_privacy_even_when_unsupported(command):
    report, _ = inspect(PREFIXES["bash"] + command)
    assert "firstSensitiveValue" not in str(report.to_dict())
    assert "secondSensitiveValue" not in str(report.to_dict())


@pytest.mark.parametrize("cmdlet", ["Invoke-WebRequest", "Invoke-RestMethod"])
@pytest.mark.parametrize("operand", [
    '-Headers @{Authorization="Bearer $p"}',
    '-Headers @{"Proxy-Authorization"="Basic $p"}',
    '-Token $p',
    '-Credential $p',
])
@pytest.mark.parametrize("effort", ["Full", "Partial", "None"])
def test_powershell_web_auth_candidates_are_redacted(cmdlet, operand, effort):
    report, _ = inspect(PREFIXES["powershell"] + f"{cmdlet} -Uri https://example.com {operand}",
                        shell="powershell", effort=effort)
    assert "credentials-sent" in rules(report)
    assert "firstSensitiveValue" not in str(report.to_dict())
    assert "secondSensitiveValue" not in str(report.to_dict())


@pytest.mark.parametrize("candidates", [("a.txt", "b.txt"), ("a", "b")])
def test_literal_headers_keep_ordinary_entry_candidates(candidates):
    first, second = candidates
    source = PREFIXES["powershell"] + f"$file='{first}'; if ($c) {{$file='{second}'}}; " + (
        'Invoke-WebRequest -Uri https://example.com -Headers @{Authorization="Bearer $p"; "X-File"=$file}')
    report, _ = inspect(source, shell="powershell")
    auth = next(f for f in report.findings if f.rule == "credentials-sent")
    assert auth.data["possible_values"]["p"] == ["[REDACTED]"]
    assert set(auth.data["possible_values"]["file"]) == set(candidates)


def test_assigned_auth_headers_keep_sensitive_variable_provenance():
    report, _ = inspect(PREFIXES["powershell"] + '$headers=@{Authorization="Bearer $p"}; Invoke-WebRequest -Uri https://example.com -Headers $headers', shell="powershell")
    assert "credentials-sent" in rules(report)
    assert "firstSensitiveValue" not in str(report.to_dict())
    assert "secondSensitiveValue" not in str(report.to_dict())


@pytest.mark.parametrize("command", [
    'sort -u "$p"', 'rg -u pattern "$p"', 'python -u "$p"',
    'sudo -u "$p" echo hi', 'docker run -p "$p" image',
    'sort -- "$p"',
    'curl -o "$p" https://example.com',
    'curl --output="$p" https://example.com',
])
def test_non_auth_options_keep_ordinary_candidates(command):
    report, _ = inspect('p=a.txt; if [ -e marker ]; then p=b.txt; fi; ' + command)
    metadata = [f.data["possible_values"]["p"] for f in report.findings
                if "p" in f.data.get("possible_values", {})]
    assert metadata
    assert all(set(values) == {"a.txt", "b.txt"} for values in metadata)


@pytest.mark.parametrize("clauses", [
    "'a' {Set-Content B.ps1 'Write-Output new'} default {pwsh -File B.ps1}",
    "default {pwsh -File B.ps1} 'a' {Set-Content B.ps1 'Write-Output new'}",
    "'a' {Set-Content B.ps1 'Write-Output new'} 'a' {$x=1} default {pwsh -File B.ps1}",
    "'a' {Set-Content B.ps1 'Write-Output new'}\n# unmatched input\ndefault {pwsh -File B.ps1}",
    "'a' {Set-Content B.ps1 'Write-Output new'} <# unmatched input #> default {pwsh -File B.ps1}",
    "'a' {Set-Content B.ps1 'Write-Output new'} default # unmatched input\n {pwsh -File B.ps1}",
])
def test_single_scalar_switch_default_reads_independent_evidence(clauses):
    source = "$tag='a'; if ($condition) {$tag='b'}; switch ($tag) {" + clauses + "}"
    report, provider = inspect(source, shell="powershell", files={r"C:\work\B.ps1": r"Remove-Item C:\ -Recurse -Force"})
    assert "delete-protected-root" in rules(report)
    assert "execution-content-unavailable" not in rules(report)
    assert [q.path for q in provider.queries if isinstance(q, ReadFile)] == [r"C:\work\B.ps1"]


@pytest.mark.parametrize("input_expression", ["('a','b')", "($unknown)", "-File input.txt"])
def test_multi_or_unknown_input_switch_keeps_possible_prior_mutation(input_expression):
    report, provider = inspect("switch " + input_expression + " {'a' {Set-Content B.ps1 'new'} default {pwsh -File B.ps1}}",
                               shell="powershell", files={r"C:\work\B.ps1": "Write-Output old"})
    assert "execution-content-unavailable" in rules(report)
    assert not any(isinstance(q, ReadFile) for q in provider.queries)


def test_quoted_default_is_a_matching_clause():
    report, provider = inspect("switch ('default') {'default' {Set-Content B.ps1 'new'} 'default' {pwsh -File B.ps1}}",
                               shell="powershell", files={r"C:\work\B.ps1": "Write-Output old"})
    assert "execution-content-unavailable" in rules(report)
    assert not any(isinstance(q, ReadFile) for q in provider.queries)


def test_default_bindings_do_not_pollute_single_input_matching_clauses():
    source = "$x='cache'; switch ('a') {default {$x='C:\\Windows'} 'a' {Remove-Item $x -Recurse -Force}}"
    report, _ = inspect(source, shell="powershell", effort="None")
    assert "delete-protected-root" not in rules(report)
    assert "delete-inside-workspace" in rules(report)


def test_switch_caller_keeps_union_of_mutations_after_default():
    source = "switch ('a') {'a' {Set-Content B.ps1 'new'} default {$x=1}}; pwsh -File B.ps1"
    report, provider = inspect(source, shell="powershell", files={r"C:\work\B.ps1": "Write-Output old"})
    assert "execution-content-unavailable" in rules(report)
    assert not any(isinstance(q, ReadFile) for q in provider.queries)


@pytest.mark.parametrize("intervening", ["b) A=cache ;;", "b) A=cache ;; c) A=other ;;", "b) A=cache ;;& c) A=other ;;"])
@pytest.mark.parametrize("effort", ["Full", "Partial", "None"])
def test_retesting_can_skip_clauses_without_losing_protected_bindings(intervening, effort):
    source = 'A=cache; case "$tag" in a) A=/etc ;;& ' + intervening + ' *) rm -rf "$A" ;; esac'
    report, _ = inspect(source, effort=effort)
    deletion = next(f for f in report.findings if f.rule == "delete-protected-root")
    assert deletion.data["possible"]
    assert "/etc" in deletion.data["possible_values"]["A"]


@pytest.mark.parametrize("intervening", ["b) : ;;", "b) x=b ;; c) : ;;", "b) x=b ;;& c) : ;;"])
def test_retesting_keeps_dirty_evidence_across_skipped_clauses(intervening):
    source = 'case "$tag" in a) echo new > B.sh ;;& ' + intervening + ' *) bash B.sh ;; esac'
    report, provider = inspect(source, files={"/work/B.sh": "echo old"})
    assert "execution-content-unavailable" in rules(report)
    assert not any(isinstance(q, ReadFile) for q in provider.queries)


def test_forced_fallthrough_stops_at_double_semicolon():
    source = 'case "$tag" in a) echo new > B.sh ;& b) x=b ;; *) bash B.sh ;; esac'
    report, provider = inspect(source, files={"/work/B.sh": "echo old"})
    assert "execution-content-unavailable" not in rules(report)
    assert [q.path for q in provider.queries if isinstance(q, ReadFile)] == ["/work/B.sh"]
