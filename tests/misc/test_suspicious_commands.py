"""Command-boundary hints and reported PowerShell parser regressions."""
import json
import pytest
from command_inspector import Analyzer, AnalyzerConfig
from command_inspector.local_evidence import DisabledEvidenceProvider
from command_inspector.shared.command_names import suspicious_command_name


ps1 = "Write-Output '--- log ---'; git log --format='%h | %ad | %an <%ae> | %s' --date=iso --all; Write-Output '--- HEAD stat ---'; git show --stat --oneline HEAD; Write-Output '--- HEAD~1 stat ---'; git show --stat --oneline HEAD~1; Write-Output '--- tracked count ---'; (git ls-files).Count; Write-Output '--- ignored/untracked ---'; git status --short --ignored | Select-Object -First 30"
ps2 = '''$p = 'D:\\Temp\\pythonCodeChecker\\README.md'
Write-Output '--- headings ---'
Select-String -LiteralPath $p -Pattern '^#{1,3} ' | Select-Object LineNumber, Line
Write-Output '--- history/tools refs ---'
Select-String -LiteralPath $p -Pattern '1\\.9\\.0|Old|New|Update|Before|Early|tools/|tests/|pytest' | Select-Object LineNumber, Line
Write-Output '--- fences ---'
$t = Get-Content -LiteralPath $p -Raw
"fences: $(([regex]::Matches($t, '(?m)^```')).Count)"
Write-Output '--- plugin link ---'
Select-String -LiteralPath $p -Pattern 'dsh-manual-approval' | Select-Object LineNumber, Line'''
bash = r'''python -c "
print('The \"Unknown Command\" rule should be updated')
print('Because it only produces a "Low" findings')
print('But if it is really a \"quote-hazard\" like this example')
print('We should report it as "HIGH" findings')
print('A typical is the `unknown command` rule triggers multiple times with strings that do not look like a command at all')
"'''


def analyze(command, shell="bash", config=None):
    return Analyzer(config, evidence=DisabledEvidenceProvider()).analyze(
        command, "/work" if shell == "bash" else r"D:\work", shell=shell)


def unknown(report):
    return [f for f in report.get("findings", []) if f["rule"] == "unknown-command"]


@pytest.mark.parametrize("shell", ["bash", "powershell", "cmd"])
@pytest.mark.parametrize("name", ["print(hello)", "a;b", "a|b", "{}", "###", "llama cpp", "llamacpp(", "my tool", "llama\u00a0cpp"])
def test_suspicious_command_position(shell, name):
    command = ('& ' if shell == 'powershell' else '') + '"' + name + '"'
    finding, = unknown(analyze(command, shell))
    assert finding['level'] == 'HIGH'
    assert finding['data']['reason'] == 'suspicious_command_name'
    assert finding['data']['command_resolved'] is True
    assert 'possible' in finding['title']


@pytest.mark.parametrize("shell", ["bash", "powershell", "cmd"])
@pytest.mark.parametrize("name", ["my-tool", "my_tool2", "custom.bin", "工具", "foo+bar",
                                  "llama-cpp", "llama.cpp", "llama_cpp", "llamacpp"])
def test_plausible_unknown_names_remain_low(shell, name):
    command = ('& ' if shell == 'powershell' else '') + '"' + name + '"'
    finding, = unknown(analyze(command, shell))
    assert finding['level'] == 'LOW'


@pytest.mark.parametrize('shell', ['bash', 'powershell', 'cmd'])
def test_space_separating_an_argument_is_not_part_of_command_name(shell):
    finding, = unknown(analyze('llama cpp', shell))
    assert finding['level'] == 'LOW'
    assert finding['data']['command'] == 'llama'


def test_whitespace_hint_is_machine_readable():
    finding, = unknown(analyze('"llama cpp"'))
    assert finding['data']['name_pattern'] == 'whitespace_in_command_name'


@pytest.mark.parametrize("name,shell", [
    ('./my (copy)', 'bash'), ('/opt/my;tool', 'bash'),
    ('tools/my (copy)', 'bash'), (r'C:\Program Files\tool.exe', 'powershell'),
    (r'..\my (copy).exe', 'cmd'), (r'tools\my (copy).exe', 'cmd'),
    (r'Module\Get-CustomThing', 'powershell'), (None, 'bash'),
])
def test_paths_and_unresolved_names_are_not_lexical_hazards(name, shell):
    assert suspicious_command_name(name, shell) is None


@pytest.mark.parametrize('command,shell', [
    ('echo "print(hello); !!!"', 'bash'),
    ('Write-Output "print(hello); !!!"', 'powershell'),
    ('echo "print(hello)"', 'cmd'),
    ('"print(hello); !!!"', 'powershell'),
])
def test_text_outside_command_position_is_not_classified(command, shell):
    assert not unknown(analyze(command, shell))


def test_suspicious_slash_is_not_hidden_by_path_fallback():
    finding, = unknown(analyze("'print(foo/bar)'"))
    assert finding['level'] == 'HIGH'


def test_newline_and_variable_command_values():
    finding, = unknown(analyze("x='hello\nworld'; \"$x\""))
    assert finding['data']['name_pattern'] == 'control_character'
    finding, = unknown(analyze('"$MISSING"'))
    assert finding['level'] == 'LOW'
    assert finding['data']['command_resolved'] is False


def test_custom_tool_registration_does_not_hide_boundary_hint():
    finding, = unknown(analyze("'print(hello)'", config=AnalyzerConfig(known_tools={'print(hello)': 'custom'})))
    assert finding['level'] == 'HIGH'


def test_many_plausible_unknowns_do_not_raise_level():
    findings = unknown(analyze('foo; bar; baz'))
    assert len(findings) == 3
    assert {f['level'] for f in findings} == {'LOW'}


def test_suspicious_command_secret_is_redacted():
    token = 'sk-' + 'x' * 28
    result = analyze("'print(" + token + ")'")
    assert unknown(result)[0]['level'] == 'HIGH'
    assert token not in json.dumps(result)


def test_user_powershell_scripts_do_not_invent_command_boundaries():
    for source in (ps1, ps2):
        assert not Analyzer().parse(source, shell='powershell').diagnostics
        findings = analyze(source, 'powershell').get('findings', [])
        assert not any(f['level'] == 'HIGH' for f in findings)
        assert {f['data']['command'] for f in findings if f['rule'] == 'unknown-command'} <= {'git'}
    assert analyze('"' + ps1 + '"', 'powershell') == {}
    # JSON transport syntax is not silently decoded into shell source.
    assert Analyzer().parse(json.dumps(ps2), shell='powershell').diagnostics


def test_user_bash_example_has_a_plausible_backtick_command():
    finding, = unknown(analyze(bash))
    assert finding['data']['command'] == 'unknown'
    assert finding['level'] == 'LOW'


@pytest.mark.parametrize('shell,commands', [('powershell', {'print'}), ('cmd', set())])
def test_same_inline_text_has_shell_specific_meanings(shell, commands):
    result = analyze(bash, shell)
    assert {f['data']['command'] for f in unknown(result)} == commands
    assert all(f['level'] == 'LOW' for f in unknown(result))
    assert any(f['rule'] == 'unsupported-syntax' for f in result['findings'])


@pytest.mark.parametrize('source', [
    "git log --format='%h | %s' --date=iso",
    'git log --format="%h | %s" --date=iso',
    "Select-String -Pattern 'a|b' | Select-Object LineNumber, Line\nWrite-Output 'next'",
    "git log --format='a,b' | Select-Object Name, Value\nWrite-Output 'next'",
])
def test_parser_repairs_keep_literal_boundaries(source):
    assert not Analyzer().parse(source, shell='powershell').diagnostics
    assert not unknown(analyze(source, 'powershell'))


def test_comma_repair_preserves_following_effects():
    result = analyze("git status | Select-Object Name, Value\nRemove-Item C:\\Windows -Recurse -Force", 'powershell')
    assert any(f['level'] == 'BLOCK' for f in result.get('findings', []))


def test_unmatched_native_option_quote_stays_unparsed():
    assert Analyzer().parse("git log --format='broken", shell='powershell').diagnostics


@pytest.mark.parametrize('suffix', ['', ' | Select-Object Name, Value\nWrite-Output next'])
def test_repaired_native_option_retains_its_value(suffix):
    result = analyze("curl --url='https://example.invalid/a|b'" + suffix, 'powershell')
    finding, = result['findings']
    assert finding['rule'] == 'network-request'
    assert finding['data']['destinations'] == ['https://example.invalid/a|b']


def test_catalog_advertises_both_unknown_command_levels():
    from command_inspector.catalog import rule_catalog
    catalog = rule_catalog()
    rule = next(r for r in catalog['rules'] if r['rule'] == 'unknown-command')
    assert rule['levels'] == ['LOW', 'HIGH']
