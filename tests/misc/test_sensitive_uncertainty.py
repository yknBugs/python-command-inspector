"""Coverage follows sensitive consumers; content checks follow source operations."""
import json
import pytest
from command_inspector import Analyzer, AnalyzerConfig
from command_inspector.local_evidence import MemoryEvidenceProvider, DisabledEvidenceProvider
from command_inspector.shared.command_names import suspicious_command_name


def analyze(source, shell='bash', *, files=None, env=None, disabled=False, **config):
    provider = DisabledEvidenceProvider() if disabled else MemoryEvidenceProvider(files or {})
    return Analyzer(AnalyzerConfig(**config), evidence=provider).analyze(source,
        '/work' if shell == 'bash' else r'C:\work', shell=shell, env=env)


def rules(result):
    return {f['rule'] for f in result.get('findings', [])}


@pytest.mark.parametrize('source', ['ls > out.txt', 'git status > out.txt', 'cat a.txt > b.txt'])
def test_ordinary_runtime_output_does_not_need_payload_coverage(source):
    assert analyze(source, files={'/work/a.txt':'ordinary'}) == {}


@pytest.mark.parametrize('source', ['ls > out.sh', 'git status > out.py', 'echo x >> a.sh'])
def test_written_code_still_needs_content_coverage(source):
    assert 'unresolved-value' in rules(analyze(source, disabled=True))


@pytest.mark.parametrize('shell,source,path', [
    ('bash', 'cat password', '/work/password'),
    ('bash', 'cat password > file.txt', '/work/password'),
    ('bash', 'cat password > /dev/null', '/work/password'),
    ('powershell', 'Get-Content password > $null', r'C:\work\password'),
    ('cmd', 'type password > NUL', r'C:\work\password'),
])
def test_credential_source_is_inspected_independently_of_output_destination(shell, source, path):
    result = analyze(source, shell, files={path:'password=not-for-output'})
    assert 'credentials-read' in rules(result)
    assert 'not-for-output' not in json.dumps(result)


@pytest.mark.parametrize('suffix', ['', ' > file.txt', ' > /dev/null'])
def test_visible_token_is_checked_even_when_discarded(suffix):
    result = analyze('echo "sk-abcdefghijklmn"' + suffix)
    assert 'credentials-exposed' in rules(result)
    assert 'sk-abcdefghijklmn' not in json.dumps(result)


@pytest.mark.parametrize('source', ['ls *.txt', 'ls src/*.txt'])
def test_workspace_listing_pattern_is_quiet_without_enumeration(source):
    assert analyze(source, disabled=True) == {}


@pytest.mark.parametrize('source', ['cat *.log', 'grep -rn foo src/*.py', 'rg foo src/*.py'])
def test_bounded_content_pattern_keeps_only_ingestion_coverage(source):
    result = analyze(source, disabled=True)
    assert 'ingestion-inspection-incomplete' in rules(result)
    assert 'unresolved-value' not in rules(result)


def test_listing_pattern_outside_workspace_remains_visible():
    result = analyze('ls /outside/*.txt', disabled=True)
    assert rules(result) == {'read-outside-workspace'}


@pytest.mark.parametrize('source', ['test -f $X && echo ok', 'test -z "$X" && echo empty', '[ -z "$X" ] && echo empty'])
def test_condition_checks_do_not_report_unknown_command_or_unknown_operand(source):
    assert analyze(source) == {}


def test_test_command_still_inspects_substitutions():
    assert 'delete-protected-root' in rules(analyze('test -n "$(rm -rf /etc)"'))


def test_test_condition_does_not_hide_following_effects():
    assert 'delete-protected-root' in rules(analyze('test -f $X && rm -rf /etc'))


@pytest.mark.parametrize('source', ['Get-ChildItem "C:\\outside\\path contains space"', "Get-ChildItem -LiteralPath 'C:\\outside\\path contains space'"])
def test_powershell_path_spaces_do_not_make_the_path_unresolved(source):
    result = analyze(source, 'powershell')
    assert rules(result) == {'read-outside-workspace'}


def test_push_location_has_success_conditional_cwd():
    result = analyze('Push-Location C:\\outside && Remove-Item x', 'powershell')
    assert 'unknown-command' not in rules(result)
    assert next(f for f in result['findings'] if f['rule'] == 'delete-outside-workspace')['data']['target'] == r'C:\outside\x'
    result = analyze('Push-Location C:\\outside; Remove-Item x', 'powershell')
    assert 'delete-variable-unresolved' not in rules(result)
    assert {'delete-inside-workspace', 'delete-outside-workspace'} <= rules(result)
    assert analyze('Push-Location', 'powershell') == {}


@pytest.mark.parametrize('source', [
    '[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new()',
    '[System.Console]::InputEncoding=[Text.UTF8Encoding]::new($false)',
    '[Console]::OutputEncoding=[System.Text.Encoding]::UTF8',
    '$env:PYTHONIOENCODING="utf-8"', '$env:PYTHONUTF8="1"',
])
def test_defensive_encoding_setup_is_quiet(source):
    assert analyze(source, 'powershell') == {}


def test_unsupported_encoding_expression_preserves_effects():
    result = analyze('[Console]::OutputEncoding=$(Remove-Item C:\\Windows -Recurse -Force)', 'powershell')
    assert 'delete-protected-root' in rules(result)


@pytest.mark.parametrize('source,shell', [('export PYTHONIOENCODING=utf-8', 'bash'), ('$env:PYTHONIOENCODING="utf-8"', 'powershell')])
def test_environment_notice_allowlist_is_configurable(source, shell):
    assert analyze(source, shell) == {}
    assert 'environment-modified' in rules(analyze(source, shell, quiet_environment_variables=()))


def test_path_assignment_is_not_a_defensive_encoding_change():
    assert 'environment-modified' in rules(analyze('$env:PATH="D:\\x;"+$env:PATH', 'powershell', env={'PATH':r'C:\tools'}))


@pytest.mark.parametrize('property', ["Name,@{n='MB'}", "Name,@{n='MB';e={1}}", "Name,@{n='MB';e={[math]::Round($_.Length/1MB,1)}}"])
def test_calculated_properties_parse_without_invented_commands(property):
    source = 'Get-ChildItem | Sort-Object Length | Select-Object ' + property
    assert not Analyzer().parse(source, shell='powershell').diagnostics
    assert analyze(source, 'powershell') == {}


def test_calculated_property_scriptblock_effects_are_still_inspected():
    source = "Get-ChildItem | Select-Object Name,@{n='x';e={Remove-Item C:\\Windows -Recurse -Force}}"
    assert 'delete-protected-root' in rules(analyze(source, 'powershell'))


def test_trim_expression_without_sensitive_consumer_is_quiet():
    result = analyze('(Get-Content x).Trim()', 'powershell', files={r'C:\work\x':'text'})
    assert result == {}


@pytest.mark.parametrize('name', ['llama[', 'llama]', 'name=value', 'foo:bar'])
def test_more_suspicious_bare_names(name):
    assert suspicious_command_name(name, 'bash') == 'syntax_in_command_name'


@pytest.mark.parametrize('name', ['$','%','!','^','~','@','*','?', r'HKLM:\Software', 'Env:', 'C:foo', r'C:\tools\foo[1].exe'])
def test_control_spelling_and_windows_path_forms_are_not_suspicious(name):
    assert suspicious_command_name(name, 'powershell') is None


@pytest.mark.parametrize('property', ["@{n='MB';e={1}},Name", "Name,@{n='MB';e={1}},Length", "Name,@{n='MB';e={1}},@{n='GB';e={2}}"])
def test_calculated_properties_can_be_followed_by_more_properties(property):
    source = 'Get-ChildItem | Select-Object ' + property
    assert not Analyzer().parse(source, shell='powershell').diagnostics
    assert analyze(source, 'powershell') == {}


def test_malformed_calculated_property_still_reports_syntax_error():
    assert Analyzer().parse("Select-Object Name,@{n='x';e={1}", shell='powershell').diagnostics


def test_environment_allowlist_does_not_suppress_credential_output():
    result = analyze('$env:PYTHONIOENCODING="sk-abcdefghijklmn"; Write-Output $env:PYTHONIOENCODING', 'powershell')
    assert 'environment-modified' not in rules(result)
    assert 'credentials-exposed' in rules(result)


def test_environment_allowlist_mapping_and_validation():
    from command_inspector.models import ConfigurationError
    assert AnalyzerConfig.from_mapping({'quiet_environment_variables':['MY_ENCODING']}).quiet_environment_variables == ('MY_ENCODING',)
    with pytest.raises(ConfigurationError):
        AnalyzerConfig(quiet_environment_variables='PYTHONUTF8')


def test_console_encoding_constructor_argument_effects_are_not_hidden():
    result = analyze('[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($(Remove-Item C:\\Windows -Recurse -Force))', 'powershell')
    assert 'delete-protected-root' in rules(result)


def test_unmodeled_binary_output_keeps_coverage():
    assert 'unresolved-value' in rules(analyze('ls > out.exe'))
