"""Unknown display values are not effects; syntax-check input is not executed."""
import pytest
from command_inspector import Analyzer
from command_inspector.local_evidence import DisabledEvidenceProvider, MemoryEvidenceProvider


def analyze(source, shell='powershell', files=None, env=None, disabled=False):
    return Analyzer(evidence=DisabledEvidenceProvider() if disabled else MemoryEvidenceProvider(files or {})).analyze(
        source, '/work' if shell == 'bash' else r'D:\work', shell=shell, env=env)


def rules(result):
    return {f['rule'] for f in result.get('findings', [])}


@pytest.mark.parametrize('quote', ['"', "'"])
@pytest.mark.parametrize('newline', ['\n', '\r\n'])
def test_powershell_here_string_is_inline_python_source(quote, newline):
    source = f'python -c @{quote}{newline}print(1){newline}{quote}@'
    assert rules(analyze(source)) == {'uses-interpreter'}


def test_python_here_string_effect_is_inspected():
    result = analyze('python -c @"\nimport shutil\nshutil.rmtree("C:/Windows")\n"@')
    assert 'delete-protected-root' in rules(result)


def test_expandable_here_string_interpolation_preserves_effects():
    result = analyze('python -c @"\n$(Remove-Item C:\\Windows -Recurse -Force)\n"@')
    assert 'delete-protected-root' in rules(result)
    assert 'execution-content-unavailable' in rules(result)


def test_single_quoted_here_string_does_not_expand_shell_syntax():
    result = analyze("python -c @'\nprint('$(Remove-Item C:/Windows)')\n'@")
    assert rules(result) == {'uses-interpreter'}


@pytest.mark.parametrize('source', [
    'Select-String -Path README.md -Pattern x | ForEach-Object { $_.Line.Trim() }',
    'Get-Content README.md | ForEach-Object { $_.Trim() }',
    '"$($_.Line.Trim())"', '$_.Path.Substring($gd.Length+1)',
    '$_.FullName.Substring(2)', '(Get-Content README.md | Out-String).Trim()',
    "$_.Path.Replace($x,'')", '$_.TrimEnd()', '$Matches[2].Trim()',
    '$x.Trim().ToLower().Replace("a","b")',
])
def test_display_transformations_are_quiet(source):
    assert analyze(source, files={r'D:\work\README.md':'x ordinary text'}) == {}


def test_original_read_still_requires_evidence():
    result = analyze('Get-Content README.md | ForEach-Object { $_.Trim() }', disabled=True)
    assert rules(result) == {'ingestion-inspection-incomplete'}
    assert result['num_findings'] == 1


@pytest.mark.parametrize('source', [
    'Get-Content README.md',
    'Get-Content README.md | ForEach-Object { $_.Trim() }',
    '(Get-Content README.md | Out-String).Trim()',
    'Select-String -Path README.md -Pattern x | ForEach-Object { $_.Line.Trim() }',
])
def test_credentials_stay_at_original_read(source):
    result = analyze(source, files={r'D:\work\README.md':'password=super-private-value'})
    assert rules(result) == {'credentials-read'}
    assert result['num_findings'] == 1
    assert 'super-private-value' not in str(result)


def test_unresolved_transformation_used_as_path_is_visible():
    result = analyze("$p=$_.FullName.Replace('src','lib'); Get-Content $p")
    assert rules(result) == {'unresolved-value'}
    assert result['level'] == 'LOW'


def test_transform_arguments_and_receivers_keep_side_effects():
    result = analyze('$x.Replace((Remove-Item C:\\Windows -Recurse -Force), "")')
    assert 'delete-protected-root' in rules(result)
    result = analyze('(Remove-Item C:\\Windows -Recurse -Force).Trim()')
    assert 'delete-protected-root' in rules(result)


def test_unknown_non_string_method_is_not_silenced():
    assert 'unresolved-value' in rules(analyze('$x.DeleteEverything()'))


@pytest.mark.parametrize('shell', ['bash', 'powershell', 'cmd'])
@pytest.mark.parametrize('flag', ['--check', '-c'])
def test_node_syntax_check_does_not_execute_source(shell, flag):
    path = '/work/lib/index.js' if shell == 'bash' else r'D:\work\lib\index.js'
    result = analyze(f'node {flag} lib/index.js', shell, {path:'require("fs").rmSync("/", {recursive:true,force:true})'})
    assert result == {}


@pytest.mark.parametrize('shell', ['bash', 'powershell', 'cmd'])
def test_node_check_stdin_does_not_execute_payload(shell):
    assert analyze('node --check -', shell) == {}


@pytest.mark.parametrize('flag', ['--require setup.js', '-r setup.js', '--import setup.mjs'])
def test_node_check_startup_preloads_still_need_coverage(flag):
    assert 'execution-content-unavailable' in rules(analyze(f'node --check {flag} index.js'))


def test_node_options_environment_keeps_startup_coverage():
    assert 'execution-content-unavailable' in rules(analyze('node --check index.js', env={'NODE_OPTIONS':'--require ./setup.js'}))


def test_node_script_argument_is_not_a_node_check_flag():
    assert 'uses-interpreter' in rules(analyze('node index.js --check'))


@pytest.mark.parametrize('shell', ['bash', 'powershell', 'cmd'])
@pytest.mark.parametrize('source', ['git checkout -- .', 'git checkout -- --not-an-option', 'git log -- src/'])
def test_git_operand_delimiter_is_not_unknown_option(shell, source):
    assert analyze(source, shell) == {}


def test_git_reset_pathspec_does_not_become_hard_reset():
    assert analyze('git reset -- --hard') == {}


def test_node_check_outside_workspace_still_reports_read_scope():
    assert rules(analyze('node --check C:\\outside\\index.js')) == {'read-outside-workspace'}


def test_unresolved_string_used_as_execution_source_remains_visible():
    result = analyze('$code=$x.Trim(); Invoke-Expression $code')
    assert 'execution-content-unavailable' in rules(result)


def test_unknown_method_body_keeps_loop_coverage():
    result = analyze('Get-ChildItem | ForEach-Object { $_.DoSomethingUnknown() }')
    assert rules(result) == {'unresolved-value', 'unsupported-syntax'}


def test_here_string_variable_does_not_replace_surrounding_source():
    source = '$target="C:/Windows"; python -c @"\nimport shutil\nshutil.rmtree(\'$target\')\n"@'
    assert 'delete-protected-root' in rules(analyze(source))


def test_node_import_does_not_become_quiet_during_normal_execution():
    result = analyze('node --import ./setup.mjs -e "1"')
    assert 'execution-content-unavailable' in rules(result)


@pytest.mark.parametrize('type_name', ['regex', 'System.Text.RegularExpressions.Regex', 'REGEX'])
@pytest.mark.parametrize('method', ['Matches', 'Match', 'IsMatch'])
def test_static_regex_matching_is_a_quiet_transformation(type_name, method):
    assert analyze(f"[{type_name}]::{method}('aaa','a')") == {}


def test_regex_matching_keeps_nested_argument_effects():
    result = analyze("[regex]::Matches((Get-Content README.md), 'a')",
                     files={r'D:\work\README.md':'password=super-private-value'})
    assert rules(result) == {'credentials-read'}
    result = analyze("[regex]::Matches((Remove-Item C:\\Windows -Recurse -Force), 'a')")
    assert 'delete-protected-root' in rules(result)


def test_regex_result_used_as_path_remains_unresolved():
    result = analyze("$p=[regex]::Matches('aaa','a'); Get-Content $p")
    assert rules(result) == {'unresolved-value'}


def test_regex_matching_inside_display_loop_is_quiet():
    assert analyze("Get-ChildItem | ForEach-Object { [regex]::Matches($_.Name,'a').Count }") == {}


def test_other_regex_methods_keep_coverage():
    assert 'unresolved-value' in rules(analyze("[regex]::UnknownMethod('aaa','a')"))
