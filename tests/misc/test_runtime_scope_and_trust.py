"""Runtime scopes, output provenance and trusted scripts; no input executes."""
import json
import pytest
from command_inspector import Analyzer, AnalyzerConfig
from command_inspector.models import ConfigurationError
from command_inspector.local_evidence import MemoryEvidenceProvider, ReadFile
from command_inspector.shared.runtime_values import runtime_output, path_scope, component
from command_inspector.shared.value_flow import compose
from command_inspector.models import Value
from command_inspector.paths import PathStyle


def analyze(source, shell='bash', *, env=None, files=None, **config):
    provider = MemoryEvidenceProvider(files or {})
    result = Analyzer(AnalyzerConfig(**config), evidence=provider).analyze(source,
        '/work' if shell == 'bash' else r'C:\work', shell=shell, env=env)
    return result, provider


def rules(result):
    return {f['rule'] for f in result.get('findings', [])}


@pytest.mark.parametrize('shell,prefix,write,read,delete', [
    ('bash', 'STAMP=$(date +%Y%m%d_%H%M%S); ', 'echo x > "/work/doc_$STAMP.txt"', 'cat "/work/doc_$STAMP.txt"', 'rm "/work/doc_$STAMP.txt"'),
    ('powershell', '$stamp=Get-Date -Format yyyyMMdd_HHmmss; ', 'Set-Content "C:\\work\\doc_$stamp.txt" x', 'Get-Content "C:\\work\\doc_$stamp.txt"', 'Remove-Item "C:\\work\\doc_$stamp.txt"'),
])
def test_runtime_timestamp_scopes(shell, prefix, write, read, delete):
    assert analyze(prefix + write, shell)[0] == {}
    result, _ = analyze(prefix + read, shell)
    assert rules(result) == {'ingestion-inspection-incomplete'}
    result, provider = analyze(prefix + delete, shell)
    assert rules(result) == {'delete-inside-workspace'}
    assert result['findings'][0]['data']['target_resolved'] is False
    assert provider.queries == []


@pytest.mark.parametrize('shell,source', [
    ('bash', 'for ((i=0;i<1000;i++)); do echo x > "/work/doc_$i.txt"; done'),
    ('powershell', 'foreach ($i in 1..1000) {Set-Content "C:\\work\\doc_$i.txt" x}'),
    ('cmd', 'for /L %i in (1,1,1000) do echo x > C:\\work\\doc_%i.txt'),
])
def test_numeric_loop_paths_do_not_become_unbounded(shell, source):
    result, _ = analyze(source, shell)
    assert not rules(result) & {'write-variable-unresolved', 'write-outside-workspace'}
    assert result.get('level', 'NONE') in {'NONE', 'LOW'}


@pytest.mark.parametrize('source', [
    'x=$(date +%Y%m%d); echo x > "/outside/doc_$x.txt"',
    'x=$((counter+1)); echo x > "/outside/doc_$x.txt"',
    "x=$(sha256sum input.txt | cut -d ' ' -f 1); echo x > \"/outside/doc_$x.txt\"",
])
def test_runtime_outside_scope_is_reported(source):
    result, _ = analyze(source)
    assert 'write-outside-workspace' in rules(result)
    assert 'write-variable-unresolved' not in rules(result)
    finding = next(f for f in result['findings'] if f['rule'] == 'write-outside-workspace')
    assert finding['data']['scope_root'] == '/outside'


@pytest.mark.parametrize('source', [
    'x=$(date +%Y/%m/%d); echo x > "/work/doc_$x.txt"',
    'x=$(sha256sum input.txt); echo x > "/work/doc_$x.txt"',
    'echo x > "/work/doc_$MISSING.txt"',
    'x=$(date +%Y); echo x > "/work/$x/../../outside.txt"',
    'x=$(date +%Y); echo x > "/work/$x"',
])
def test_unproved_paths_remain_unresolved(source):
    assert 'write-variable-unresolved' in rules(analyze(source)[0])


@pytest.mark.parametrize('fmt', ['d', 'f', 'M', 'yyyy/MM/dd', 'yyyy\\MM', 'yyyy:mm'])
def test_unsafe_powershell_date_formats_are_not_constrained(fmt):
    assert runtime_output('Get-Date -Format "' + fmt + '"', 'powershell') is None


@pytest.mark.parametrize('shell,write,known', [
    ('bash', "printf 'rm -rf /etc' > \"$OUT/task.sh\"", "printf 'rm -rf /etc' > task.sh"),
    ('powershell', "Set-Content \"$out/task.ps1\" 'Remove-Item C:\\Windows -Recurse -Force'", "Set-Content task.ps1 'Remove-Item C:\\Windows -Recurse -Force'"),
    ('cmd', 'echo rd /s /q C:\\Windows > %OUT%\\task.cmd', 'echo rd /s /q C:\\Windows > task.cmd'),
])
def test_unknown_path_does_not_hide_written_source(shell, write, known):
    assert 'delete-protected-root' in rules(analyze(known, shell)[0])
    result, _ = analyze(write, shell)
    assert {'delete-protected-root', 'write-variable-unresolved'} <= rules(result)
    finding = next(f for f in result['findings'] if f['rule'] == 'delete-protected-root')
    assert finding['data']['context'] == 'written_content'


@pytest.mark.parametrize('shell,source', [
    ('bash', "printf '%s' 'password=review-example' > \"$OUT/file.txt\""),
    ('powershell', "Set-Content \"$out/file.txt\" 'password=review-example'"),
    ('cmd', 'echo password=review-example > %OUT%\\file.txt'),
])
def test_unknown_path_payload_secret_detection(shell, source):
    result, _ = analyze(source, shell)
    assert 'credentials-written' in rules(result)
    assert 'review-example' not in json.dumps(result)


OUTPUTS = [
    ('bash', 'echo "$NAME"', 'NAME=local; ', 'if test -f marker; then NAME=local; fi; '),
    ('powershell', 'Write-Output $env:NAME', "$env:NAME='local'; ", "if ($condition) {$env:NAME='local'}; "),
    ('cmd', 'echo %NAME%', 'set NAME=local\n', 'if exist marker set NAME=local\n'),
]


@pytest.mark.parametrize('shell,echo,assignment,conditional', OUTPUTS)
def test_output_provenance(shell, echo, assignment, conditional):
    assert not rules(analyze(echo, shell)[0])
    assert 'environment-value-output' in rules(analyze(echo, shell, env={'NAME':'supplied'})[0])
    assert 'environment-value-output' not in rules(analyze(assignment + echo, shell, env={'NAME':'supplied'})[0])
    assert 'environment-value-output' in rules(analyze(conditional + echo, shell, env={'NAME':'supplied'})[0])


@pytest.mark.parametrize('shell,echo,assignment,conditional', OUTPUTS)
def test_credential_environment_output_is_never_silenced_by_name_allowlist(shell, echo, assignment, conditional):
    source = echo.replace('NAME', 'AWS_PRIVATE_KEY')
    result, _ = analyze(source, shell, env={'AWS_PRIVATE_KEY':'opaque-credential'}, quiet_output_variables=('AWS_PRIVATE_KEY',))
    assert 'credentials-exposed' in rules(result)
    assert 'opaque-credential' not in json.dumps(result)


@pytest.mark.parametrize('shell,echo,assignment,conditional', OUTPUTS)
def test_configured_output_name_is_quiet(shell, echo, assignment, conditional):
    assert analyze(echo, shell, env={'NAME':'ordinary'}, quiet_output_variables=('NAME',))[0] == {}


TRUST = [
    ('bash', '/work/init.sh', 'source /work/init.sh', "printf 'rm -rf /etc' > /work/init.sh", '; '),
    ('powershell', r'C:\work\init.ps1', '. C:\\work\\init.ps1', "Set-Content C:\\work\\init.ps1 'Remove-Item C:\\Windows -Recurse -Force'", '; '),
    ('cmd', r'C:\work\init.cmd', 'call C:\\work\\init.cmd', 'echo rd /s /q C:\\Windows > C:\\work\\init.cmd', '\n'),
]


@pytest.mark.parametrize('shell,path,invoke,write,separator', TRUST)
def test_trusted_script_is_not_read_but_its_writes_are_inspected(shell, path, invoke, write, separator):
    result, provider = analyze(invoke, shell, trusted_scripts=(path,), files={path:'unmodeled nonsense'})
    assert 'trusted-script-invoked' in rules(result)
    assert result['level'] == 'LOW'
    assert not any(isinstance(q, ReadFile) for q in provider.queries)
    result, _ = analyze(write, shell, trusted_scripts=(path,))
    assert 'delete-protected-root' in rules(result)
    result, _ = analyze(write + separator + invoke, shell, trusted_scripts=(path,))
    assert 'trusted-script-invoked' not in rules(result)
    assert 'execution-content-unavailable' in rules(result)


@pytest.mark.parametrize('path', ['init.sh', './init.sh', '../init.sh', 'C:init.cmd', '$HOME/init.sh', ''])
def test_trust_requires_absolute_paths(path):
    with pytest.raises(ConfigurationError):
        AnalyzerConfig(trusted_scripts=(path,))


def test_new_config_fields_load_from_mapping():
    config = AnalyzerConfig.from_mapping({'trusted_scripts':['/work/init.sh'], 'quiet_output_variables':['STATUS']})
    assert config.trusted_scripts == ('/work/init.sh',)
    assert config.quiet_output_variables == ('STATUS',)


@pytest.mark.parametrize('shell,source', [
    ('bash', 'echo x > new.txt; rm new.txt'),
    ('powershell', 'Set-Content new.txt x; Remove-Item new.txt'),
    ('cmd', 'echo x > new.txt & del new.txt'),
])
def test_creation_then_deletion_does_not_use_stale_absence(shell, source):
    result, _ = analyze(source, shell)
    assert rules(result) == {'delete-inside-workspace'}


def test_numbered_cmd_assignment_is_a_runtime_component():
    result, _ = analyze('set /a i=1\necho x > C:\\work\\doc_%i%.txt', 'cmd')
    assert result == {}


def test_runtime_scope_invalidates_evidence_without_inventing_a_file():
    result, provider = analyze('x=$(date +%Y); echo x > "/work/doc_$x.txt"; cat /work/doc_2026.txt', files={'/work/doc_2026.txt':'old bytes'})
    assert 'ingestion-inspection-incomplete' in rules(result)
    assert not any(isinstance(q, ReadFile) for q in provider.queries)


def test_quiet_output_variable_is_not_trusted_as_a_path():
    result, _ = analyze('rm "$PIPESTATUS"', quiet_output_variables=('PIPESTATUS',))
    assert 'delete-variable-unresolved' in rules(result)
    assert analyze('echo "PIP_EXIT=${PIPESTATUS[0]}"')[0] == {}
    assert analyze('echo "${PIPESTATUS[0]}"', env={'PIPESTATUS':'0'})[0] == {}


def test_unknown_output_fed_to_interpreter_remains_visible():
    result, _ = analyze('echo "$MISSING" | bash')
    assert 'execution-content-unavailable' in rules(result)


def test_output_does_not_hide_substitution_effects():
    assert 'delete-protected-root' in rules(analyze('echo "$(rm -rf /etc)"')[0])


@pytest.mark.parametrize('shell,source', [
    ('bash', 'echo "$AWS_PRIVATE_KEY" >/dev/null'),
    ('powershell', 'Write-Output $env:AWS_PRIVATE_KEY > $null'),
    ('cmd', 'echo %AWS_PRIVATE_KEY% > NUL'),
])
def test_discarded_output_retains_credential_detection(shell, source):
    assert 'credentials-exposed' in rules(analyze(source, shell, env={'AWS_PRIVATE_KEY':'opaque'})[0])


def test_unresolved_write_target_keeps_syntax_check():
    result, _ = analyze("printf 'def broken(' > \"$OUT/code.py\"")
    assert 'written-source-syntax-error' in rules(result)


def test_unknown_filename_with_shebang_is_inspected():
    result, _ = analyze("printf '#!/bin/bash\\nrm -rf /etc\\n' > \"$OUT\"")
    assert 'delete-protected-root' in rules(result)


def test_unknown_append_prefix_is_not_parsed_as_standalone_script():
    result, _ = analyze("printf 'rm -rf /etc\\n' >> \"$OUT/code.sh\"")
    assert 'delete-protected-root' not in rules(result)
    assert any(f['data'].get('reason') == 'unresolved_append_target' for f in result['findings'])


def test_sourced_script_trust_is_exact_not_basename_matching():
    result, _ = analyze('source /other/init.sh', trusted_scripts=('/work/init.sh',))
    assert 'trusted-script-invoked' not in rules(result)


def test_same_value_conditional_assignment_does_not_erase_environment_origin():
    result, _ = analyze('if true; then AWS_PRIVATE_KEY=opaque; fi; echo "$AWS_PRIVATE_KEY"', env={'AWS_PRIVATE_KEY':'opaque'})
    assert 'credentials-exposed' in rules(result)


@pytest.mark.parametrize('shell,path,source', [
    ('bash', '/work/init.sh', 'V=before; source /work/init.sh; rm "$V"'),
    ('powershell', r'C:\work\init.ps1', "$v='before'; . C:\\work\\init.ps1; Remove-Item $v"),
    ('cmd', r'C:\work\init.cmd', 'set V=before\ncall C:\\work\\init.cmd\ndel %V%'),
])
def test_trusted_script_does_not_claim_to_preserve_parent_variables(shell, path, source):
    result, _ = analyze(source, shell, trusted_scripts=(path,))
    assert 'trusted-script-invoked' in rules(result)
    assert 'delete-variable-unresolved' in rules(result)


def test_custom_ifs_does_not_prove_an_unquoted_path_component():
    source = 'IFS=2; STAMP=$(date +%Y); echo x > /work/doc_$STAMP.txt'
    assert 'write-variable-unresolved' in rules(analyze(source)[0])
    assert 'write-variable-unresolved' not in rules(analyze(source.replace('/work/doc_$STAMP.txt', '"/work/doc_$STAMP.txt"'))[0])


def test_new_rules_have_current_introduction_version():
    from command_inspector.catalog import rule_catalog
    entries = {r['rule']: r for r in rule_catalog()['rules']}
    for rule in ('trusted-script-invoked', 'environment-value-output'):
        assert entries[rule]['levels'] == ['LOW']
        assert entries[rule]['introduced_in'] == '1.12.0'


def test_device_namespace_is_not_downgraded_to_ordinary_runtime_file_scope():
    result, _ = analyze('i=$((1+1)); echo x > "/dev/loop$i"')
    assert 'write-variable-unresolved' in rules(result)


def test_quiet_name_does_not_hide_credential_shaped_content():
    result, _ = analyze('echo "$STATUS"', env={'STATUS':'sk-' + 'a' * 30}, quiet_output_variables=('STATUS',))
    assert 'credentials-exposed' in rules(result)


def test_cmd_delayed_output_uses_the_current_environment_definition():
    result, _ = analyze('setlocal EnableDelayedExpansion\nset NAME=local & echo !NAME!', 'cmd', env={'NAME':'supplied'})
    assert 'environment-value-output' not in rules(result)
    result, _ = analyze('set NAME=local & echo %NAME%', 'cmd', env={'NAME':'supplied'})
    assert 'environment-value-output' in rules(result)
