"""Finite control-flow domains and rule/evidence lifting; never execute inputs."""
import shlex

import pytest

from command_inspector import Analyzer, AnalyzerConfig, ConfigurationError, EvidenceEffort, Level
from command_inspector.local_evidence import DisabledEvidenceProvider, MemoryEvidenceProvider, ReadFile
from command_inspector.models import Value
from command_inspector.shared.value_flow import join, choices


SHELLS = ('bash', 'powershell', 'cmd')


def cwd(shell):
    return '/work' if shell == 'bash' else r'C:\work'


def branch(shell, left, right, command):
    if shell == 'bash':
        return f'V={shlex.quote(left)}; if true; then V={shlex.quote(right)}; fi; {command}'
    if shell == 'powershell':
        quote = lambda s: "'" + s.replace("'", "''") + "'"
        return f'$v={quote(left)}; if ($condition) {{$v={quote(right)}}}; {command}'
    return f'set "V={left}"\nif exist marker set "V={right}"\n{command}'


def report(shell, source, *, files=None, config=None, effort=EvidenceEffort.NONE):
    provider = DisabledEvidenceProvider() if files is None else MemoryEvidenceProvider(files)
    analyzer = Analyzer(config, evidence=provider)
    return analyzer.analyze_report(source, cwd(shell), shell=shell, effort=effort), provider


def rules(result):
    return {f.rule for f in result.findings}


def selected(result, rule):
    return [f for f in result.findings if f.rule == rule]


@pytest.mark.parametrize('shell', SHELLS)
@pytest.mark.parametrize('outside', [False, True])
def test_possible_deletion_targets_are_checked_separately(shell, outside):
    command = {'bash': 'rm -rf "$V"', 'powershell': 'Remove-Item $v -Recurse -Force', 'cmd': 'rd /s /q %V%'}[shell]
    other = ('/outside/b' if shell == 'bash' else r'C:\outside\b') if outside else 'b'
    result, _ = report(shell, branch(shell, 'a', other, command))
    assert result.level == (Level.MEDIUM if outside else Level.LOW)
    assert 'delete-variable-unresolved' not in rules(result)
    findings = [f for f in result.findings if f.type == 'filesystem']
    assert len(findings) == 2
    assert all(f.data['possible'] for f in findings)
    assert all(set(next(iter(f.data['possible_values'].values()))) == {'a', other} for f in findings)
    assert any(f.rule == 'delete-outside-workspace' for f in findings) == outside


@pytest.mark.parametrize('shell', SHELLS)
def test_one_possible_protected_target_blocks(shell):
    target = '/etc' if shell == 'bash' else 'C:\\'
    command = {'bash': 'rm -rf "$V"', 'powershell': 'Remove-Item $v -Recurse -Force', 'cmd': 'rd /s /q %V%'}[shell]
    result, _ = report(shell, branch(shell, 'cache', target, command))
    assert result.level == Level.BLOCK
    assert selected(result, 'delete-protected-root')[0].data['possible']


@pytest.mark.parametrize('shell', SHELLS)
@pytest.mark.parametrize('outside', [False, True])
def test_reads_of_possible_paths_are_quiet_inside_and_possible_outside(shell, outside):
    command = {'bash': 'cat "$V"', 'powershell': 'Get-Content $v', 'cmd': 'type %V%'}[shell]
    target = ('/outside/b' if shell == 'bash' else r'C:\outside\b') if outside else 'b'
    separator = '/' if shell == 'bash' else '\\'
    files = {cwd(shell) + separator + 'a': 'harmless text', (target if outside else cwd(shell) + separator + 'b'): 'ordinary text'}
    result, _ = report(shell, branch(shell, 'a', target, command), files=files, effort=EvidenceEffort.FULL)
    if outside:
        assert rules(result) == {'read-outside-workspace'}
        assert result.findings[0].data['possible']
        assert result.level == Level.LOW
    else:
        assert result.to_dict() == {}


@pytest.mark.parametrize('shell', SHELLS)
@pytest.mark.parametrize('effort', list(EvidenceEffort))
def test_possible_writes_follow_workspace_policy_at_every_effort(shell, effort):
    target = '/outside/b' if shell == 'bash' else r'C:\outside\b'
    command = {'bash': 'echo text > "$V"', 'powershell': 'Set-Content $v text', 'cmd': 'echo text > %V%'}[shell]
    result, _ = report(shell, branch(shell, 'a', target, command), effort=effort)
    assert selected(result, 'write-outside-workspace')[0].data['possible']
    assert 'write-variable-unresolved' not in rules(result)


@pytest.mark.parametrize('shell', SHELLS)
def test_domain_limit_is_configurable_and_does_not_truncate(shell):
    command = {'bash': 'rm -rf "$V"', 'powershell': 'Remove-Item $v -Recurse -Force', 'cmd': 'rd /s /q %V%'}[shell]
    config = AnalyzerConfig(possible_values=1)
    result, _ = report(shell, branch(shell, 'a', 'b', command), config=config)
    assert rules(result) == {'delete-variable-unresolved'}
    assert result.findings[0].data['variables'] == (['V'] if shell == 'bash' else ['v'])
    assert not any(f.data.get('target') for f in result.findings)


@pytest.mark.parametrize('limit', [0, -1, True, '3', 1.5])
@pytest.mark.parametrize('field', ['possible_values', 'control_flow_steps'])
def test_invalid_flow_limits_are_rejected(field, limit):
    with pytest.raises(ConfigurationError):
        AnalyzerConfig(**{field: limit})


def test_config_mapping_accepts_flow_limits():
    config = AnalyzerConfig.from_mapping({'limits': {'possible_values': 3, 'control_flow_steps': 10}})
    assert (config.possible_values, config.control_flow_steps) == (3, 10)


def test_scalar_domain_preserves_patterns_deduplicates_and_unknown_absorbs():
    domain = join([Value('*.txt', pattern=True), Value('*.txt', pattern=True), Value('a')], 2)
    assert [(v.text, v.pattern) for v in domain.alternatives] == [('*.txt', True), ('a', False)]
    assert join([domain, Value('b')], 2).reason == 'possible_values_limit'
    assert join([domain, Value(None, 'runtime')], 2).reason == 'runtime'


def test_cartesian_budget_does_not_select_a_prefix_of_combinations():
    domain = join([Value('a'), Value('b')])
    rows, metadata = choices({'A': domain, 'B': domain}, ['A', 'B'], 3)
    assert len(rows) == 1 and not metadata
    assert all(v.text is None and v.reason == 'possible_values_limit' for v in rows[0].values())


@pytest.mark.parametrize('shell,source,targets', [
    ('bash', 'for n in a b /etc; do rm -rf "$n"; done', {'/work/a', '/work/b', '/etc'}),
    ('powershell', "foreach ($n in 'a','b','C:\\') {Remove-Item $n -Recurse -Force}", {r'C:\work\a', r'C:\work\b', 'C:\\'}),
    ('powershell', "'a','b','C:\\' | ForEach-Object {Remove-Item $_ -Recurse -Force}", {r'C:\work\a', r'C:\work\b', 'C:\\'}),
    ('cmd', r'for %n in (a b C:\) do rd /s /q %n', {r'C:\work\a', r'C:\work\b', 'C:\\'}),
    ('cmd', r'for %%n in (a b C:\) do (rd /s /q %%n)', {r'C:\work\a', r'C:\work\b', 'C:\\'}),
])
def test_finite_loop_bindings_are_choices_not_pre_loop_values(shell, source, targets):
    result, _ = report(shell, source)
    assert result.level == Level.BLOCK
    assert 'delete-variable-unresolved' not in rules(result)
    assert {f.data['target'] for f in result.findings if f.type == 'filesystem'} == targets


@pytest.mark.parametrize('shell,source', [
    ('bash', 'a=cache; for n in 1 2; do rm -rf "$a"; a=/etc; done'),
    ('bash', 'a=cache; while true; do rm -rf "$a"; a=/etc; done'),
    ('powershell', "$a='cache'; foreach ($n in 1,2) {Remove-Item $a -Recurse -Force; $a='C:\\'}"),
    ('powershell', "$a='cache'; while ($true) {Remove-Item $a -Recurse -Force; $a='C:\\'}"),
    ('powershell', "$a='cache'; 1,2 | % {Remove-Item $a -Recurse -Force; $a='C:\\'}"),
    ('cmd', 'setlocal EnableDelayedExpansion\nset a=cache\nfor %n in (1 2) do (rd /s /q !a! & set a=C:\\)'),
])
def test_loop_carried_assignments_reach_a_fixed_point(shell, source):
    result, _ = report(shell, source)
    assert result.level == Level.BLOCK
    assert selected(result, 'delete-protected-root')[0].data['possible']


@pytest.mark.parametrize('shell,source', [
    ('bash', 'a=x; while true; do a="${a}x"; done; rm -rf "$a"'),
    ('powershell', "$a='x'; while ($true) {$a=\"${a}x\"}; Remove-Item $a -Recurse -Force"),
    ('powershell', "$a='x'; 1,2 | % {$a=\"${a}x\"}; Remove-Item $a -Recurse -Force"),
    ('cmd', 'setlocal EnableDelayedExpansion\nset a=x\nfor %n in (1 2) do (set a=!a!x)\nrd /s /q !a!'),
])
def test_growing_loop_domains_become_unresolved(shell, source):
    result, _ = report(shell, source, config=AnalyzerConfig(possible_values=3))
    assert 'delete-variable-unresolved' in rules(result)


@pytest.mark.parametrize('shell', SHELLS)
def test_all_native_models_receive_concrete_possible_options(shell):
    reference = '"$V"' if shell == 'bash' else '$v' if shell == 'powershell' else '%V%'
    result, _ = report(shell, branch(shell, 'status', 'push', f'git {reference}'))
    assert 'git-push' in rules(result)
    assert 'unresolved-value' not in rules(result)
    assert selected(result, 'git-push')[0].data['possible']


@pytest.mark.parametrize('shell', SHELLS)
def test_unknown_command_names_and_known_tool_catalog_preserve_candidates(shell):
    invocation = '"$V"' if shell == 'bash' else '& $v' if shell == 'powershell' else '%V%'
    result, _ = report(shell, branch(shell, 'crontab', 'unmodeled_xyz', invocation))
    assert {'tool-invoked', 'unknown-command'} <= rules(result)
    assert selected(result, 'unknown-command')[0].data['command'] == 'unmodeled_xyz'
    assert selected(result, 'tool-invoked')[0].data['possible']


@pytest.mark.parametrize('shell', SHELLS)
def test_sql_inline_code_is_checked_for_every_possible_statement(shell):
    reference = '"$V"' if shell == 'bash' else '$v' if shell == 'powershell' else '%V%'
    result, _ = report(shell, branch(shell, 'SELECT 1', 'DROP TABLE things', f'psql -c {reference}'))
    assert 'sql-drop-object' in rules(result)
    assert selected(result, 'sql-drop-object')[0].data['possible']


@pytest.mark.parametrize('effort', [EvidenceEffort.FULL, EvidenceEffort.PARTIAL])
def test_wildcards_stay_deferred_until_used_and_match_under_partial(effort):
    source = branch('bash', '*.txt', '*.log', 'rm $V')
    files = {'/work/a.txt': 'a', '/work/b.log': 'bb'}
    result, provider = report('bash', source, files=files, effort=effort)
    assert 'delete-variable-unresolved' not in rules(result)
    deletion = [f for f in result.findings if f.rule.startswith('delete-')]
    assert deletion and all(f.data['possible'] for f in deletion)
    assert not any(isinstance(q, ReadFile) for q in provider.queries)


def test_possible_script_invocations_isolate_evidence_between_candidates():
    source = branch('bash', 'a.sh', 'b.sh', 'bash "$V"; bash later.sh')
    result, provider = report('bash', source, files={
        '/work/a.sh': 'crontab -r', '/work/b.sh': 'rm -rf /etc', '/work/later.sh': 'echo safe',
    }, effort=EvidenceEffort.FULL)
    assert 'delete-protected-root' in rules(result)
    assert selected(result, 'delete-protected-root')[0].data['possible']
    assert {q.path for q in provider.queries if isinstance(q, ReadFile)} == {'/work/a.sh', '/work/b.sh'}
    assert 'execution-content-unavailable' in rules(result)


@pytest.mark.parametrize('shell', SHELLS)
def test_possible_mutations_invalidate_every_candidate_before_later_reads(shell):
    command = {'bash': 'rm "$V"; cat a; cat b', 'powershell': 'Remove-Item $v; Get-Content a; Get-Content b', 'cmd': 'del %V%\ntype a\ntype b'}[shell]
    sep = '/' if shell == 'bash' else '\\'
    result, provider = report(shell, branch(shell, 'a', 'b', command), files={cwd(shell)+sep+'a': 'password=abcdefghijk', cwd(shell)+sep+'b':'password=abcdefghijk'}, effort=EvidenceEffort.FULL)
    assert 'credentials-read' not in rules(result)
    assert 'ingestion-inspection-incomplete' in rules(result)
    assert not any(isinstance(q, ReadFile) for q in provider.queries)


def test_exported_possible_bash_bindings_survive_script_inspection():
    source = 'export V=a; if true; then V=/etc; fi; bash script.sh'
    result, _ = report('bash', source, files={'/work/script.sh': 'rm -rf "$V"'}, effort=EvidenceEffort.FULL)
    assert 'delete-protected-root' in rules(result)
    assert selected(result, 'delete-protected-root')[0].data['possible']


@pytest.mark.parametrize('shell', SHELLS)
@pytest.mark.parametrize('tool,left,right,tail,rule', [
    ('docker', 'inspect', 'stop', 'demo', 'docker-change'),
    ('pip', 'show', 'install', 'torch', 'package-install'),
    ('systemctl', 'status', 'start', 'demo', 'service-change'),
    ('chmod', '644', '777', 'file', 'permissions-too-broad'),
    ('dd', 'of=local.bin', 'of=/dev/block/boot', '', 'raw-device-write'),
])
def test_shared_behavior_families_lift_possible_arguments(shell, tool, left, right, tail, rule):
    reference = '"$V"' if shell == 'bash' else '$v' if shell == 'powershell' else '%V%'
    result, _ = report(shell, branch(shell, left, right, f'{tool} {reference} {tail}'))
    if shell != 'bash' and tool in {'systemctl', 'chmod', 'dd'}:
        assert rules(result) == {'unknown-command'}
        assert selected(result, 'unknown-command')[0].data['possible']
    else:
        assert rule in rules(result)
        assert all(f.data['possible'] for f in selected(result, rule))


@pytest.mark.parametrize('shell', SHELLS)
def test_inline_interpreter_source_is_checked_for_every_candidate(shell):
    ref = '"$V"' if shell == 'bash' else '$v' if shell == 'powershell' else '"%V%"'
    safe, danger = ('true', 'rm -rf /etc') if shell == 'bash' else ('print(1)', "import shutil; shutil.rmtree('C:/')")
    interpreter = 'bash' if shell == 'bash' else 'python'
    result, _ = report(shell, branch(shell, safe, danger, f'{interpreter} -c {ref}'))
    assert 'delete-protected-root' in rules(result)
    assert selected(result, 'delete-protected-root')[0].data['possible']


@pytest.mark.parametrize('shell', SHELLS)
def test_written_code_candidates_are_inspected_at_none(shell):
    code = 'rm -rf /etc' if shell == 'bash' else r'Remove-Item C:\ -Recurse -Force' if shell == 'powershell' else 'rd /s /q C:\\'
    command = {'bash': 'echo "$V" > task.sh', 'powershell': 'Set-Content task.ps1 $v', 'cmd': 'echo %V% > task.cmd'}[shell]
    result, _ = report(shell, branch(shell, 'echo safe', code, command))
    danger = selected(result, 'delete-protected-root')[0]
    assert danger.data['possible'] and danger.data['context'] == 'written_content'


@pytest.mark.parametrize('shell', SHELLS)
def test_pipeline_file_alternatives_are_execution_choices(shell):
    pipe = {'bash': 'cat "$V" | bash', 'powershell': 'Get-Content $v | python -', 'cmd': 'type %V% | python -'}[shell]
    sep = '/' if shell == 'bash' else '\\'
    files = {cwd(shell)+sep+'a': 'crontab -r' if shell == 'bash' else "import os; os.system('crontab -r')", cwd(shell)+sep+'b': 'rm -rf /etc' if shell == 'bash' else "import shutil; shutil.rmtree('C:/')"}
    result, provider = report(shell, branch(shell, 'a', 'b', pipe), files=files, effort=EvidenceEffort.FULL)
    assert 'delete-protected-root' in rules(result)
    assert selected(result, 'delete-protected-root')[0].data['possible']
    assert {q.path for q in provider.queries if isinstance(q, ReadFile)} == set(files)


@pytest.mark.parametrize('shell,source', [
    ('bash', 'if true; then rm script.sh; else bash script.sh; fi'),
    ('powershell', 'if ($condition) {Remove-Item script.py} else {python script.py}'),
    ('cmd', 'if exist marker (del script.py) else (python script.py)'),
])
def test_mutually_exclusive_branches_do_not_dirty_each_others_source(shell, source):
    sep = '/' if shell == 'bash' else '\\'
    name = 'script.sh' if shell == 'bash' else 'script.py'
    content = 'rm -rf /etc' if shell == 'bash' else "import shutil; shutil.rmtree('C:/')"
    result, provider = report(shell, source, files={cwd(shell)+sep+name:content}, effort=EvidenceEffort.FULL)
    assert 'delete-protected-root' in rules(result)
    assert [q.path for q in provider.queries if isinstance(q, ReadFile)] == [cwd(shell)+sep+name]


@pytest.mark.parametrize('shell,source', [
    ('bash', 'v=a; if true; then v=b; elif false; then v=/etc; else v=c; fi; rm -rf "$v"'),
    ('powershell', "$v='a'; if ($c) {$v='b'} elseif ($d) {$v='C:\\'} else {$v='c'}; Remove-Item $v -Recurse -Force"),
    ('cmd', 'set v=a\nif 1 EQU 1 (set v=b) else (set v=C:\\)\nrd /s /q %v%'),
])
def test_exhaustive_alternatives_exclude_superseded_entry_binding(shell, source):
    result, _ = report(shell, source)
    assert 'delete-protected-root' in rules(result)
    assert 'delete-variable-unresolved' not in rules(result)
    assert not any(f.data.get('target') == cwd(shell)+('/a' if shell == 'bash' else r'\a') for f in result.findings)


@pytest.mark.parametrize('source', [
    'if (Stop-Computer) {}',
    'if ($c) {} elseif (Stop-Computer) {}',
    r"switch ($x) {1 {Remove-Item 'C:\' -Recurse -Force} default {Write-Output ok}}",
])
def test_powershell_control_conditions_and_switch_arms_keep_visible_effects(source):
    result, _ = report('powershell', source)
    assert rules(result) & {'machine-power-change', 'delete-protected-root'}


def test_dotnet_recursive_boolean_choices_preserve_both_meanings():
    source = "$recursive=$false; if ($c) {$recursive=$true}; [IO.Directory]::Delete('C:\\', $recursive)"
    result, _ = report('powershell', source)
    assert 'delete-protected-root' in rules(result)
    assert 'delete-recursion-unresolved' not in rules(result)
    assert selected(result, 'delete-protected-root')[0].data['possible']


def test_cmd_percent_snapshot_and_delayed_domain_are_distinct():
    source = 'setlocal EnableDelayedExpansion\nset v=a\nif exist marker set v=b\n(set v=c & rd /s /q %v% & rd /s /q !v!)'
    result, _ = report('cmd', source)
    assert {f.data['target'] for f in selected(result, 'delete-inside-workspace')} == {r'C:\work\a', r'C:\work\b', r'C:\work\c'}
    assert 'delete-variable-unresolved' not in rules(result)


def test_cmd_for_variables_do_not_leak_or_ignore_case():
    result, _ = report('cmd', 'for %n in (a b) do rd /s /q %N\nrd /s /q %n')
    assert 'delete-variable-unresolved' in rules(result)
    assert 'delete-inside-workspace' not in rules(result)


@pytest.mark.parametrize('shell,source', [
    ('bash', 'a=x; while true; do a="${a}x"; done; rm -rf "$a"; rm -rf /etc'),
    ('powershell', "$a='x'; while ($true) {$a=\"${a}x\"}; Remove-Item $a -Recurse -Force; Remove-Item C:\\ -Recurse -Force"),
    ('cmd', 'setlocal EnableDelayedExpansion\nset a=x\nfor %n in (1 2) do (set a=!a!x)\nrd /s /q !a!\nrd /s /q C:\\'),
])
def test_control_budget_widens_without_hiding_literal_destruction(shell, source):
    result, _ = report(shell, source, config=AnalyzerConfig(control_flow_steps=1))
    assert {'unresolved-value', 'delete-variable-unresolved', 'delete-protected-root'} <= rules(result)


def test_powershell_catch_sees_possible_try_prefix_bindings():
    source = "$v='a'; try {$v='C:\\'; $v='b'; throw 'bad'} catch {Remove-Item $v -Recurse -Force}"
    result, _ = report('powershell', source)
    assert 'delete-protected-root' in rules(result)
    assert selected(result, 'delete-protected-root')[0].data['possible']


def test_powershell_finally_overrides_joined_values():
    source = "$v='C:\\'; try {$v='a'} catch {$v='b'} finally {$v='safe'}; Remove-Item $v -Recurse -Force"
    result, _ = report('powershell', source)
    assert 'delete-protected-root' not in rules(result)
    assert {f.data['target'] for f in selected(result, 'delete-inside-workspace')} == {r'C:\work\safe'}


def test_bash_case_default_excludes_the_superseded_initial_value():
    result, _ = report('bash', 'v=/etc; case "$key" in a) v=a;; *) v=b;; esac; rm -rf "$v"')
    assert 'delete-protected-root' not in rules(result)
    assert {f.data['target'] for f in selected(result, 'delete-inside-workspace')} == {'/work/a','/work/b'}


def test_bash_all_arm_readonly_is_definite():
    result, _ = report('bash', 'v=/etc; if true; then readonly v; else readonly v; fi; v=a; rm -rf "$v"')
    assert rules(result) == {'readonly-assignment-failed'}
    assert result.findings[0].data.get('possible') is not True


@pytest.mark.parametrize('shell,source', [
    ('bash', 'a=x; while true; do a="$a$a"; done; rm -rf "$a"; rm -rf /etc'),
    ('powershell', "$a='x'; while ($true) {$a=\"$a$a\"}; Remove-Item $a -Recurse -Force; Remove-Item C:\\ -Recurse -Force"),
    ('cmd', 'setlocal EnableDelayedExpansion\nset a=x\nfor %n in (1 2) do (set a=!a!!a!)\nrd /s /q !a!\nrd /s /q C:\\'),
])
def test_expanded_value_byte_budget_stops_doubling_and_preserves_literal_risks(shell, source):
    result, _ = report(shell, source, config=AnalyzerConfig(value_bytes=64))
    assert {'delete-variable-unresolved', 'delete-protected-root'} <= rules(result)
    assert 'value_bytes_limit' in selected(result, 'delete-variable-unresolved')[0].data['unresolved_reasons']


@pytest.mark.parametrize('shell,source', [
    ('bash', 'for n in a b; do cat "$n"; done'),
    ('powershell', "foreach ($n in 'a','b') {Get-Content $n}"),
    ('powershell', "'a','b' | ForEach-Object {Get-Content $_}"),
    ('cmd', 'for %n in (a b) do type %n'),
])
def test_finite_in_workspace_loop_reads_are_quiet(shell, source):
    sep = '/' if shell == 'bash' else '\\'
    result, _ = report(shell, source, files={cwd(shell)+sep+'a': 'ordinary text',cwd(shell)+sep+'b': 'ordinary text'}, effort=EvidenceEffort.FULL)
    assert result.to_dict() == {}


@pytest.mark.parametrize('launcher', ['cmd /c "rd /s /q %V%"', 'pwsh -Command "Remove-Item %V% -Recurse -Force"'])
def test_cmd_unresolved_launcher_interpolation_never_crashes(launcher):
    result, _ = report('cmd', branch('cmd', 'a', 'b', launcher), config=AnalyzerConfig(possible_values=1))
    assert 'execution-content-unavailable' in rules(result)


@pytest.mark.parametrize('assignment', ['set a=%MISSING%', 'set /p a=Prompt', 'set /a a=1+2'])
def test_cmd_unknown_assignment_does_not_restore_the_old_binding(assignment):
    result, _ = report('cmd', 'set a=safe\n'+assignment+'\nrd /s /q %a%')
    assert 'delete-variable-unresolved' in rules(result)
    assert 'delete-inside-workspace' not in rules(result)


def test_powershell_condition_exit_binding_is_not_lost_when_body_restores_it():
    source = "$v='a'; while (($v='C:\\')) {$v='a'}; Remove-Item $v -Recurse -Force"
    result, _ = report('powershell', source)
    assert 'delete-protected-root' in rules(result)
    assert selected(result, 'delete-protected-root')[0].data['possible']


def test_powershell_foreach_rebinds_input_domain_before_each_abstract_pass():
    source = "foreach ($n in 'a','b') {Remove-Item $n -Recurse -Force; $n='C:\\'}"
    result, _ = report('powershell', source)
    assert 'delete-protected-root' not in rules(result)
    assert {f.data['target'] for f in selected(result, 'delete-inside-workspace')} == {r'C:\work\a', r'C:\work\b'}


def test_grouped_interpreter_notice_keeps_later_possible_metadata():
    source = 'python -c "print(1)"; v="print(2)"; if true; then v="print(3)"; fi; python -c "$v"'
    result, _ = report('bash', source)
    notices = selected(result, 'uses-interpreter')
    assert len(notices) == 1
    assert notices[0].data['possible']
    assert set(notices[0].data['possible_values']['v']) == {'print(2)', 'print(3)'}


def test_argument_byte_budget_also_applies_with_an_unknown_operand():
    from command_inspector.shared.value_flow import bounded_arguments, ValueLimits
    values = bounded_arguments([Value(None, 'missing', ('x',)), Value('a'*40, variables=('y',)), Value('b'*40, variables=('z',)), Value('/etc')], ValueLimits(bytes=64))
    assert [v.reason for v in values[:3]] == ['value_bytes_limit']*3
    assert values[3].text == '/etc'


def test_combined_cached_stdin_is_bounded_before_concatenation():
    result, _ = report('bash', 'cat a a a | bash', files={'/work/a': '# comment\n'},
                       config=AnalyzerConfig(file_bytes=20), effort=EvidenceEffort.FULL)
    assert selected(result, 'unreadable-payload')[0].data['reason'] == 'file_bytes_limit'


@pytest.mark.parametrize('invalid', [0, True, '64'])
def test_value_byte_budget_requires_a_positive_integer(invalid):
    with pytest.raises(ConfigurationError):
        AnalyzerConfig(value_bytes=invalid)


def test_powershell_short_circuit_chain_preserves_intermediate_exit_values():
    source = "$v='a'; Write-Output ok && ($v='C:\\') && ($v='b'); Remove-Item $v -Recurse -Force"
    result, _ = report('powershell', source)
    assert 'delete-protected-root' in rules(result)
    assert 'delete-variable-unresolved' not in rules(result)


def test_bash_possible_readonly_names_keep_declaration_effects():
    source = 'x=safe; name=x; if true; then name=y; fi; readonly "$name"; x=/etc; rm -rf "$x"'
    result, _ = report('bash', source)
    assert {'readonly-assignment-failed', 'delete-protected-root', 'delete-inside-workspace'} <= rules(result)
    assert selected(result, 'readonly-assignment-failed')[0].data['possible']


def test_bash_possible_export_names_reach_nested_source():
    source = 'x=/etc; name=x; if true; then name=y; fi; export "$name"; bash -c \'rm -rf "$x"\''
    result, _ = report('bash', source)
    assert 'delete-protected-root' in rules(result)


def test_cmd_possible_metadata_uses_plain_delayed_and_loop_variable_names():
    source = 'setlocal EnableDelayedExpansion\nset v=a\nif exist marker set v=b\nfor %n in (a b) do rd /s /q !v!\\%n'
    result, _ = report('cmd', source)
    assert selected(result, 'delete-inside-workspace')
    assert all(set(f.data['possible_values']) == {'v','n'} for f in selected(result, 'delete-inside-workspace'))


def test_bash_short_circuit_chain_preserves_intermediate_exit_values():
    result, _ = report('bash', 'v=a; v=/etc && v=b && v=c; rm -rf "$v"')
    assert 'delete-protected-root' in rules(result)
    assert {f.data['target'] for f in selected(result, 'delete-inside-workspace')} == {'/work/b','/work/c'}
    assert 'delete-variable-unresolved' not in rules(result)


@pytest.mark.parametrize('shell', ['powershell','cmd'])
@pytest.mark.parametrize('effort', [EvidenceEffort.FULL,EvidenceEffort.PARTIAL])
def test_windows_possible_wildcards_expand_only_at_use(shell, effort):
    source = branch(shell, '*.txt', '*.log', 'Remove-Item $v' if shell == 'powershell' else 'del %V%')
    files = {r'C:\work\a.txt': 'text',r'C:\work\b.log': 'log'}
    result, provider = report(shell, source, files=files, effort=effort)
    assert 'delete-variable-unresolved' not in rules(result)
    deletion = selected(result,'delete-inside-workspace')
    assert deletion and all(f.data['possible'] for f in deletion)
    assert not any(isinstance(q,ReadFile) for q in provider.queries)


def test_capabilities_exposes_current_flow_budgets():
    capabilities = Analyzer(AnalyzerConfig(possible_values=4,control_flow_steps=10,value_bytes=1024)).capabilities()
    assert capabilities['bounded_value_tracking'] == [*SHELLS, 'python', 'javascript']
    assert capabilities['control_flow_limits'] == {'possible_values':4,'control_flow_steps':10,'value_bytes':1024}


@pytest.mark.parametrize('shell', SHELLS)
def test_possible_cd_destinations_never_restore_the_old_workspace_directory(shell):
    source = branch(shell, 'cache', '/outside' if shell == 'bash' else r'C:\outside',
                    {'bash':'cd "$V" && rm child','powershell':'Set-Location $v && Remove-Item child','cmd':'cd %V% && rd child'}[shell])
    result, _ = report(shell, source)
    if shell in {'bash', 'powershell'}:
        assert 'delete-variable-unresolved' not in rules(result)
        assert {'delete-inside-workspace', 'delete-outside-workspace'} <= rules(result)
        targets = {f.data['target'] for f in result.findings if f.rule.startswith('delete-')}
        assert ('/work/child' if shell == 'bash' else r'C:\work\child') not in targets
    else:
        assert 'delete-variable-unresolved' in rules(result)
        assert 'delete-inside-workspace' not in rules(result)


def test_cmd_branch_scope_changes_leave_delayed_mode_uncertain():
    source = 'setlocal DisableDelayedExpansion\nset v=C:\\\nif exist marker (setlocal EnableDelayedExpansion)\nrd /s /q !v!'
    result, _ = report('cmd', source)
    assert 'delete-variable-unresolved' in rules(result)
    assert 'delete-inside-workspace' not in rules(result)


def test_cmd_unknown_scope_cannot_restore_a_stale_safe_binding():
    source = 'set v=C:\\\nif exist marker (setlocal & set v=cache) else (set v=cache)\nset v=cache\nendlocal\nrd /s /q %v%'
    result, _ = report('cmd', source)
    assert 'delete-variable-unresolved' in rules(result)
    assert 'delete-inside-workspace' not in rules(result)


def test_cmd_equally_nested_branch_scopes_restore_joined_outer_values():
    source = 'set v=C:\\\nif exist marker (setlocal & set v=a) else (setlocal & set v=b)\nendlocal\nrd /s /q %v%'
    result, _ = report('cmd', source)
    assert 'delete-protected-root' in rules(result)
    assert 'delete-variable-unresolved' not in rules(result)


def test_cmd_possible_setlocal_options_do_not_confirm_delayed_expansion():
    source = 'set target=C:\\\n' + branch('cmd','EnableDelayedExpansion','DisableDelayedExpansion','setlocal %V%\nrd /s /q !target!')
    result, _ = report('cmd', source)
    assert 'delete-variable-unresolved' in rules(result)
