"""Loop coverage regressions; all shell commands are input text only."""
import pytest

from command_inspector import Analyzer
from command_inspector.local_evidence import DisabledEvidenceProvider
from command_inspector.models import Level
from command_inspector.bash.semantics import SemanticBuilder


def analyze(source, shell='bash'):
    cwd = '/work' if shell == 'bash' else 'C:\\work'
    return Analyzer(evidence=DisabledEvidenceProvider()).analyze_report(source, cwd, shell=shell)


def facts(source):
    parsed = Analyzer().parse(source, shell='bash')
    assert not parsed.diagnostics
    return SemanticBuilder('/work', {}).build(parsed.root)


def rules(report):
    return {f.rule for f in report.findings}


@pytest.mark.parametrize('source,shell,target', [
    ('for ((i=0;i<3;i++)); do rm -rf /etc; done', 'bash', '/etc'),
    ('for i in a b; do rm -rf /etc; done', 'bash', '/etc'),
    (r'Get-ChildItem | ForEach-Object -Parallel {Remove-Item -Recurse -Force C:\}', 'powershell', 'C:\\'),
])
def test_literal_protected_deletion_is_visible_in_all_loop_forms(source, shell, target):
    result = analyze(source, shell)
    assert result.level == Level.BLOCK
    assert 'delete-protected-root' in rules(result)
    deletion = next(f for f in result.findings if f.rule == 'delete-protected-root')
    assert deletion.data['target'] == target


@pytest.mark.parametrize('header', ['i=0;i<3;i++', ';;', 'i=0;0;i++'])
@pytest.mark.parametrize('body', ['do rm -rf /etc; done', '{ rm -rf /etc; }'])
def test_arithmetic_loop_body_is_inspected_once_without_evaluating_conditions(header, body):
    operations = [f for f in facts('for ((' + header + ')); ' + body) if f.kind == 'delete']
    assert len(operations) == 1
    assert operations[0].targets == ('/etc',)
    assert operations[0].guard == 'if the loop body runs'


@pytest.mark.parametrize('header,name', [
    ('i=0;i<3;i++', 'i'),
    ('i=0;i<3;++i', 'i'),
    ('i=0;i<3;--i', 'i'),
    ('i=0;i++<3;', 'i'),
    ('i=0;i<3;i+=1', 'i'),
    ('i=0;i<3;i<<=1', 'i'),
    ('i=0,j=2;i<3;j--,i++', 'j'),
    ('i=(j=0);i<3;i++', 'j'),
    ('i=0;limit;(j+=1,k--)', 'k'),
])
def test_arithmetic_header_writes_discard_stale_bindings_in_body_and_after_loop(header, name):
    source = name + '=/etc; for ((' + header + ')); do rm -rf "$' + name + '"; done; rm -rf "$' + name + '"'
    result = analyze(source)
    assert result.level == Level.MEDIUM
    assert 'delete-variable-unresolved' in rules(result)
    assert 'delete-protected-root' not in rules(result)
    operations = [f for f in facts(source) if f.kind == 'delete']
    assert len(operations) == 2
    assert all(not f.targets and f.values[0].text is None for f in operations)


@pytest.mark.parametrize('part', ['init', 'condition', 'update'])
def test_header_substitution_effects_are_inspected_once(part):
    header = {
        'init': 'i=$(sudo reboot);i<3;i++',
        'condition': 'i=0;$(sudo reboot);i++',
        'update': 'i=0;i<3;i+=$(sudo reboot)',
    }[part]
    source = 'for ((' + header + ')); do :; done'
    result = analyze(source)
    assert {'privilege-escalation', 'machine-power-change'} <= rules(result)
    power = [f for f in facts(source) if f.operation == 'machine-power-change']
    assert len(power) == 1
    assert power[0].guard == 'during command substitution'


def test_header_substitution_assignments_do_not_invalidate_parent_bindings():
    source = 'x=/etc; for ((i=$(x=0; echo 0);i<3;i++)); do rm -rf "$x"; done'
    result = analyze(source)
    assert 'delete-protected-root' in rules(result)
    assert 'delete-variable-unresolved' not in rules(result)


def test_header_reads_do_not_invalidate_unchanged_bindings():
    result = analyze('x=/etc; for ((i=0;x;i++)); do rm -rf "$x"; done')
    assert 'delete-protected-root' in rules(result)
    assert 'delete-variable-unresolved' not in rules(result)


def test_arithmetic_header_readonly_write_is_rejected_without_overwriting_binding():
    result = analyze('readonly i=/etc; for ((i=0;i<3;i++)); do :; done; rm -rf "$i"')
    assert 'readonly-assignment-failed' in rules(result)
    assert 'delete-protected-root' in rules(result)
    assert 'delete-variable-unresolved' not in rules(result)


def test_arithmetic_path_write_remains_an_environment_change():
    result = analyze('for ((PATH=0;0;)); do :; done')
    assert 'environment-modified' in rules(result)


@pytest.mark.parametrize('source', [
    'x=/etc; for ((i=0;i<3;i++)); do x=/work/cache; done; rm -rf "$x"',
    'x=/work/cache; for ((i=0;i<3;i++)); do x=/etc; done; rm -rf "$x"',
    'for ((i=0;i<3;i++)); do x=/etc; done; rm -rf "$x"',
])
def test_body_modified_bindings_remain_uncertain_after_arithmetic_loop(source):
    result = analyze(source)
    if source.startswith('x='):
        assert {'delete-protected-root', 'delete-inside-workspace'} <= rules(result)
        assert 'delete-variable-unresolved' not in rules(result)
        assert all(f.data['possible'] for f in result.findings if f.rule.startswith('delete-'))
    else:
        assert 'delete-variable-unresolved' in rules(result)
        assert 'delete-protected-root' not in rules(result)


def test_arithmetic_loop_cwd_change_is_not_restored_to_old_directory():
    source = 'for ((i=0;i<3;i++)); do cd build; done; rm -rf cache'
    operation = next(f for f in facts(source) if f.kind == 'delete')
    assert operation.cwd is None
    assert operation.targets == ()


def test_nested_loop_retains_outer_guard():
    source = 'for i in a b; do for ((j=0;j<3;j++)); do rm -rf /etc; done; done'
    operation = next(f for f in facts(source) if f.kind == 'delete')
    assert operation.guard == 'if the loop body runs; if the loop body runs'


def test_defined_function_loop_keeps_defined_body_context():
    operation = next(f for f in facts('unused() { for ((i=0;i<3;i++)); do rm -rf /etc; done; }') if f.kind == 'delete')
    assert operation.context == 'defined_body'


@pytest.mark.parametrize('control', ['break', 'continue'])
@pytest.mark.parametrize('argument', ['', ' 2', ' "$depth"'])
def test_loop_control_is_a_coverage_notice_not_an_unknown_command(control, argument):
    result = analyze('for ((i=0;i<3;i++)); do ' + control + argument + '; done')
    assert result.level == Level.LOW
    assert 'unsupported-syntax' in rules(result)
    assert 'unknown-command' not in rules(result)
    if '$depth' in argument:
        assert 'unresolved-value' in rules(result)


@pytest.mark.parametrize('control', ['break', 'continue'])
def test_loop_control_does_not_hide_following_visible_operations(control):
    source = 'for ((i=0;i<3;i++)); do ' + control + '; rm -rf /etc; done; sudo reboot'
    result = analyze(source)
    assert {'delete-protected-root', 'privilege-escalation', 'machine-power-change'} <= rules(result)
    assert 'unknown-command' not in rules(result)


@pytest.mark.parametrize('control', ['break', 'continue'])
def test_loop_control_argument_substitution_is_inspected(control):
    result = analyze(control + ' $(sudo reboot)')
    assert {'privilege-escalation', 'machine-power-change', 'unsupported-syntax'} <= rules(result)
    assert 'unknown-command' not in rules(result)


def test_readonly_arithmetic_loop_keeps_a_coverage_notice():
    result = analyze('for ((i=0;i<3;i++)); do echo "$i"; done')
    assert result.level == Level.LOW
    assert 'unsupported-syntax' in rules(result)
    assert 'unknown-command' not in rules(result)


@pytest.mark.parametrize('loop', ['while', 'until'])
@pytest.mark.parametrize('condition', ['true', 'false'])
def test_condition_loops_keep_literal_body_deletions_visible_once(loop, condition):
    source = loop + ' ' + condition + '; do rm -rf /etc; done'
    result = analyze(source)
    assert result.level == Level.BLOCK
    assert rules(result) == {'delete-protected-root', 'unsupported-syntax'}
    operations = [f for f in facts(source) if f.kind == 'delete']
    assert len(operations) == 1
    assert operations[0].guard == 'if the loop body runs'


@pytest.mark.parametrize('loop', ['while', 'until'])
@pytest.mark.parametrize('initial,changed', [('/work/cache', '/etc'), ('/etc', '/work/cache')])
def test_condition_loop_does_not_restore_stale_body_modified_binding(loop, initial, changed):
    source = 'x=' + initial + '; ' + loop + ' true; do x=' + changed + '; done; rm -rf "$x"'
    result = analyze(source)
    assert result.level == Level.BLOCK
    assert {'delete-protected-root', 'delete-inside-workspace'} <= rules(result)
    assert 'delete-variable-unresolved' not in rules(result)
    assert all(f.data['possible'] for f in result.findings if f.rule.startswith('delete-'))


@pytest.mark.parametrize('loop', ['while', 'until'])
def test_condition_loop_does_not_restore_stale_cwd(loop):
    operation = next(f for f in facts(loop + ' true; do cd build; done; rm -rf cache') if f.kind == 'delete')
    assert operation.cwd is None
    assert operation.targets == ()


@pytest.mark.parametrize('loop', ['while', 'until'])
def test_condition_cwd_change_remains_uncertain_even_if_body_restores_original(loop):
    source = loop + ' cd build && true; do cd /work && true; done; rm -rf cache'
    operation = next(f for f in facts(source) if f.kind == 'delete')
    assert operation.cwd is None
    assert operation.targets == ()


@pytest.mark.parametrize('loop', ['while', 'until'])
def test_condition_assignment_not_ignored_or_reverted_when_body_restores_old_value(loop):
    source = 'x=/work/cache; ' + loop + ' x=/etc; do rm -rf "$x"; x=/work/cache; done; rm -rf "$x"'
    operations = [f for f in facts(source) if f.kind == 'delete']
    assert operations[0].targets == ('/etc',)
    assert {p for f in operations[1:] for p in f.targets} == {'/etc', '/work/cache'}
    result = analyze(source)
    assert {'delete-protected-root', 'delete-inside-workspace'} <= rules(result)
    assert 'delete-variable-unresolved' not in rules(result)


@pytest.mark.parametrize('loop', ['while', 'until'])
@pytest.mark.parametrize('condition', [
    'sudo reboot', '! sudo reboot', '(sudo reboot)', '{ sudo reboot; }',
    'sudo reboot | cat', '[[ "$(sudo reboot)" ]]',
    '[ -n "$(sudo reboot)" ]', '[[ -f marker ]] && [ -n "$(sudo reboot)" ]',
])
def test_visible_condition_effects_are_inspected_once(loop, condition):
    source = loop + ' ' + condition + '; do :; done'
    result = analyze(source)
    assert {'privilege-escalation', 'machine-power-change'} <= rules(result)
    assert 'unknown-command' not in rules(result)
    assert len([f for f in facts(source) if f.operation == 'machine-power-change']) == 1


@pytest.mark.parametrize('loop', ['while', 'until'])
@pytest.mark.parametrize('condition', [
    '((i++ < 3))', '((++i < 3))', '((i+=1))', '((i=0))',
    '((i++))', '[[ $((i++)) ]]', 'x=$((i++))',
])
def test_condition_arithmetic_writes_discard_old_literal_before_body_and_after_loop(loop, condition):
    source = 'i=/etc; ' + loop + ' ' + condition + '; do rm -rf "$i"; done; rm -rf "$i"'
    result = analyze(source)
    assert result.level == Level.MEDIUM
    assert 'delete-variable-unresolved' in rules(result)
    assert 'delete-protected-root' not in rules(result)
    assert 'unknown-command' not in rules(result)
    operations = [f for f in facts(source) if f.kind == 'delete']
    assert len(operations) == 2
    assert all(not f.targets for f in operations)


@pytest.mark.parametrize('loop', ['while', 'until'])
def test_arithmetic_body_write_is_not_lost_after_condition_loop(loop):
    result = analyze('i=/etc; ' + loop + ' ((i < 3)); do ((i++)); done; rm -rf "$i"')
    assert 'delete-variable-unresolved' in rules(result)
    assert 'delete-protected-root' not in rules(result)


@pytest.mark.parametrize('loop', ['while', 'until'])
def test_readonly_arithmetic_condition_retains_rejected_binding(loop):
    result = analyze('readonly i=/etc; ' + loop + ' ((i=0)); do :; done; rm -rf "$i"')
    assert {'readonly-assignment-failed', 'delete-protected-root'} <= rules(result)


@pytest.mark.parametrize('loop', ['while', 'until'])
def test_arithmetic_substitution_assignments_stay_in_substitution_scope(loop):
    source = 'x=/etc; ' + loop + ' ((i=$(x=0; echo 0))); do rm -rf "$x"; done'
    result = analyze(source)
    assert 'delete-protected-root' in rules(result)
    assert 'delete-variable-unresolved' not in rules(result)


@pytest.mark.parametrize('loop', ['while', 'until'])
def test_condition_subshell_binding_does_not_leak_into_loop_body(loop):
    result = analyze('x=/etc; ' + loop + ' (x=/work/cache); do rm -rf "$x"; done')
    assert 'delete-protected-root' in rules(result)
    assert 'delete-variable-unresolved' not in rules(result)


@pytest.mark.parametrize('loop', ['while', 'until'])
def test_unchanged_binding_remains_concrete_across_condition_loop(loop):
    result = analyze('x=/etc; ' + loop + ' true; do echo hello; done; rm -rf "$x"')
    assert 'delete-protected-root' in rules(result)
    assert 'delete-variable-unresolved' not in rules(result)


@pytest.mark.parametrize('loop', ['while', 'until'])
@pytest.mark.parametrize('control', ['break', 'continue'])
def test_condition_loop_control_does_not_hide_literal_operations(loop, control):
    result = analyze(loop + ' true; do ' + control + '; rm -rf /etc; done')
    assert 'delete-protected-root' in rules(result)
    assert 'unknown-command' not in rules(result)


@pytest.mark.parametrize('loop', ['while', 'until'])
def test_condition_loop_nested_in_for_preserves_outer_guard(loop):
    operation = next(f for f in facts('for i in a b; do ' + loop + ' true; do rm -rf /etc; done; done') if f.kind == 'delete')
    assert operation.guard == 'if the loop body runs; if the loop body runs'


@pytest.mark.parametrize('loop', ['while', 'until'])
@pytest.mark.parametrize('reader,name', [
    ('read -r x', 'x'), ('IFS= read -r x', 'x'), ('read -rs x', 'x'),
    ('read -d : -u3 x', 'x'), ('read -a x', 'x'), ('read', 'REPLY'),
])
def test_read_condition_has_runtime_bindings_instead_of_old_literal_targets(loop, reader, name):
    source = name + '=/etc; ' + loop + ' ' + reader + '; do rm -rf "$' + name + '"; done'
    result = analyze(source)
    assert result.level == Level.MEDIUM
    assert 'delete-variable-unresolved' in rules(result)
    assert 'delete-protected-root' not in rules(result)
    assert 'unknown-command' not in rules(result)


def test_uncertain_read_options_do_not_preserve_possible_written_bindings():
    result = analyze('x=/etc; while read -Z x; do rm -rf "$x"; done')
    assert {'unknown-option', 'delete-variable-unresolved'} <= rules(result)
    assert 'delete-protected-root' not in rules(result)


def test_read_argument_substitution_effects_remain_visible():
    result = analyze('while read -p "$(sudo reboot)" x; do :; done')
    assert {'privilege-escalation', 'machine-power-change'} <= rules(result)


def test_read_names_do_not_invalidate_unrelated_binding():
    result = analyze('kept=/etc; while read -r x; do :; done; rm -rf "$kept"')
    assert 'delete-protected-root' in rules(result)
    assert 'delete-variable-unresolved' not in rules(result)


def test_pipeline_read_loop_bindings_do_not_leak_into_parent_shell():
    source = 'x=/etc; printf line | while read -r x; do rm -rf "$x"; done; rm -rf "$x"'
    result = analyze(source)
    assert {'delete-variable-unresolved', 'delete-protected-root'} <= rules(result)
    operations = [f for f in facts(source) if f.kind == 'delete']
    assert operations[0].targets == ()
    assert operations[1].targets == ('/etc',)
