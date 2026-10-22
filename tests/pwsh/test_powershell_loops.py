"""Bounded pipeline loops: input commands are analyzed, never executed."""
import pytest

from command_inspector import Analyzer
from command_inspector.local_evidence import DisabledEvidenceProvider, MemoryEvidenceProvider
from command_inspector.models import Level
from command_inspector.bash.syntax import ParseBudgetExceeded
from command_inspector.pwsh.semantics import PowerShellBuilder
from command_inspector.pwsh.syntax import PowerShellFrontend


CWD = r'C:\work'


def analyze(command, files=None):
    provider = DisabledEvidenceProvider() if files is None else MemoryEvidenceProvider(files)
    return Analyzer(evidence=provider).analyze_report(command, CWD, shell='powershell')


def facts(command):
    root = Analyzer().parse(command, shell='powershell').root
    return PowerShellBuilder(CWD, {}).build(root)


def rules(report):
    return {f.rule for f in report.findings}


@pytest.mark.parametrize('name', ['ForEach-Object', 'foreach-object', 'FOREACH-OBJECT', '%', 'foreach'])
@pytest.mark.parametrize('prefix', ['', 'Get-ChildItem | '])
def test_visible_loop_body_uses_existing_deletion_rules(name, prefix):
    result = analyze(prefix + name + r' {Remove-Item C:\Windows -Recurse -Force}')
    assert rules(result) == {'delete-protected-root', 'unsupported-syntax'}
    assert result.level == Level.BLOCK
    deletion = next(f for f in result.findings if f.rule == 'delete-protected-root')
    assert deletion.data['target'] == r'C:\Windows'


@pytest.mark.parametrize('body', ['', 'Write-Output $_', '$_.Name', 'Write-Output $PSItem'])
def test_readonly_body_retains_only_the_bash_style_loop_notice(body):
    result = analyze('Get-ChildItem | ForEach-Object {' + body + '}')
    assert rules(result) == {'unsupported-syntax'}
    assert result.level == Level.LOW
    assert result.findings[0].title == 'Loop iteration counts are not modeled'


@pytest.mark.parametrize('name', ['_', 'PSItem', '{_}', '{PSItem}'])
@pytest.mark.parametrize('initial', [r"'C:\Windows'", r"@('C:\Windows','build')"])
def test_current_item_discards_old_literal_and_array_bindings(name, initial):
    source = '$' + name + '=' + initial + '; Get-ChildItem | % {Remove-Item $' + name + ' -Recurse -Force}'
    result = analyze(source)
    assert rules(result) == {'delete-variable-unresolved', 'unsupported-syntax'}
    assert result.level == Level.MEDIUM
    assert not any('target' in f.data for f in result.findings)


@pytest.mark.parametrize('input_source', [
    r"'C:\Windows','build' | ForEach-Object",
    r"ForEach-Object -InputObject 'C:\Windows'",
    r"ForEach-Object -InputObject @('C:\Windows','build')",
])
def test_literal_input_binds_bounded_current_item_choices(input_source):
    result = analyze(input_source + ' {Remove-Item $_ -Recurse -Force}')
    assert 'delete-protected-root' in rules(result)
    assert 'delete-variable-unresolved' not in rules(result)
    assert result.level == Level.BLOCK


@pytest.mark.parametrize('source', [
    r"$x='C:\Windows'; 1,2 | % {$x='build'}; Remove-Item $x -Recurse -Force",
    r"$x='build'; 1,2 | % {$x='C:\Windows'}; Remove-Item $x -Recurse -Force",
    r"1,2 | % {$x='C:\Windows'}; Remove-Item $x -Recurse -Force",
    r"$x=@('C:\Windows','build'); 1,2 | % {$x=@('build','cache')}; Remove-Item $x -Recurse -Force",
    r"$env:X='C:\Windows'; 1,2 | % {$env:X='build'}; Remove-Item $env:X -Recurse -Force",
    r"$x='C:\Windows'; 1 | % {1 | % {$x='build'}}; Remove-Item $x -Recurse -Force",
])
def test_changed_caller_bindings_become_unresolved(source):
    result = analyze(source)
    if source.startswith('1,2') or '$x=@' in source:
        assert 'delete-variable-unresolved' in rules(result)
        assert 'delete-protected-root' not in rules(result)
        assert result.level == Level.MEDIUM
    else:
        assert {'delete-protected-root', 'delete-inside-workspace'} <= rules(result)
        assert 'delete-variable-unresolved' not in rules(result)
        assert result.level == Level.BLOCK
    assert 'unknown-command' not in rules(result)


def test_unchanged_caller_binding_remains_concrete():
    result = analyze(r"$x='C:\Windows'; 1 | % {Write-Output $_}; Remove-Item $x -Recurse -Force")
    assert 'delete-protected-root' in rules(result)
    assert 'delete-variable-unresolved' not in rules(result)


def test_literal_assignment_inside_body_is_visible_without_simulating_output():
    result = analyze(r"1 | % {$x='C:\Windows'; Remove-Item $x -Recurse -Force}")
    assert 'delete-protected-root' in rules(result)


def test_loop_cwd_change_invalidates_later_relative_targets():
    result = analyze('1 | % {Set-Location build}; Remove-Item cache -Recurse -Force')
    assert 'delete-variable-unresolved' in rules(result)
    assert not any(f.data.get('target') == CWD + r'\cache' for f in result.findings)


@pytest.mark.parametrize('source', [
    'Set-Location build | % {Write-Output $_} && Remove-Item cache',
    '1 | % {Set-Location build} && Remove-Item cache',
])
def test_loop_success_does_not_confirm_an_uncertain_directory_change(source):
    operation = next(f for f in facts(source) if f.kind == 'delete')
    assert operation.cwd is None
    assert operation.targets == ()


def test_conditional_fatal_body_error_does_not_halt_later_top_level_analysis():
    result = analyze("$ErrorActionPreference='Stop'; 1 | % {$HOME='build'}; Stop-Computer")
    assert {'readonly-assignment-failed', 'machine-power-change'} <= rules(result)


def test_body_is_inspected_once_and_guard_is_preserved():
    operations = [f for f in facts('1,2,3 | % {Remove-Item cache}') if f.kind == 'delete']
    assert len(operations) == 1
    assert operations[0].guard == 'if the loop body runs'


@pytest.mark.parametrize('source', [
    'ForEach-Object -InputObject $(Stop-Computer) -Process {Write-Output $_}',
    'ForEach-Object -InputObject (Stop-Computer) -Process {Write-Output $_}',
    'ForEach-Object -InputObject @(Stop-Computer) -Process {Write-Output $_}',
])
def test_argument_evaluation_effects_remain_visible_once(source):
    operations = [f for f in facts(source) if f.operation == 'machine-power-change']
    assert len(operations) == 1
    assert 'during expression evaluation' in operations[0].guard


@pytest.mark.parametrize('source', [
    r'1 | % -InputObject {Remove-Item C:\Windows -Recurse -Force} {Write-Output $_}',
    r'1 | % -InputObject @({Remove-Item C:\Windows -Recurse -Force}) {Write-Output $_}',
])
def test_input_scriptblock_is_data_and_not_the_process_body(source):
    assert not any(f.kind == 'delete' for f in facts(source))


def test_incoming_pipeline_text_is_not_body_command_stdin():
    operations = [f for f in facts("Write-Output 'password=abcdefg' | % {Set-Content out}") if f.kind == 'write']
    assert len(operations) == 1
    assert operations[0].payload is None


def test_pipeline_content_read_still_receives_credential_inspection():
    result = analyze('Get-Content secrets | % {Write-Output $_}', {CWD + r'\secrets': 'password=abcdefg\n'})
    assert 'credentials-read' in rules(result)


def test_explicit_begin_process_end_phases_inspect_visible_operations_once():
    source = '1,2 | ForEach-Object -Begin {Stop-Computer} -Process {Remove-Item $_} -End {Restart-Computer}'
    operations = [f for f in facts(source) if f.kind in {'delete', 'system'}]
    assert [f.operation for f in operations] == ['machine-power-change', 'delete', 'delete', 'machine-power-change']
    assert 'begin block' in operations[0].guard
    assert all(f.guard == 'if the loop body runs' for f in operations[1:3])
    assert {f.targets for f in operations[1:3]} == {(CWD + r'\1',), (CWD + r'\2',)}
    assert 'end block' in operations[-1].guard


@pytest.mark.parametrize('source', [
    r"ForEach-Object {$x='C:\Windows'} {Remove-Item $x -Recurse -Force}",
    r"ForEach-Object -Begin {$x='C:\Windows'} -Process {Remove-Item $x -Recurse -Force}",
    r"ForEach-Object -Begin {$x='C:\Windows'} -Process {Write-Output $_} -End {Remove-Item $x -Recurse -Force}",
])
def test_begin_literal_binding_is_visible_inside_invocation(source):
    assert 'delete-protected-root' in rules(analyze(source))


def test_process_assignment_is_uncertain_in_end_block():
    result = analyze(r"$x='build'; 1 | % -Process {$x='C:\Windows'} -End {Remove-Item $x -Recurse -Force}")
    assert {'delete-protected-root', 'delete-inside-workspace'} <= rules(result)
    assert 'delete-variable-unresolved' not in rules(result)
    assert all(f.data['possible'] for f in result.findings if f.rule.startswith('delete-'))


@pytest.mark.parametrize('argument', [
    '{Remove-Item first}, {Remove-Item second}, {Remove-Item third}, {Remove-Item last}',
    '{Remove-Item first} {Remove-Item second} {Remove-Item third} {Remove-Item last}',
])
def test_multiple_scriptblocks_map_to_begin_process_end(argument):
    operations = [f for f in facts('1 | ForEach-Object ' + argument) if f.kind == 'delete']
    assert len(operations) == 4
    assert 'begin block' in operations[0].guard
    assert all(f.guard == 'if the loop body runs' for f in operations[1:3])
    assert 'end block' in operations[3].guard


@pytest.mark.parametrize('argument', [
    '{Remove-Item first}, {Remove-Item second}',
    '@({Remove-Item first}, {Remove-Item second})',
])
def test_explicit_null_begin_end_preserve_all_process_blocks(argument):
    source = 'ForEach-Object -Begin $null -Process ' + argument + ' -End $null'
    operations = [f for f in facts(source) if f.kind == 'delete']
    assert len(operations) == 2
    assert all(f.guard == 'if the loop body runs' for f in operations)


@pytest.mark.parametrize('source', ['ForEach-Object -Process $null', 'ForEach-Object -Process @()'])
def test_null_and_empty_process_arguments_do_not_invent_unavailable_code(source):
    assert rules(analyze(source)) == {'unsupported-syntax'}


@pytest.mark.parametrize('argument', [
    r"$null, {Remove-Item C:\Windows -Recurse -Force}",
    r"$body, {Remove-Item C:\Windows -Recurse -Force}",
    r"@($body, {Remove-Item C:\Windows -Recurse -Force})",
])
def test_unknown_and_null_slots_do_not_hide_literal_scriptblocks(argument):
    source = 'ForEach-Object -Process ' + argument
    result = analyze(source)
    assert 'delete-protected-root' in rules(result)
    operations = [f for f in facts(source) if f.kind == 'delete']
    assert len(operations) == 1
    assert operations[0].guard == 'if the loop body runs'
    if '$body' in argument:
        assert 'execution-content-unavailable' in rules(result)


def test_remaining_scripts_are_inspected():
    result = analyze(r'1 | % -Begin $null -Process {Write-Output $_} -RemainingScripts {Remove-Item C:\Windows -Recurse -Force} -End $null')
    assert 'delete-protected-root' in rules(result)
    assert 'unknown-option' not in rules(result)


@pytest.mark.parametrize('option', ['-NotAParameter', '-Process'])
def test_uncertain_binding_does_not_hide_visible_bodies(option):
    source = r'1 | % -Process {Remove-Item C:\Windows -Recurse -Force} ' + option + ' {Write-Output $_}'
    result = analyze(source)
    assert 'delete-protected-root' in rules(result)
    assert rules(result) & {'unknown-option', 'unresolved-value'}


@pytest.mark.parametrize('source', ['ForEach-Object -Process $body', '1 | % $body'])
def test_dynamic_process_content_retains_uncertainty(source):
    result = analyze(source)
    assert 'unknown-command' not in rules(result)
    assert rules(result) & {'execution-content-unavailable', 'unresolved-value'}


@pytest.mark.parametrize('source', ['1 | % Delete', '1 | % -MemberName Delete -ArgumentList foo'])
def test_simplified_method_dispatch_is_not_silenced(source):
    result = analyze(source)
    assert 'unresolved-value' in rules(result)
    assert 'unknown-command' not in rules(result)


@pytest.mark.parametrize('option', ['-WhatIf', '-WhatIf:$true'])
@pytest.mark.parametrize('body', [r'{Remove-Item C:\Windows -Recurse -Force}', r'@({Remove-Item C:\Windows -Recurse -Force})'])
def test_whatif_keeps_deferred_bodies_from_becoming_operations(option, body):
    source = 'ForEach-Object -Process ' + body + ' ' + option
    result = analyze(source)
    assert rules(result) == {'unresolved-value'}
    assert not any(f.kind == 'delete' for f in facts(source))


def test_false_whatif_still_inspects_body():
    result = analyze(r'1 | % -WhatIf:$false {Remove-Item C:\Windows -Recurse -Force}')
    assert 'delete-protected-root' in rules(result)


def test_whatif_still_inspects_argument_evaluation():
    source = 'ForEach-Object -WhatIf -InputObject $(Stop-Computer) -Process {Restart-Computer}'
    operations = [f for f in facts(source) if f.operation == 'machine-power-change']
    assert len(operations) == 1
    assert operations[0].guard == 'during expression evaluation'


def test_parallel_body_has_unknown_caller_variables_and_keeps_caller_binding():
    source = r"$x='C:\Windows'; 1 | % -Parallel {Remove-Item $x -Recurse -Force; $x='build'} -ThrottleLimit 2; Remove-Item $x -Recurse -Force"
    result = analyze(source)
    assert {'delete-variable-unresolved', 'delete-protected-root', 'unsupported-syntax'} <= rules(result)
    assert not rules(result) & {'unknown-command', 'unknown-option'}


def test_parallel_literal_effects_remain_visible():
    result = analyze(r'1 | ForEach-Object -Parallel {Remove-Item C:\Windows -Recurse -Force} -AsJob -UseNewRunspace -TimeoutSeconds 2')
    assert 'delete-protected-root' in rules(result)
    assert not rules(result) & {'unknown-command', 'unknown-option'}


def test_parallel_directory_change_does_not_leak_into_caller():
    operation = next(f for f in facts('1 | % -Parallel {Set-Location build}; Remove-Item cache') if f.kind == 'delete')
    assert operation.cwd == CWD
    assert operation.targets == (CWD + r'\cache',)


@pytest.mark.parametrize('source', [
    "ForEach-Object -InputObject a,b -Process {Write-Output $_}",
    "Write-Output '你好 ForEach-Object'; ForEach-Object -Begin {} -Process {Write-Output $_} -End {} # ForEach-Object",
])
def test_keyword_repair_preserves_character_spans_and_composes_with_comma_repair(source):
    parsed = Analyzer().parse(source, shell='powershell')
    assert not parsed.diagnostics
    pending = [parsed.root]
    while pending:
        node = pending.pop()
        assert node.text == source[node.span.start:node.span.end]
        pending.extend(node.children)


def test_keyword_repair_does_not_change_foreach_statement_or_longer_command_names():
    assert analyze('foreach ($n in 1,2) {Write-Output $n}').to_dict() == {}
    parsed = Analyzer().parse('ForEach-Objectify {Write-Output ok}', shell='powershell')
    assert parsed.diagnostics
    assert parsed.root.children[0].kind == 'ERROR'
    assert parsed.root.children[0].children[0].kind == 'foreach'


def test_keyword_repair_charges_both_parses_to_node_budget():
    source = 'ForEach-Object -Process {Write-Output $_}'
    frontend = PowerShellFrontend()
    def count(root):
        pending, total = [root], 0
        while pending:
            node = pending.pop()
            total += 1
            pending.extend(node.children)
        return total
    total = count(frontend._parse(source, 50000).root) + count(frontend._parse('X' + source[1:], 50000).root)
    with pytest.raises(ParseBudgetExceeded):
        frontend.parse(source, max_nodes=total - 1)
    assert not frontend.parse(source, max_nodes=total).diagnostics


def test_malformed_loop_is_not_repaired_into_valid_syntax():
    assert Analyzer().parse('ForEach-Object {', shell='powershell').diagnostics


def test_nested_loop_retains_outer_guard():
    operation = next(f for f in facts('1 | % {2 | % {Remove-Item cache}}') if f.kind == 'delete')
    assert operation.guard == 'if the loop body runs; if the loop body runs'


def test_loop_in_defined_function_keeps_defined_body_context():
    operation = next(f for f in facts('function unused {1 | % {Remove-Item cache}}') if f.kind == 'delete')
    assert operation.context == 'defined_body'


@pytest.mark.parametrize('template', [
    'while ($true) {{{body}}}',
    'do {{{body}}} while ($true)',
    'do {{{body}}} until ($true)',
    'do {{{body}}} until ($false)',
    'for ($i=0; $i -lt 3; $i++) {{{body}}}',
])
@pytest.mark.parametrize('body', ['', 'Remove-Item -Recurse -Force C:\\'])
def test_language_loops_share_the_iteration_notice_and_keep_literal_effects(template, body):
    source = template.format(body=body)
    result = analyze(source)
    expected = {'unsupported-syntax', 'delete-protected-root'} if body else {'unsupported-syntax'}
    assert rules(result) == expected
    notice = next(f for f in result.findings if f.rule == 'unsupported-syntax')
    assert notice.title == 'Loop iteration counts are not modeled'
    assert notice.level == Level.LOW
    if body:
        assert result.level == Level.BLOCK
        operations = [f for f in facts(source) if f.kind == 'delete']
        assert len(operations) == 1
        assert operations[0].guard == 'if the loop body runs'


@pytest.mark.parametrize('suffix', ['while ($true)', 'until ($true)'])
@pytest.mark.parametrize('setup, body, target', [
    (r"$x='C:\Windows'", "$x='build'", '$x'),
    (r"$x=@('C:\Windows','build')", "$x=@('build','cache')", '$x'),
    (r"$env:X='C:\Windows'", "$env:X='build'", '$env:X'),
])
def test_do_loop_changes_do_not_become_concrete_after_one_syntactic_pass(suffix, setup, body, target):
    source = f'{setup}; do {{{body}}} {suffix}; Remove-Item {target} -Recurse -Force'
    result = analyze(source)
    expected = {'delete-variable-unresolved', 'unsupported-syntax'} if '@(' in setup else {'delete-protected-root', 'delete-inside-workspace', 'unsupported-syntax'}
    if target == '$env:X':
        expected.add('environment-modified')
    assert rules(result) == expected
    operations = [f for f in facts(source) if f.kind == 'delete']
    if '@(' in setup:
        assert all(not f.targets and all(v.text is None for v in f.values) for f in operations)
    else:
        assert {p for f in operations for p in f.targets} == {r'C:\Windows', CWD + r'\build'}


def test_do_loop_preserves_unchanged_caller_bindings():
    result = analyze(r"$x='C:\Windows'; do {Write-Output $x} until ($true); Remove-Item $x -Recurse -Force")
    assert rules(result) == {'delete-protected-root', 'unsupported-syntax'}


def test_do_loop_changed_directory_remains_uncertain_afterward():
    source = 'do {Set-Location build} until ($true); Remove-Item cache -Recurse -Force'
    operation = next(f for f in facts(source) if f.kind == 'delete')
    assert operation.cwd is None
    assert operation.targets == ()


@pytest.mark.parametrize('template', [
    'while ({condition}) {{Write-Output ok}}',
    'do {{Write-Output ok}} while ({condition})',
    'do {{Write-Output ok}} until ({condition})',
])
@pytest.mark.parametrize('condition', ['Stop-Computer', '$(Stop-Computer)', '[System.IO.File]::Delete("cache.txt")'])
def test_language_loop_condition_effects_are_inspected_once(template, condition):
    source = template.format(condition=condition)
    operations = [f for f in facts(source) if f.operation == 'machine-power-change' or f.kind == 'delete']
    assert len(operations) == 1
    assert 'unknown-command' not in rules(analyze(source))


def test_do_loop_inspects_body_before_condition():
    source = r"do {$x='C:\Windows'} until ($(Remove-Item $x -Recurse -Force)); Remove-Item $x -Recurse -Force"
    operations = [f for f in facts(source) if f.kind == 'delete']
    assert len(operations) == 2
    assert operations[0].targets == (r'C:\Windows',)
    assert operations[1].targets == ()


def test_do_loop_conditional_fatal_error_does_not_hide_later_top_level_effect():
    result = analyze("$ErrorActionPreference='Stop'; do {$HOME='build'} until ($true); Stop-Computer")
    assert {'readonly-assignment-failed', 'machine-power-change', 'unsupported-syntax'} <= rules(result)


def test_do_loop_in_pipeline_loop_preserves_outer_guard():
    source = '1 | % {do {Remove-Item cache} until ($true)}'
    operation = next(f for f in facts(source) if f.kind == 'delete')
    assert operation.guard == 'if the loop body runs; if the loop body runs'


@pytest.mark.parametrize('expression', [
    '1..3', '3..1', '1..-3', '-2..2', '1 .. 3', '(1..3)', '$a..$b',
    '1..2147483647', '@(1..3)', '@(1,2,3)',
])
def test_runtime_range_keeps_coverage_notice_but_literal_array_is_known(expression):
    result = analyze(expression + ' | ForEach-Object { $_ }')
    if expression == '@(1,2,3)':
        assert result.to_dict() == {}
        return
    assert rules(result) == {'unsupported-syntax'}
    assert result.findings[0].title == 'Loop iteration counts are not modeled'
    assert result.level == Level.LOW


@pytest.mark.parametrize('source', [
    '1..2147483647 | % {Remove-Item $_}',
    '$x=1..3; Remove-Item $x',
    '$x=@(1..3); Remove-Item $x',
    'Remove-Item (1..3)',
])
def test_ranges_never_become_literal_file_targets_or_enumerated_items(source):
    operations = [f for f in facts(source) if f.kind == 'delete']
    assert len(operations) == 1
    assert operations[0].targets == ()
    assert all(v.text is None for v in operations[0].values)
    assert 'unknown-command' not in rules(analyze(source))


@pytest.mark.parametrize('source', [
    '1..3 > out.txt',
    '$x=1..3; Set-Content out.txt $x',
    '1..3 | Set-Content out.txt',
])
def test_range_output_is_unavailable_but_its_write_is_still_analyzed(source):
    operation = next(f for f in facts(source) if f.kind == 'write')
    assert operation.targets == (CWD + r'\out.txt',)
    assert operation.payload is None
    assert rules(analyze(source)) == {'unresolved-value'}


@pytest.mark.parametrize('source', [
    "Write-Output '1..3' | Set-Content out.txt",
    'Write-Output 1..3 | Set-Content out.txt',
    "$x='1..3'; Set-Content out.txt $x",
])
def test_quoted_and_argument_mode_range_text_remains_literal(source):
    operation = next(f for f in facts(source) if f.kind == 'write')
    assert operation.payload == '1..3'
    assert analyze(source).to_dict() == {}


@pytest.mark.parametrize('source', [
    "& '1..3'", '& 1..3', '. 1..3', '1..3.exe', r'.\1..3',
    '1..3 extra', '1..3 -Foo',
])
def test_numeric_looking_command_invocations_still_report_unknown_meaning(source):
    assert ('executable-via-path' if source == r'.\1..3' else 'unknown-command') in rules(analyze(source))


def test_numeric_looking_unknown_command_keeps_argument_evaluation_effects():
    result = analyze('1..3 $(Stop-Computer)')
    assert rules(result) == {'unknown-command', 'machine-power-change'}
