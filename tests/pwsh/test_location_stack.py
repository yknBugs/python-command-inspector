"""Location stacks are local abstract state, never real shell navigation."""
import pytest
from command_inspector import Analyzer
from command_inspector.local_evidence import DisabledEvidenceProvider


def analyze(source):
    return Analyzer(evidence=DisabledEvidenceProvider()).analyze(source, r'D:\work', shell='powershell')


def rules(source):
    return {f['rule'] for f in analyze(source).get('findings', [])}


@pytest.mark.parametrize('source', ['Pop-Location', 'popd', 'Pop-Location -PassThru', 'Push-Location; Pop-Location'])
def test_empty_or_unchanged_stack_is_quiet(source):
    assert analyze(source) == {}


@pytest.mark.parametrize('source', [
    r'Push-Location C:\outside; Pop-Location && Remove-Item x',
    r'pushd C:\outside; popd && Remove-Item x',
    r'Push-Location C:\outside -StackName saved; Pop-Location -StackName SAVED && Remove-Item x',
    r'Push-Location C:\outside && Push-Location C:\elsewhere && Pop-Location && Pop-Location && Remove-Item x',
])
def test_successful_restore_uses_saved_location(source):
    findings = analyze(source)['findings']
    deletion = next(f for f in findings if f['rule'] == 'delete-inside-workspace')
    assert deletion['data']['target'] == r'D:\work\x'
    assert not {'unknown-command', 'unknown-option', 'delete-variable-unresolved'} & {f['rule'] for f in findings}


def test_pop_without_success_guard_does_not_assume_restore_succeeded():
    assert 'delete-variable-unresolved' in rules(r'Push-Location C:\outside; Pop-Location; Remove-Item x')


def test_named_stacks_are_independent():
    source = r'Push-Location C:\outside -StackName first && Push-Location D:\work -StackName second && Pop-Location -StackName second && Remove-Item x'
    deletion = next(f for f in analyze(source)['findings'] if f['rule'] == 'delete-outside-workspace')
    assert deletion['data']['target'] == r'C:\outside\x'


@pytest.mark.parametrize('prefix', [
    r'if ($x) { Push-Location C:\outside }',
    r'foreach ($x in $items) { Push-Location C:\outside }',
    r'Push-Location C:\outside -StackName $unknown',
    r'Push-Location C:\outside -StackName "s*"',
])
def test_uncertain_stack_cannot_resolve_later_relative_target(prefix):
    assert 'delete-variable-unresolved' in rules(prefix + '; Pop-Location && Remove-Item x')


def test_stack_is_not_inherited_between_calls():
    analyzer = Analyzer(evidence=DisabledEvidenceProvider())
    analyzer.analyze(r'Push-Location C:\outside', r'D:\work', shell='powershell')
    result = analyzer.analyze('Pop-Location; Remove-Item x', r'E:\next', shell='powershell')
    deletion = next(f for f in result['findings'] if f['rule'] == 'delete-inside-workspace')
    assert deletion['data']['target'] == r'E:\next\x'
