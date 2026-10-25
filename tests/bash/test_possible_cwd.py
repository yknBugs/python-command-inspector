"""Relative effects are expanded over bounded execution-directory alternatives."""
import pytest
from command_inspector import Analyzer, AnalyzerConfig
from command_inspector.local_evidence import DisabledEvidenceProvider


def analyze(command, cwd='/work', **config):
    return Analyzer(AnalyzerConfig(**config), evidence=DisabledEvidenceProvider()).analyze(command, cwd, shell='bash')


def targets(result, prefix='delete-'):
    return {f['data']['target'] for f in result.get('findings', []) if f['rule'].startswith(prefix) and 'target' in f['data']}


def rules(result):
    return {f['rule'] for f in result.get('findings', [])}


@pytest.mark.parametrize('separator', [';', '\n'])
def test_cd_failure_and_success_both_retain_concrete_targets(separator):
    result = analyze(f'cd /{separator} rm -rf etc')
    assert targets(result) == {'/work/etc', '/etc'}
    assert result['level'] == 'BLOCK'
    assert 'delete-variable-unresolved' not in rules(result)
    assert all(f['data']['possible'] for f in result['findings'] if f['rule'].startswith('delete-'))


def test_reported_project_example():
    result = analyze('cd /home/user/Projects; rm -rf PythonCodeAnalyzer; rm -rf Temp; echo "Done."', '/home/user/Projects/data')
    assert targets(result) == {f'/home/user/Projects/{part}{name}' for part in ('', 'data/') for name in ('PythonCodeAnalyzer', 'Temp')}
    assert 'delete-variable-unresolved' not in rules(result)
    assert result['level'] == 'MEDIUM'


@pytest.mark.parametrize('source', ['if test -f marker; then cd /; fi', 'case "$X" in a) cd /;; esac', 'cd / || echo failed'])
def test_branch_joins_preserve_directory_alternatives(source):
    result = analyze(source + '; rm -rf etc')
    assert targets(result) == {'/work/etc', '/etc'}
    assert result['level'] == 'BLOCK'


def test_success_chain_only_uses_successful_location_for_its_rhs():
    assert targets(analyze('cd / && rm -rf etc')) == {'/etc'}


def test_after_success_chain_includes_failure_location():
    assert targets(analyze('cd / && echo changed; rm -rf etc')) == {'/work/etc', '/etc'}


def test_relative_directory_changes_compose():
    assert targets(analyze('cd a; cd b; rm x')) == {'/work/x','/work/a/x','/work/b/x','/work/a/b/x'}


def test_variable_choices_and_directory_choices_share_product_budget():
    source = 'if test -f marker; then X=a; else X=b; fi; cd /; rm -rf "$X"'
    assert targets(analyze(source, possible_values=4)) == {'/work/a','/work/b','/a','/b'}
    result = analyze(source, possible_values=3)
    assert 'delete-variable-unresolved' in rules(result)


def test_directory_budget_never_truncates_candidates():
    result = analyze('cd a; cd b; rm x', possible_values=3)
    assert 'delete-variable-unresolved' in rules(result)
    assert not targets(result)
    assert '\\u0000' not in str(result)


@pytest.mark.parametrize('prefix', ['(cd /)', 'cd / &', 'echo "$(cd /)"'])
def test_child_shell_directory_changes_do_not_escape(prefix):
    assert targets(analyze(prefix + '\nrm -rf etc')) == {'/work/etc'}


def test_unknown_destination_stays_unresolved():
    assert 'delete-variable-unresolved' in rules(analyze('cd "$missing"; rm x'))


def test_redirection_uses_all_possible_directories():
    result = analyze('cd /outside; echo text > out.txt')
    assert '/outside/out.txt' in targets(result, 'write-')
    assert 'write-variable-unresolved' not in rules(result)


def test_loop_state_is_bounded():
    result = analyze('while test -f marker; do cd child; done; rm x', possible_values=3, control_flow_steps=8)
    assert 'delete-variable-unresolved' in rules(result)


def test_calls_do_not_share_directory_state():
    analyzer = Analyzer(evidence=DisabledEvidenceProvider())
    analyzer.analyze('cd /', '/work', shell='bash')
    assert targets(analyzer.analyze('rm -rf etc', '/work', shell='bash')) == {'/work/etc'}
