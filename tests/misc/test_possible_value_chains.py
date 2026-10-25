"""Chained branch assignments must retain intermediate and directory choices."""
import pytest
from command_inspector import Analyzer, AnalyzerConfig
from command_inspector.bash.semantics import SemanticBuilder
from command_inspector.pwsh.semantics import PowerShellBuilder
from command_inspector.shared.value_flow import candidates


def inputs(shell):
    if shell == 'bash':
        return '/work', [f'/x{i}' for i in range(1, 6)], [
            'a=/x1; if test -f one; then a=/x2; fi',
            'b=/x3; if test -f two; then b=/x4; fi',
            'c=$a; if test -f three; then c=$b; fi',
        ], 'cd "$c"; if test -f four; then cd /x5; fi; rm leaf'
    return r'C:\work', [f'C:\\x{i}' for i in range(1, 6)], [
        "$a='C:\\x1'; if ($one) {$a='C:\\x2'}",
        "$b='C:\\x3'; if ($two) {$b='C:\\x4'}",
        '$c=$a; if ($three) {$c=$b}',
    ], r'Set-Location $c; if ($four) {Set-Location C:\x5}; Remove-Item leaf'


def builder_for(shell, limit):
    cwd, _, _, _ = inputs(shell)
    return (SemanticBuilder if shell == 'bash' else PowerShellBuilder)(cwd, {}, possible_values=limit)


def bindings(builder, shell):
    return builder.state.env if shell == 'bash' else builder.variables


def texts(value):
    return {candidate.text for candidate in candidates(value)}


@pytest.mark.parametrize('shell', ['bash', 'powershell'])
def test_assignment_chain_retains_two_two_four_values(shell):
    _, paths, stages, _ = inputs(shell)
    builder = builder_for(shell, 6)
    for stage, name, expected in zip(stages, ('a', 'b', 'c'), (paths[:2], paths[2:4], paths[:4])):
        builder.build(Analyzer().parse(stage, shell=shell).root)
        assert texts(bindings(builder, shell)[name]) == set(expected)
    # Copying/joining c must not mutate the earlier source bindings.
    assert texts(bindings(builder, shell)['a']) == set(paths[:2])
    assert texts(bindings(builder, shell)['b']) == set(paths[2:4])


@pytest.mark.parametrize('shell', ['bash', 'powershell'])
def test_four_value_assignment_widens_instead_of_truncating_at_three(shell):
    _, paths, stages, _ = inputs(shell)
    builder = builder_for(shell, 3)
    builder.build(Analyzer().parse('; '.join(stages), shell=shell).root)
    values = bindings(builder, shell)
    assert texts(values['a']) == set(paths[:2])
    assert texts(values['b']) == set(paths[2:4])
    assert values['c'].text is None and not values['c'].alternatives
    assert values['c'].reason == 'possible_values_limit'


@pytest.mark.parametrize('shell', ['bash', 'powershell'])
def test_directory_chain_retains_exactly_six_possible_targets(shell):
    cwd, paths, stages, tail = inputs(shell)
    report = Analyzer(AnalyzerConfig(possible_values=6)).analyze(
        '; '.join([*stages, tail]), cwd, shell=shell, effort='None')
    findings = report.get('findings', [])
    deletions = [f for f in findings if f['rule'].startswith('delete-')]
    separator = '/' if shell == 'bash' else '\\'
    expected = {directory + separator + 'leaf' for directory in [cwd, *paths]}
    assert {f['data'].get('target') for f in deletions} == expected
    assert len(deletions) == 6
    assert all(f['data'].get('possible') for f in deletions)
    assert 'delete-variable-unresolved' not in {f['rule'] for f in findings}


@pytest.mark.parametrize('shell', ['bash', 'powershell'])
def test_six_directory_chain_widens_at_five_without_dropping_a_target(shell):
    cwd, _, stages, tail = inputs(shell)
    report = Analyzer(AnalyzerConfig(possible_values=5)).analyze(
        '; '.join([*stages, tail]), cwd, shell=shell, effort='None')
    deletions = [f for f in report['findings'] if f['rule'].startswith('delete-')]
    assert len(deletions) == 1
    assert deletions[0]['rule'] == 'delete-variable-unresolved'
