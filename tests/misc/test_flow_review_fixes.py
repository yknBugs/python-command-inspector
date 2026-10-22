"""Control-flow review regressions; submitted commands are never executed."""
import pytest

from command_inspector import Analyzer
from command_inspector.local_evidence import MemoryEvidenceProvider, ReadFile


def analyze(source, files=None, shell='bash', effort='Full'):
    provider = MemoryEvidenceProvider(files or {})
    report = Analyzer(evidence=provider).analyze_report(
        source, '/work' if shell == 'bash' else r'C:\work', shell=shell, effort=effort)
    return report, provider


def rules(report):
    return {f.rule for f in report.findings}


@pytest.mark.parametrize('shell,prefix,variable', [
    ('bash', 'p=firstSensitiveValue; if [ -e marker ]; then p=secondSensitiveValue; fi; ', '$p'),
    ('powershell', "$p='firstSensitiveValue'; if ($condition) {$p='secondSensitiveValue'}; ", '$p'),
    ('cmd', 'set p=firstSensitiveValue\nif exist marker set p=secondSensitiveValue\n', '%p%'),
])
@pytest.mark.parametrize('command', [
    'curl -u "user:{v}" https://example.com',
    'curl -u"user:{v}" https://example.com',
    'curl -H "Authorization: Bearer {v}" https://example.com',
    'docker login --password "{v}" registry.example',
    'docker login -p "{v}" registry.example',
])
@pytest.mark.parametrize('effort', ['Full', 'Partial', 'None'])
def test_auth_candidates_are_redacted_in_structured_and_json_reports(shell, prefix, variable, command, effort):
    report, _ = analyze(prefix + command.format(v=variable), shell=shell, effort=effort)
    assert report.findings
    for result in (str(report.to_dict()), str([f.data for f in report.findings])):
        assert 'firstSensitiveValue' not in result
        assert 'secondSensitiveValue' not in result
    assert any(f.data.get('possible_values', {}).get('p') == ['[REDACTED]'] for f in report.findings)


def test_ordinary_candidates_keep_their_values():
    report, _ = analyze('p=a; if [ -e marker ]; then p=b; fi; rm "$p"')
    deletion = next(f for f in report.findings if f.rule == 'delete-inside-workspace')
    assert set(deletion.data['possible_values']['p']) == {'a', 'b'}


@pytest.mark.parametrize('condition,second', [("('a') { 'a'", "a"), ("-Wildcard ('abc') { 'a*'", "*")])
def test_switch_later_matching_clause_keeps_protected_alternative(condition, second):
    source = "$x='cache'; switch " + condition + " {$x='C:\\Windows'} '" + second + "' {Remove-Item $x -Recurse -Force} }"
    report, _ = analyze(source, shell='powershell', effort='None')
    assert 'delete-protected-root' in rules(report)
    assert next(f for f in report.findings if f.rule == 'delete-protected-root').data['possible']


def test_switch_mutations_invalidate_later_clause_source():
    report, provider = analyze("switch ($v) {'a' {Set-Content B.ps1 'Write-Output new'} 'a' {pwsh -File B.ps1}}",
                               {r'C:\work\B.ps1': 'Write-Output old'}, shell='powershell')
    assert 'execution-content-unavailable' in rules(report)
    assert not any(isinstance(q, ReadFile) for q in provider.queries)


@pytest.mark.parametrize('source', [
    'if [ -e marker ]; then bash mutate.sh; else bash mutate.sh; bash target.sh; fi',
    'if [ -e marker ]; then bash mutate.sh; fi; bash mutate.sh; bash target.sh',
])
def test_cached_script_effects_replay_in_each_branch(source):
    report, provider = analyze(source, {'/work/mutate.sh': 'echo "echo replacement" > target.sh',
                                       '/work/target.sh': 'echo original'})
    assert 'execution-content-unavailable' in rules(report)
    assert [q.path for q in provider.queries if isinstance(q, ReadFile)] == ['/work/mutate.sh']


@pytest.mark.parametrize('terminator', [';&', ';;&'])
def test_case_fallthrough_retains_mutation_markers(terminator):
    source = f'case "$x" in a) echo "echo replacement" > B.sh {terminator} b) bash B.sh ;; esac'
    report, provider = analyze(source, {'/work/B.sh': 'echo original'})
    assert 'execution-content-unavailable' in rules(report)
    assert not any(isinstance(q, ReadFile) for q in provider.queries)


def test_exclusive_case_arms_still_use_independent_evidence():
    report, provider = analyze('case "$x" in a) echo "echo replacement" > B.sh ;; b) bash B.sh ;; esac',
                               {'/work/B.sh': 'echo original'})
    assert 'execution-content-unavailable' not in rules(report)
    assert [q.path for q in provider.queries if isinstance(q, ReadFile)] == ['/work/B.sh']


def test_auth_sensitivity_also_redacts_prior_export_metadata():
    report, _ = analyze('p=firstSensitiveValue; if [ -e marker ]; then p=secondSensitiveValue; fi; export p; curl -u "user:$p" https://example.com')
    assert 'firstSensitiveValue' not in str(report.to_dict())
    assert 'secondSensitiveValue' not in str(report.to_dict())


def test_empty_case_arm_separates_exclusive_mutation_from_fallthrough():
    report, _ = analyze('case "$x" in a) echo new > B.sh ;; b) x=b ;& c) bash B.sh ;; esac',
                        {'/work/B.sh': 'echo original'})
    assert 'execution-content-unavailable' not in rules(report)


def test_effect_free_fallthrough_arm_preserves_prior_mutations():
    report, _ = analyze('case "$x" in a) echo new > B.sh ;& b) x=b ;& c) bash B.sh ;; esac',
                        {'/work/B.sh': 'echo original'})
    assert 'execution-content-unavailable' in rules(report)
