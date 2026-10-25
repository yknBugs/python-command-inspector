"""Bounded cwd joins and the deliberately non-exhaustive switch join."""
import pytest
from command_inspector import Analyzer, AnalyzerConfig
from command_inspector.local_evidence import DisabledEvidenceProvider


def analyze(source, **config):
    return Analyzer(AnalyzerConfig(**config), evidence=DisabledEvidenceProvider()).analyze(source, r'C:\work', shell='powershell')


def deletions(result):
    return [f for f in result.get('findings', []) if f['rule'].startswith('delete-')]


def targets(result):
    return {f['data'].get('target') for f in deletions(result)}


@pytest.mark.parametrize('prefix', [
    'Set-Location C:/',
    r'if ($c) {Set-Location C:\}',
    r'switch ($c) {1 {Set-Location C:\}}',
    r'try {Set-Location C:\} catch {}',
    r'while ($c) {Set-Location C:\}',
    r'Get-ChildItem | ForEach-Object {Set-Location C:\}',
])
def test_known_directory_branch_preserves_protected_target(prefix):
    result = analyze(prefix + '; Remove-Item Windows -Recurse -Force')
    assert targets(result) == {r'C:\work\Windows', r'C:\Windows'}
    assert result['level'] == 'BLOCK'


def test_successful_cd_with_possible_variable_excludes_old_location():
    result = analyze(r"if ($c) {$d='C:\a'} else {$d='C:\b'}; Set-Location $d && Remove-Item leaf")
    assert targets(result) == {r'C:\a\leaf', r'C:\b\leaf'}


def test_after_conditional_chain_keeps_old_location():
    result = analyze(r'Set-Location C:\a && Write-Output ok; Remove-Item leaf')
    assert targets(result) == {r'C:\work\leaf', r'C:\a\leaf'}


def test_relative_location_changes_compose():
    assert targets(analyze('Set-Location a; Set-Location b; Remove-Item leaf')) == {
        r'C:\work\leaf', r'C:\work\a\leaf', r'C:\work\b\leaf', r'C:\work\a\b\leaf'}


def test_saved_stack_entries_join_possible_directories():
    result = analyze(r'Set-Location C:\a; Push-Location C:\b; Pop-Location && Remove-Item leaf')
    assert targets(result) == {r'C:\work\leaf', r'C:\a\leaf'}


def test_directory_and_variable_product_is_bounded():
    source = r"if ($c) {$p='a'} else {$p='b'}; Set-Location C:\; Remove-Item $p"
    assert len(targets(analyze(source, possible_values=4))) == 4
    assert [f['rule'] for f in deletions(analyze(source, possible_values=3))] == ['delete-variable-unresolved']


@pytest.mark.parametrize('branch', [
    r"if ($c) {$a='C:\a'} else {$a='C:\b'}",
    r"try {$a='C:\a'} catch {$a='C:\b'}",
])
def test_if_else_and_try_catch_assign_on_both_modeled_paths(branch):
    result = analyze(branch + '; Remove-Item -Recurse -Force $a')
    assert targets(result) == {r'C:\a', r'C:\b'}
    assert len(deletions(result)) == 2
    assert all(f['level'] == 'MEDIUM' for f in deletions(result))


@pytest.mark.parametrize('branch', [
    r"if ($c) {$a='C:\a'}",
    r"switch ($c) {1 {$a='C:\a'} 2 {$a='C:\b'}}",
])
def test_unassigned_no_match_path_absorbs_finite_values(branch):
    result = analyze(branch + '; Remove-Item -Recurse -Force $a')
    assert [f['rule'] for f in deletions(result)] == ['delete-variable-unresolved']


def test_switch_preserves_initial_value_on_no_match_path():
    result = analyze(r"$a='C:\old'; switch ($c) {1 {$a='C:\a'} 2 {$a='C:\b'}}; Remove-Item -Recurse -Force $a")
    assert targets(result) == {r'C:\old', r'C:\a', r'C:\b'}
    assert len(deletions(result)) == 3
