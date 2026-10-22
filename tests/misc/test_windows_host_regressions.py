"""Regressions reported by native Windows testing; no input commands are run."""
import pytest

from command_inspector import Analyzer, AnalyzerConfig, ConfigurationError
from command_inspector.local_evidence import MemoryEvidenceProvider, ReadFile
from command_inspector.paths import PathStyle

CWD = r'D:\work'


def analyze(command, shell='powershell', files=None):
    provider = MemoryEvidenceProvider(files or {})
    result = Analyzer(evidence=provider).analyze_report(command, CWD, shell=shell)
    return result, provider


def rules(report):
    return {f.rule for f in report.findings}


def test_config_paths_do_not_depend_on_host_isabs():
    # Windows Python versions disagree about slash-rooted paths. Configuration
    # accepts either explicit lexical dialect independent of the host version.
    assert AnalyzerConfig().protected_directories[0] == '/'
    assert AnalyzerConfig.from_mapping({}).protected_directories[0] == '/'
    AnalyzerConfig(additional_paths=('/work', r'D:\work', r'\\server\share'))
    for path in ('relative', 'D:relative', r'\relative'):
        with pytest.raises(ConfigurationError):
            AnalyzerConfig(additional_paths=(path,))


@pytest.mark.parametrize('cwd', ['/work', CWD, r'\\server\share\work'])
def test_explicit_shell_and_missing_parser_are_distinct_from_no_default(cwd):
    analyzer = Analyzer(AnalyzerConfig(shell=None), evidence=MemoryEvidenceProvider())
    assert analyzer.config.shell is None
    # CMD is built in, so explicit selection does not require an optional grammar.
    assert analyzer.analyze('echo hello', CWD, shell='cmd') == {}
    result = analyzer.analyze('true', cwd)
    assert result['findings'][0]['data']['reason'] == 'unsupported_shell'
    result = analyzer.analyze('true', cwd, shell=None)
    assert result['findings'][0]['data']['reason'] == 'unsupported_shell'
    analyzer.frontend = None
    result = analyzer.analyze('true', '/work', shell='bash')
    assert result['findings'][0]['data']['reason'] == 'missing_parser'


def test_default_text_shell_is_bash_and_explicit_none_is_preserved():
    assert AnalyzerConfig().shell == 'bash'
    assert AnalyzerConfig.from_mapping({}).shell == 'bash'
    assert AnalyzerConfig(shell=None).shell is None
    assert AnalyzerConfig.from_mapping({'shell': None}).shell is None


@pytest.mark.parametrize('name', ['x', 'X', '{x}'])
def test_foreach_discards_previous_array_binding(name):
    result, _ = analyze("$x=@('D:\\Windows','build'); foreach($" + name + " in @('build')) { Remove-Item $x -Recurse -Force }")
    assert rules(result) == {'delete-inside-workspace', 'delete-target-missing'}
    assert result.level.name == 'LOW'
    assert next(f for f in result.findings if f.rule == 'delete-inside-workspace').data['target'] == CWD + r'\build'


@pytest.mark.parametrize('shell,operation,invocation,source', [
    ('powershell', 'Move-Item source.ps1 moved.ps1', 'pwsh -File source.ps1', 'source.ps1'),
    ('powershell', 'Rename-Item source.ps1 moved.ps1', 'pwsh -File source.ps1', 'source.ps1'),
    ('powershell', 'Move-Item folder moved', 'pwsh -File folder/source.ps1', 'folder/source.ps1'),
    ('cmd', 'move source.cmd moved.cmd', 'source.cmd', 'source.cmd'),
    ('cmd', 'ren source.cmd moved.cmd', 'source.cmd', 'source.cmd'),
    ('cmd', 'rename folder moved', 'folder\\source.cmd', 'folder/source.cmd'),
])
def test_move_invalidates_source_evidence(shell, operation, invocation, source):
    path = PathStyle(True).norm(CWD + '/' + source)
    result, provider = analyze(operation + ('; ' if shell == 'powershell' else ' & ') + invocation, shell, {path: 'echo harmless'})
    assert 'execution-content-unavailable' in rules(result)
    assert not any(isinstance(q, ReadFile) for q in provider.queries)


@pytest.mark.parametrize('command', [
    'Copy-Item source.ps1 moved.ps1; pwsh -File source.ps1',
    'Move-Item source.ps1 moved.ps1 -WhatIf; pwsh -File source.ps1',
    'Move-Item other.ps1 moved.ps1; pwsh -File source.ps1',
    'function unused { Move-Item source.ps1 moved.ps1 }; pwsh -File source.ps1',
])
def test_unchanged_source_remains_inspectable(command):
    result, provider = analyze(command, files={CWD + r'\source.ps1': 'Write-Output ok'})
    assert 'execution-content-unavailable' not in rules(result)
    assert any(isinstance(q, ReadFile) for q in provider.queries)


@pytest.mark.parametrize('shell,command', [
    ('cmd', 'format'), ('cmd', 'format /q'), ('cmd', 'format %VOLUME% /q'),
    ('powershell', 'format $volume /q'), ('powershell', 'format "" /q'),
    ('cmd', 'format * /q'),
])
def test_format_without_concrete_volume_is_not_block(shell, command):
    result, _ = analyze(command, shell)
    assert rules(result) == {'unresolved-value'}
    assert result.level.name == 'LOW'


@pytest.mark.parametrize('command', [
    "Copy-Item '*.ps1' out", "Copy-Item -Path '*.ps1' -Destination out",
    "$files=@('*.ps1','a.ps1'); Copy-Item $files out",
    "Move-Item '*.ps1' out", "Rename-Item '*.ps1' renamed.ps1",
])
def test_copy_move_patterns_are_not_resolved_as_literal_paths(command):
    result, _ = analyze(command)
    assert 'unresolved-value' in rules(result)


def test_literalpath_copy_does_not_expand_wildcards():
    result, _ = analyze("Copy-Item -LiteralPath '*.ps1' -Destination out")
    assert not result.findings


@pytest.mark.parametrize('command,shell', [
    ('Move-Item source.ps1 moved.ps1; Get-Content source.ps1', 'powershell'),
    ('move source.cmd moved.cmd & type source.cmd', 'cmd'),
])
def test_move_does_not_ingest_stale_source(command, shell):
    result, provider = analyze(command, shell, {CWD + r'\source.ps1': 'password=abcdefghijk', CWD + r'\source.cmd': 'password=abcdefghijk'})
    assert 'ingestion-inspection-incomplete' in rules(result)
    assert 'credentials-read' not in rules(result)
    assert not any(isinstance(q, ReadFile) for q in provider.queries)


def test_unresolved_move_cannot_reuse_precommand_evidence():
    result, provider = analyze("Move-Item '*.ps1' out; pwsh -File source.ps1", files={CWD + r'\source.ps1': 'Write-Output ok'})
    assert 'unresolved-value' in rules(result)
    assert 'execution-content-unavailable' in rules(result)
    assert not any(isinstance(q, ReadFile) for q in provider.queries)


def test_move_destination_directory_also_invalidates_descendants():
    result, provider = analyze('Move-Item folder moved; pwsh -File moved/source.ps1', files={CWD + r'\moved\source.ps1': 'Write-Output ok'})
    assert 'execution-content-unavailable' in rules(result)
    assert not any(isinstance(q, ReadFile) for q in provider.queries)


@pytest.mark.parametrize('shell,operation,invocation,source', [
    ('powershell', 'Move-Item other.ps1 $destination', 'pwsh -File source.ps1', 'source.ps1'),
    ('powershell', 'Rename-Item other.ps1 $destination', 'pwsh -File source.ps1', 'source.ps1'),
    ('cmd', 'move other.cmd %DESTINATION%', 'source.cmd', 'source.cmd'),
    ('cmd', 'ren other.cmd %DESTINATION%', 'source.cmd', 'source.cmd'),
    ('cmd', 'rename other.cmd %DESTINATION%', 'source.cmd', 'source.cmd'),
])
def test_unresolved_move_destination_invalidates_execution(shell, operation, invocation, source):
    result, provider = analyze(operation + ('; ' if shell == 'powershell' else ' & ') + invocation,
                               shell, {CWD + '\\' + source: 'echo harmless'})
    expected = ['unresolved-value', 'uses-interpreter', 'execution-content-unavailable']
    if operation.startswith(('Move-Item', 'Rename-Item', 'move ')):
        expected.append('write-variable-unresolved')
    if shell == 'powershell':
        expected.append('unresolved-value')
    assert sorted(f.rule for f in result.findings) == sorted(expected)
    assert result.level.name == 'MEDIUM'
    unavailable = next(f for f in result.findings if f.rule == 'execution-content-unavailable')
    assert unavailable.data['reason'] == 'changed_earlier'
    assert not any(isinstance(q, ReadFile) for q in provider.queries)


@pytest.mark.parametrize('shell,command,source', [
    ('powershell', 'Move-Item other.ps1 $destination; Get-Content source.ps1', 'source.ps1'),
    ('cmd', 'move other.cmd %DESTINATION% & type source.cmd', 'source.cmd'),
])
def test_unresolved_move_destination_does_not_ingest_stale_content(shell, command, source):
    result, provider = analyze(command, shell, {CWD + '\\' + source: 'password=abcdefghijk'})
    expected = ['unresolved-value', 'ingestion-inspection-incomplete', 'write-variable-unresolved']
    if shell == 'powershell':
        expected.append('unresolved-value')
    assert sorted(f.rule for f in result.findings) == sorted(expected)
    assert result.level.name == 'MEDIUM'
    assert not any(isinstance(q, ReadFile) for q in provider.queries)


@pytest.mark.parametrize('command', [
    'Move-Item other.ps1 $destination -WhatIf; pwsh -File source.ps1',
    'function unused { Move-Item other.ps1 $destination }; pwsh -File source.ps1',
])
def test_unresolved_destination_without_invoked_move_retains_evidence(command):
    result, provider = analyze(command, files={CWD + r'\source.ps1': 'Write-Output ok'})
    assert 'execution-content-unavailable' not in rules(result)
    assert [q.path for q in provider.queries if isinstance(q, ReadFile)] == [CWD + r'\source.ps1']


@pytest.mark.parametrize('shell,command', [
    ('powershell', r"Move-Item '*.ps1' out; Get-Content -LiteralPath '\\.\PhysicalDrive0'"),
    ('powershell', r"Move-Item other.ps1 $destination; Get-Content -LiteralPath '\\.\PhysicalDrive0'"),
    ('cmd', r'move *.cmd out & type \\.\PhysicalDrive0'),
    ('cmd', r'move other.cmd %DESTINATION% & type \\.\PhysicalDrive0'),
])
def test_unknown_move_changes_do_not_hide_raw_disk_read(shell, command):
    result, provider = analyze(command, shell)
    expected = ['unresolved-value', 'read-outside-workspace', 'raw-device-read']
    if '$destination' in command or '%DESTINATION%' in command:
        expected.append('write-variable-unresolved')
    if shell == 'powershell' and '$destination' in command:
        expected.append('unresolved-value')
    assert sorted(f.rule for f in result.findings) == sorted(expected)
    assert result.level.name == 'HIGH'
    disk = next(f for f in result.findings if f.rule == 'raw-device-read')
    assert disk.data['target'] == r'\\.\PhysicalDrive0'
    assert not any(isinstance(q, ReadFile) for q in provider.queries)
