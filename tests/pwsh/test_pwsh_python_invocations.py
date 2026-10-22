"""Reported PowerShell/Python invocations are analyzed, never executed."""
import os
import subprocess

import pytest

from command_inspector import Analyzer
from command_inspector.local_evidence import DisabledEvidenceProvider, MemoryEvidenceProvider, ReadFile


COMMAND = r'''cd D:\Temp\Analyzer
& "D:\Temp\python\python.exe" -c "
import ast, pathlib
for n in ('writers.py','policy.py'):
    try:
        ast.parse(pathlib.Path(n).read_text(encoding='utf-8')); print(f'{n} ok')
    except SyntaxError as e: print(f'{n} SYNTAX', e.lineno, e.msg)
" 2>&1 | Out-String -Width 175
& "D:\Temp\python\python.exe" tools\dump_all_copy.py 2>&1 | Select-Object -Last 1 | Out-String -Width 175
& "D:\Temp\python\python.exe" -m pytest -q -p no:cacheprovider --tb=line 2>&1 | Select-Object -Last 8 | Out-String -Width 185
'''

WORKSPACE = r'D:\Temp\Analyzer'
PYTHON = r'D:\Temp\python\python.exe'
FILES = {
    PYTHON: b'\x00executable fixture',
    WORKSPACE + r'\writers.py': 'value = 1\n',
    WORKSPACE + r'\policy.py': 'value = 2\n',
    WORKSPACE + r'\tools\dump_all_copy.py': 'print("ok")\n',
}


@pytest.fixture(autouse=True)
def no_command_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('Analyzing PowerShell/Python started a process')
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    monkeypatch.setattr(os, 'system', forbidden)


@pytest.mark.parametrize('effort', ['Full', 'Partial', 'None'])
@pytest.mark.parametrize('cwd', [WORKSPACE, r'C:\work'])
def test_reported_multiline_python_commands_and_output_pipelines(cwd, effort):
    provider = MemoryEvidenceProvider(FILES)
    analyzer = Analyzer(evidence=provider)
    assert not analyzer.parse(COMMAND, shell='powershell').diagnostics
    report = analyzer.analyze_report(COMMAND, cwd, shell='powershell', effort=effort)
    rules = {finding.rule for finding in report.findings}
    expected = {'command-via-path', 'uses-interpreter'}
    if cwd != WORKSPACE:
        expected |= {'read-outside-workspace', 'unresolved-value', 'execution-content-unavailable'}
    elif effort != 'Full':
        expected |= {'ingestion-inspection-incomplete', 'execution-content-unavailable'}
    assert rules == expected
    assert report.level.name == ('LOW' if cwd == WORKSPACE and effort == 'Full' else 'MEDIUM')
    reads = [query.path for query in provider.queries if isinstance(query, ReadFile)]
    assert reads == ([WORKSPACE + r'\writers.py', WORKSPACE + r'\policy.py',
                      WORKSPACE + r'\tools\dump_all_copy.py'] if cwd == WORKSPACE and effort == 'Full' else [])
    if effort == 'None':
        assert not provider.queries


def test_reported_command_keeps_missing_execution_content_explicit_without_evidence():
    report = Analyzer(evidence=DisabledEvidenceProvider()).analyze_report(COMMAND, WORKSPACE, shell='powershell')
    assert {finding.rule for finding in report.findings} == {
        'command-via-path', 'uses-interpreter', 'ingestion-inspection-incomplete', 'execution-content-unavailable'}
    assert report.level.name == 'MEDIUM'


@pytest.mark.parametrize('effort', ['Full', 'Partial', 'None'])
def test_python_absolute_candidates_keep_windows_scope_when_cwd_is_unknown(effort):
    command = r'''cd D:\elsewhere
& "D:\Temp\python\python.exe" -c "import shutil; names=('C:/Windows', 'cache'); [shutil.rmtree(n) for n in names]"
'''
    report = Analyzer(evidence=DisabledEvidenceProvider()).analyze_report(
        command, WORKSPACE, shell='powershell', effort=effort)
    rules = {finding.rule for finding in report.findings}
    assert 'delete-protected-root' in rules
    assert 'delete-variable-unresolved' in rules
    assert 'delete-inside-workspace' not in rules
    assert report.level.name == 'BLOCK'


def test_invoked_python_file_is_still_inspected_after_same_directory_cd():
    files = FILES | {WORKSPACE + r'\tools\dump_all_copy.py': 'import shutil; shutil.rmtree("C:/Windows")\n'}
    report = Analyzer(evidence=MemoryEvidenceProvider(files)).analyze_report(COMMAND, WORKSPACE, shell='powershell')
    assert 'delete-protected-root' in {finding.rule for finding in report.findings}
    assert report.level.name == 'BLOCK'


@pytest.mark.parametrize('argument', ['--tb=line', '--color=always'])
def test_native_literal_equals_argument_preserves_source_text(argument):
    command = '& "D:\\Temp\\python\\python.exe" -m pytest ' + argument
    analyzer = Analyzer(evidence=DisabledEvidenceProvider())
    parsed = analyzer.parse(command, shell='powershell')
    assert not parsed.diagnostics
    pending = [parsed.root]
    parameters = []
    while pending:
        node = pending.pop()
        if node.kind == 'command_parameter':
            parameters.append(node.text)
        pending.extend(node.children)
    assert argument in parameters


def test_native_equals_repair_does_not_hide_unrelated_malformed_assignment():
    command = '$x = ; & "D:\\Temp\\python\\python.exe" -m pytest --tb=line'
    assert Analyzer().parse(command, shell='powershell').diagnostics
