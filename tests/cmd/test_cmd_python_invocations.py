"""Valid CMD equivalents; submitted commands and Python are never executed."""
import os
import subprocess

import pytest

from command_inspector import Analyzer
from command_inspector.local_evidence import DisabledEvidenceProvider, MemoryEvidenceProvider, ReadFile


WORKSPACE = r'D:\Temp\Analyzer'
PYTHON = r'D:\Temp\python\python.exe'
# CMD needs a single-line Python argument. PowerShell supplies the same output
# consumers as the reported example; these are nested interpreter invocations.
COMMAND = r'''cd /d D:\Temp\Analyzer
"D:\Temp\python\python.exe" -c "import ast,pathlib; [ast.parse(pathlib.Path(n).read_text(encoding='utf-8')) or print(f'{n} ok') for n in ('writers.py','policy.py')]" 2>&1 | powershell -NoProfile -Command "Out-String -Width 175"
"D:\Temp\python\python.exe" tools\dump_all_copy.py 2>&1 | powershell -NoProfile -Command "Select-Object -Last 1 | Out-String -Width 175"
"D:\Temp\python\python.exe" -m pytest -q -p no:cacheprovider --tb=line 2>&1 | powershell -NoProfile -Command "Select-Object -Last 8 | Out-String -Width 185"
'''
FILES = {
    PYTHON: b'\x00executable fixture',
    WORKSPACE + r'\writers.py': 'value = 1\n',
    WORKSPACE + r'\policy.py': 'value = 2\n',
    WORKSPACE + r'\tools\dump_all_copy.py': 'print("ok")\n',
}


@pytest.fixture(autouse=True)
def no_command_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('Analyzing CMD/Python started a process')
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    monkeypatch.setattr(os, 'system', forbidden)


@pytest.mark.parametrize('effort', ['Full', 'Partial', 'None'])
@pytest.mark.parametrize('cwd', [WORKSPACE, r'C:\work'])
def test_python_commands_and_nested_output_pipelines(cwd, effort):
    provider = MemoryEvidenceProvider(FILES)
    analyzer = Analyzer(evidence=provider)
    assert not analyzer.parse(COMMAND, shell='cmd').diagnostics
    report = analyzer.analyze_report(COMMAND, cwd, shell='cmd', effort=effort)
    expected = {'command-via-path', 'uses-interpreter', 'unresolved-value'}
    if cwd != WORKSPACE:
        expected |= {'read-outside-workspace', 'execution-content-unavailable'}
    elif effort != 'Full':
        expected |= {'ingestion-inspection-incomplete', 'execution-content-unavailable'}
    assert {finding.rule for finding in report.findings} == expected
    assert report.level.name == ('LOW' if cwd == WORKSPACE and effort == 'Full' else 'MEDIUM')
    assert any(finding.detail == 'CMD pipeline selection is conservative' for finding in report.findings)
    reads = [query.path for query in provider.queries if isinstance(query, ReadFile)]
    assert reads == ([WORKSPACE + r'\writers.py', WORKSPACE + r'\policy.py',
                      WORKSPACE + r'\tools\dump_all_copy.py'] if cwd == WORKSPACE and effort == 'Full' else [])
    if effort == 'None':
        assert not provider.queries


@pytest.mark.parametrize('effort', ['Full', 'Partial', 'None'])
def test_python_absolute_candidates_keep_windows_scope_when_cwd_is_unknown(effort):
    command = r'''cd /d D:\elsewhere
"D:\Temp\python\python.exe" -c "import shutil; names=('C:/Windows', 'cache'); [shutil.rmtree(n) for n in names]"
'''
    report = Analyzer(evidence=DisabledEvidenceProvider()).analyze_report(
        command, WORKSPACE, shell='cmd', effort=effort)
    rules = {finding.rule for finding in report.findings}
    assert 'delete-protected-root' in rules
    assert 'delete-variable-unresolved' in rules
    assert 'delete-inside-workspace' not in rules
    assert report.level.name == 'BLOCK'


def test_invoked_python_file_is_still_inspected_after_same_directory_cd():
    files = FILES | {WORKSPACE + r'\tools\dump_all_copy.py': 'import shutil; shutil.rmtree("C:/Windows")\n'}
    report = Analyzer(evidence=MemoryEvidenceProvider(files)).analyze_report(COMMAND, WORKSPACE, shell='cmd')
    assert 'delete-protected-root' in {finding.rule for finding in report.findings}
    assert report.level.name == 'BLOCK'


@pytest.mark.parametrize('cd', ['cd', 'cd .', r'cd /d d:\temp\analyzer', r'cd C:\elsewhere'])
def test_cd_queries_and_changes_that_cannot_select_another_directory_keep_cwd(cd):
    command = cd + '\npython -c "from pathlib import Path; Path(\'writers.py\').read_text()"'
    provider = MemoryEvidenceProvider(FILES)
    report = Analyzer(evidence=provider).analyze_report(command, WORKSPACE, shell='cmd')
    assert report.level.name == 'LOW'
    assert [query.path for query in provider.queries if isinstance(query, ReadFile)] == [WORKSPACE + r'\writers.py']
