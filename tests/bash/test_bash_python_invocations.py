"""POSIX equivalents of the reported PowerShell/Python command sequence."""
import os
import subprocess

import pytest

from command_inspector import Analyzer
from command_inspector.bash.semantics import resolve_word
from command_inspector.local_evidence import DisabledEvidenceProvider, MemoryEvidenceProvider, ReadFile
from command_inspector.models import Value


WORKSPACE = '/work/analyzer'
PYTHON = '/opt/python/bin/python3'
COMMAND = '''cd /work/analyzer
"/opt/python/bin/python3" -c "
import ast, pathlib
for n in ('writers.py','policy.py'):
    try:
        ast.parse(pathlib.Path(n).read_text(encoding='utf-8')); print(f'{n} ok')
    except SyntaxError as e: print(f'{n} SYNTAX', e.lineno, e.msg)
" 2>&1 | cat
"/opt/python/bin/python3" tools/dump_all_copy.py 2>&1 | tail -n 1
"/opt/python/bin/python3" -m pytest -q -p no:cacheprovider --tb=line 2>&1 | tail -n 8
'''
FILES = {
    PYTHON: b'\x00executable fixture',
    WORKSPACE + '/writers.py': 'value = 1\n',
    WORKSPACE + '/policy.py': 'value = 2\n',
    WORKSPACE + '/tools/dump_all_copy.py': 'print("ok")\n',
}


@pytest.fixture(autouse=True)
def no_command_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('Analyzing Bash/Python started a process')
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    monkeypatch.setattr(os, 'system', forbidden)


@pytest.mark.parametrize('effort', ['Full', 'Partial', 'None'])
@pytest.mark.parametrize('cwd', [WORKSPACE, '/elsewhere'])
def test_multiline_python_commands_and_output_pipelines(cwd, effort):
    provider = MemoryEvidenceProvider(FILES)
    analyzer = Analyzer(evidence=provider)
    assert not analyzer.parse(COMMAND, shell='bash').diagnostics
    report = analyzer.analyze_report(COMMAND, cwd, shell='bash', effort=effort)
    expected = {'command-via-path', 'uses-interpreter'}
    if cwd != WORKSPACE:
        expected |= {'read-outside-workspace', 'ingestion-inspection-incomplete', 'execution-content-unavailable'}
        if effort != 'None':
            expected.add('execute-target-missing')
    elif effort != 'Full':
        expected |= {'ingestion-inspection-incomplete', 'execution-content-unavailable'}
    assert {finding.rule for finding in report.findings} == expected
    assert report.level.name == ('LOW' if cwd == WORKSPACE and effort == 'Full' else 'MEDIUM')
    reads = [query.path for query in provider.queries if isinstance(query, ReadFile)]
    expected_reads = [WORKSPACE + '/writers.py', WORKSPACE + '/policy.py', WORKSPACE + '/tools/dump_all_copy.py']
    if cwd != WORKSPACE:
        expected_reads += ['/elsewhere/writers.py', '/elsewhere/policy.py', '/elsewhere/tools/dump_all_copy.py']
    assert set(reads) == (set(expected_reads) if effort == 'Full' else set())
    if effort == 'None':
        assert not provider.queries


@pytest.mark.parametrize('effort', ['Full', 'Partial', 'None'])
def test_python_candidates_keep_posix_scope_for_possible_directories(effort):
    command = '''cd /elsewhere
"/opt/python/bin/python3" -c "import shutil; names=('/etc', 'cache'); [shutil.rmtree(n) for n in names]"
'''
    report = Analyzer(evidence=DisabledEvidenceProvider()).analyze_report(
        command, WORKSPACE, shell='bash', effort=effort)
    rules = {finding.rule for finding in report.findings}
    assert 'delete-protected-root' in rules
    assert 'delete-variable-unresolved' not in rules
    assert {'delete-inside-workspace', 'delete-outside-workspace'} <= rules
    assert report.level.name == 'BLOCK'


def test_invoked_python_file_is_still_inspected_after_same_directory_cd():
    files = FILES | {WORKSPACE + '/tools/dump_all_copy.py': 'import shutil; shutil.rmtree("/etc")\n'}
    report = Analyzer(evidence=MemoryEvidenceProvider(files)).analyze_report(COMMAND, WORKSPACE, shell='bash')
    assert 'delete-protected-root' in {finding.rule for finding in report.findings}
    assert report.level.name == 'BLOCK'


@pytest.mark.parametrize('effort', ['Full', 'Partial', 'None'])
def test_multiline_literal_python_deletion_is_checked_at_every_effort(effort):
    command = 'python3 -c "\nimport shutil\nshutil.rmtree(\'/etc\')\n" 2>&1 | tail -n 1'
    report = Analyzer(evidence=DisabledEvidenceProvider()).analyze_report(
        command, WORKSPACE, shell='bash', effort=effort)
    assert 'delete-protected-root' in {finding.rule for finding in report.findings}
    assert 'unsupported-syntax' not in {finding.rule for finding in report.findings}
    assert report.level.name == 'BLOCK'


@pytest.mark.parametrize('argument,expected', [
    ('"a\nb"', 'a\nb'),
    ('"\n$x\n"', '\nvalue\n'),
    ('"a\\\nb"', 'ab'),
    ('"a\n\n b"', 'a\n\n b'),
    ('"line\\\n\n$x\n"', 'line\nvalue\n'),
    ('"é\n$x\n末"', 'é\nvalue\n末'),
])
def test_quoted_argument_keeps_literal_newlines_and_removes_line_continuations(argument, expected):
    parsed = Analyzer().parse('echo ' + argument, shell='bash')
    assert not parsed.diagnostics
    word = next(child for child in parsed.root.children[0].children if child.kind == 'string')
    assert resolve_word(word, {'x': Value('value')}).text == expected
