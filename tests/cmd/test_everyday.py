"""Everyday Windows-shell contracts, using only parsed text and memory evidence.

Reference semantics: Microsoft Learn about_Parsing, about_Redirection, Remove-Item,
Invoke-WebRequest, cmd, and setlocal. No fixture is run by Windows, Wine, or a shell.
"""
import os
import subprocess

import jsonschema
import pytest

from command_inspector import Analyzer, AnalyzerConfig
from command_inspector.local_evidence import DisabledEvidenceProvider, MemoryEvidenceProvider, ReadFile

CWD = r'C:\work\project'


@pytest.fixture(autouse=True)
def forbid_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('Static analysis attempted process execution')
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    monkeypatch.setattr(os, 'system', forbidden)


def analyze(command, shell='powershell', *, files=None, env=None, cwd=CWD):
    provider = DisabledEvidenceProvider() if files is None else MemoryEvidenceProvider(files)
    analyzer = Analyzer(evidence=provider)
    report = analyzer.analyze(command, cwd, shell=shell, env=env)
    jsonschema.validate(report, analyzer.report_schema())
    for finding in report.get('findings', []):
        catalog = next(r for r in analyzer.rule_catalog()['rules'] if r['rule'] == finding['rule'])
        assert finding['level'] in catalog['levels']
    return report


def rules(report):
    return [f['rule'] for f in report.get('findings', [])]


def targets(report, rule):
    return [f['data'].get('target') for f in report.get('findings', []) if f['rule'] == rule]


@pytest.mark.parametrize('command', ['echo shutdown >task.cmd /s', '>task.cmd echo shutdown /s', 'echo shutdown /s >task.cmd'])
def test_cmd_redirection_position_preserves_command_arguments(command):
    assert rules(analyze(command, 'cmd')) == ['machine-power-change']


@pytest.mark.parametrize('command,target', [
    ('setlocal EnableDelayedExpansion\nset T=build\nrd !T!', 'build'),
    ('setlocal EnableDelayedExpansion\nset T=build & rd !T!', 'build'),
    ('set T=old\nsetlocal\nset T=new\nendlocal\nrd %T%', 'old'),
    ('set T=old\n(set T=new\nrd %T%)', 'old'),
    ('setlocal DisableDelayedExpansion\nrd !literal!', '!literal!'),
    ('@set T=build\n@rd %T%', 'build'),
])
def test_cmd_expansion_scope(command, target):
    report = analyze(command, 'cmd')
    assert targets(report, 'delete-inside-workspace') == [CWD + '\\' + target]
    assert 'delete-variable-unresolved' not in rules(report)


@pytest.mark.parametrize('command', ['rd !T!', 'setlocal EnableDelayedExpansion\nrd !T!', 'rd %MISSING%'])
def test_cmd_missing_or_unknown_expansion_stays_unresolved(command):
    assert 'delete-variable-unresolved' in rules(analyze(command, 'cmd'))


@pytest.mark.parametrize('command', ['sc.exe stop Demo', 'sc.exe delete Demo', 'schtasks.exe /delete /tn Demo /f', 'schtasks /end /tn Demo'])
def test_cmd_service_and_task_changes(command):
    report = analyze(command, 'cmd')
    assert rules(report) == ['service-change']
    assert report['findings'][0]['data']['targets'] == ['Demo']


def test_cmd_exit_stops_later_commands():
    assert analyze('exit /b 0 & rd /s /q C:\\Windows', 'cmd') == {}


@pytest.mark.parametrize('command', [
    r'if exist marker rd /s /q C:\Windows',
    r'if not defined MISSING rd /s /q C:\Windows',
    r'if /i a==b rd /s /q C:\Windows',
    r'for %d in (a b) do rd /s /q C:\Windows',
])
def test_cmd_visible_conditional_and_loop_bodies(command):
    report = analyze(command, 'cmd')
    assert 'delete-protected-root' in rules(report)
    finding = next(f for f in report['findings'] if f['rule'] == 'delete-protected-root')
    assert 'if the CMD' in finding['detail']


def test_cmd_for_variable_is_not_enumerated():
    report = analyze(r'for %d in (a b) do rd /s /q %d', 'cmd')
    assert 'delete-variable-unresolved' not in rules(report)
    assert set(targets(report, 'delete-inside-workspace')) == {CWD + r'\a', CWD + r'\b'}
    assert all(f['data']['possible'] for f in report['findings'] if f['rule'] == 'delete-inside-workspace')
    assert 'unknown-command' not in rules(report)


def test_cmd_call_inspects_direct_artifact_only():
    provider = MemoryEvidenceProvider({CWD + r'\task.cmd': 'call dependency.cmd\nshutdown /s',
                                       CWD + r'\dependency.cmd': 'rd /s /q C:\\Windows'})
    report = Analyzer(evidence=provider).analyze('call task.cmd', CWD, shell='cmd')
    assert 'machine-power-change' in rules(report)
    assert 'delete-protected-root' not in rules(report)
    assert [q.path for q in provider.queries if isinstance(q, ReadFile)] == [CWD + r'\task.cmd']


def test_cmd_square_brackets_are_literal_path_characters():
    assert targets(analyze('rd a[1]', 'cmd'), 'delete-inside-workspace') == [CWD + r'\a[1]']

