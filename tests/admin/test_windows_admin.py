"""Static administration effects and negative controls; never run fixture text."""
import os
import subprocess

import pytest

from command_inspector import Analyzer
from command_inspector.local_evidence import DisabledEvidenceProvider


@pytest.fixture(autouse=True)
def no_execution(monkeypatch):
    def fail(*args, **kwargs):
        pytest.fail('analyzer attempted command execution')
    monkeypatch.setattr(subprocess, 'Popen', fail)
    monkeypatch.setattr(os, 'system', fail)


def report(command, shell):
    return Analyzer(evidence=DisabledEvidenceProvider()).analyze_report(command, r'D:\work\project', shell=shell)


@pytest.mark.parametrize('shell', ['cmd', 'powershell'])
@pytest.mark.parametrize('command,rule,level', [
    ('FORMAT.exe C: /q', 'volume-format', 'BLOCK'),
    ('vssadmin delete shadows /all /quiet', 'backup-delete', 'HIGH'),
    ('cipher /w:C:', 'free-space-wipe', 'HIGH'),
    ('wevtutil clear-log System', 'event-log-clear', 'HIGH'),
    (r'reg add HKCU\Software\Demo /v x /d value', 'registry-change', 'MEDIUM'),
    ('netsh advfirewall set allprofiles state off', 'security-policy-change', 'HIGH'),
    ('net user alice example-password /add', 'account-change', 'HIGH'),
    ('net localgroup administrators alice /add', 'account-change', 'HIGH'),
    ('net stop WinDefend', 'service-change', 'MEDIUM'),
])
def test_native_effects(command, rule, level, shell):
    result = report(command, shell)
    assert [(f.rule, f.level.name) for f in result.findings] == [(rule, level)]
    assert 'example-password' not in str([f.data for f in result.findings])


@pytest.mark.parametrize('shell', ['cmd', 'powershell'])
@pytest.mark.parametrize('command', [
    'format /?', 'diskpart /?', 'cipher', 'cipher /y',
    'vssadmin list shadows', 'wevtutil qe System',
    r'reg query HKCU\Software\Demo', 'netsh advfirewall show allprofiles',
    'net user', 'net user alice', 'net localgroup administrators', 'whoami /all',
])
def test_readonly_and_help(command, shell):
    assert report(command, shell).to_dict() == {}


@pytest.mark.parametrize('shell', ['cmd', 'powershell'])
@pytest.mark.parametrize('command', ['cipher /invented', 'reg invented', 'netsh invented', 'vssadmin invented', 'wevtutil invented', 'certutil -invented'])
def test_unmodeled_forms_are_not_silently_trusted(command, shell):
    assert [f.rule for f in report(command, shell).findings] == ['unsupported-syntax']


@pytest.mark.parametrize('shell', ['cmd', 'powershell'])
def test_decode_is_not_execution_or_obfuscation(shell):
    result = report('certutil -decode payload.b64 payload.exe', shell)
    assert [f.rule for f in result.findings] == ['unresolved-value']


@pytest.mark.parametrize('shell', ['cmd', 'powershell'])
def test_diskpart_filename_does_not_prove_writes(shell):
    result = report('diskpart /s wipe.txt', shell)
    assert sorted(f.rule for f in result.findings) == ['execution-content-unavailable', 'uses-interpreter']


@pytest.mark.parametrize('shell', ['cmd', 'powershell'])
def test_remote_hta_not_obfuscated(shell):
    result = report('mshta https://example.com/app.hta', shell)
    assert sorted(f.rule for f in result.findings) == ['download-content', 'execution-content-unavailable', 'uses-interpreter']


@pytest.mark.parametrize('command', [
    'Set-ExecutionPolicy Bypass -Scope Process -Force',
    'Set-MpPreference -DisableRealtimeMonitoring $true',
    'Set-MpPreference -DisableRealtimeMonitoring $false',
    'Add-MpPreference -ExclusionPath C:\\',
    'Remove-MpPreference -ExclusionPath C:\\',
])
def test_policy_changes_include_strengthening(command):
    # The rule describes a change, not an assertion that protection is disabled.
    assert [f.rule for f in report(command, 'powershell').findings] == ['security-policy-change']
    if command.startswith('Set-ExecutionPolicy'):
        assert [f.rule for f in report(command + ' -WhatIf', 'powershell').findings] == ['unresolved-value']


@pytest.mark.parametrize('command', [r'del /f /s /q D:\*', r'erase /s /f C:\*', r'del /f /s D:\*.*'])
def test_recursive_file_deletion_at_drive_root(command):
    result = report(command, 'cmd')
    assert [f.rule for f in result.findings] == ['delete-protected-root']
    assert result.level.name == 'BLOCK'


def test_nonrecursive_root_glob_not_recursive_delete():
    assert [f.rule for f in report(r'del /f D:\*', 'cmd').findings] == ['delete-variable-unresolved']


def test_catalog_additions_have_correct_introduction_version():
    catalog = Analyzer().rule_catalog()
    assert catalog['version'] == '1.13.0'
    versions = {r['rule']: r['introduced_in'] for r in catalog['rules']}
    assert versions['volume-format'] == '1.1.0'
    assert versions['service-change'] == '1.0.0'
