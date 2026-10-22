"""Windows profiles tested in process on every host; never launch the fixtures."""
import subprocess

import pytest
from jsonschema import validate

from command_inspector import Analyzer, AnalyzerConfig, InputError
from command_inspector.local_evidence import DisabledEvidenceProvider, MemoryEvidenceProvider, ReadFile, StatTarget
from command_inspector.models import Value
from command_inspector.paths import PathStyle

CWD = r'C:\work\project'
HOME = r'C:\Users\user'


def analyzer(files=None, **config):
    provider = DisabledEvidenceProvider() if files is None else MemoryEvidenceProvider(files)
    return Analyzer(AnalyzerConfig(**config), evidence=provider)


def check(command, shell, rules, level, *, env=None, files=None, cwd=CWD):
    a = analyzer(files)
    report = a.analyze_report(command, cwd, shell=shell, env=env)
    assert sorted(f.rule for f in report.findings) == sorted(rules)
    assert report.level.name == level
    assert report.num_findings == len(rules)
    if rules:
        validate(report.to_dict(), a.report_schema())
    else:
        assert report.to_dict() == {}
    return report


@pytest.mark.parametrize('command,rules,level', [
    ('echo hello', [], 'NONE'),
    ('echo "rd /s /q C:\\Windows"', [], 'NONE'),
    ('echo Invoke-Expression', [], 'NONE'),
    ('rem rd /s /q C:\\Windows', [], 'NONE'),
    ('ver', [], 'NONE'),
    ('rd /s /q build', ['delete-inside-workspace'], 'LOW'),
    ('RD /S /Q C:\\WINDOWS', ['delete-protected-root'], 'BLOCK'),
    ('rd /s /q .', ['delete-workspace-root'], 'HIGH'),
    ('rd /s C:\\Windows', ['delete-outside-workspace'], 'MEDIUM'),
    ('rd /s /q C:\\Windows\\temp', ['delete-outside-workspace'], 'MEDIUM'),
    ('del /f a', ['delete-inside-workspace'], 'LOW'),
    ('erase /q a', ['delete-inside-workspace'], 'LOW'),
    ('rd /s /q %MISSING%', ['delete-variable-unresolved'], 'MEDIUM'),
    ('rd /s /q !MISSING!', ['delete-variable-unresolved'], 'MEDIUM'),
    ('rd /s /q *.tmp', ['delete-variable-unresolved'], 'MEDIUM'),
    ('rd /bad a', ['unknown-option', 'delete-variable-unresolved'], 'MEDIUM'),
    ('rd /s /q D:build', ['delete-variable-unresolved'], 'MEDIUM'),
    ('rd /s /q C:build', ['delete-inside-workspace'], 'LOW'),
    ('rd /s /q "build cache"', ['delete-inside-workspace'], 'LOW'),
    ('rd /s /q build^ cache', ['delete-inside-workspace'], 'LOW'),
    ('rd /s /q \\', ['delete-protected-root'], 'BLOCK'),
    ('rd /s /q', ['delete-target-missing'], 'LOW'),
    ('type a', ['ingestion-inspection-incomplete'], 'LOW'),
    ('type a > NUL', [], 'NONE'),
    ('type a 2>NUL', ['ingestion-inspection-incomplete', 'errors-suppressed'], 'LOW'),
    ('dir /s a', [], 'NONE'),
    ('mkdir build', [], 'NONE'),
    ('echo hello > a', [], 'NONE'),
    ('echo hello >> a', [], 'NONE'),
    ('echo hello > C:\\other\\a', ['write-outside-workspace'], 'LOW'),
    ('echo hello > AGENTS.md', ['modify-analyzer-config'], 'HIGH'),
    ('echo rd /s /q C:\\Windows > task.cmd', ['delete-protected-root'], 'BLOCK'),
    ('set "T=build" & rd /s /q %T%', ['delete-variable-unresolved'], 'MEDIUM'),
    ('set "T=build"\nrd /s /q %T%', ['delete-inside-workspace'], 'LOW'),
    ('set PATH=C:\\bin', ['environment-modified'], 'MEDIUM'),
    ('set /a X=2', ['unsupported-syntax'], 'LOW'),
    ('setx PATH C:\\bin', ['environment-modified'], 'MEDIUM'),
    ('cd build && rd /s /q .', ['delete-inside-workspace'], 'LOW'),
    ('cd build & rd /s /q .', ['delete-variable-unresolved'], 'MEDIUM'),
    ('cd /d D:\\build && rd /s /q .', ['read-outside-workspace', 'delete-outside-workspace'], 'MEDIUM'),
    ('cmd /c "rd /s /q C:\\Windows"', ['uses-interpreter', 'delete-protected-root'], 'BLOCK'),
    ('cmd /d /s /c "echo hello"', ['uses-interpreter'], 'LOW'),
    ('pwsh -Command "Stop-Computer"', ['uses-interpreter', 'machine-power-change'], 'HIGH'),
    ('pwsh -EncodedCommand AAABBB', ['uses-interpreter', 'execution-content-unavailable', 'obfuscated-payload'], 'HIGH'),
    ('taskkill /f /pid 123', ['force-process-termination'], 'MEDIUM'),
    ('shutdown /s /t 0', ['machine-power-change'], 'HIGH'),
    ('sc create Demo binpath=demo.exe', ['service-change'], 'MEDIUM'),
    ('schtasks /create /tn Demo', ['service-change'], 'MEDIUM'),
    ('git status', [], 'NONE'),
    ('npm test', [], 'NONE'),
    ('call task.cmd', ['uses-interpreter', 'execution-content-unavailable'], 'MEDIUM'),
    ('for %x in (a) do echo %x', [], 'NONE'),
    ('unknown-command a', ['unknown-command'], 'LOW'),
])
def test_cmd_profile(command, rules, level):
    check(command, 'cmd', rules, level)


def test_cmd_literal_backslash_regression_retains_launch_context():
    # DESIGN.md command text, not JSON-decoded, never fed to an outer shell.
    command = r'cmd /c "rd /s /q \"C:\Users\user\file\""'
    report = check(command, 'cmd', ['uses-interpreter', 'delete-protected-root', 'delete-outside-workspace'], 'BLOCK')
    root = next(f for f in report.findings if f.rule == 'delete-protected-root')
    assert root.data['target'] == 'C:\\'
    assert 'backslash did not escape the quote' in root.title
    named = next(f for f in report.findings if f.rule == 'delete-outside-workspace')
    assert named.data['target'] == r'C:\Users\user\file'
    # The stray operand resolves to the supplied drive; the spelling is not a rule.
    other = analyzer().analyze_report(command, r'D:\work', shell='cmd')
    assert next(f for f in other.findings if f.rule == 'delete-protected-root').data['target'] == 'D:\\'
    check(r'echo \"C:\Users\user\file\"', 'cmd', [], 'NONE')
    check(r'rd \"C:\Users\user\file\"', 'cmd', ['delete-outside-workspace', 'delete-outside-workspace'], 'MEDIUM')


@pytest.mark.parametrize('command', ['cd build && echo ok & rd .', 'cd build && echo ok\nrd .'])
def test_cmd_cwd_after_join_is_uncertain(command):
    check(command, 'cmd', ['delete-variable-unresolved'], 'MEDIUM')


def test_caret_inside_cmd_quotes_is_literal():
    report = check('rd /s /q "build^ cache"', 'cmd', ['delete-inside-workspace'], 'LOW')
    assert report.findings[0].data['target'] == CWD + r'\build^ cache'


def test_arguments_after_cmd_redirect_are_not_silently_discarded():
    report = analyzer().analyze_report('echo shutdown > task.cmd /s', CWD, shell='cmd')
    assert any(f.rule == 'machine-power-change' for f in report.findings)
    assert not any(f.rule == 'unsupported-syntax' for f in report.findings)

