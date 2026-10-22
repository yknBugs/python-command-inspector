"""Hard-coded Python credentials are source facts, without program execution."""
import json
import shlex

import pytest
from jsonschema import validate

from command_inspector import Analyzer, AnalyzerConfig
from command_inspector.local_evidence import DisabledEvidenceProvider, MemoryEvidenceProvider, ReadFile


@pytest.mark.parametrize('source,name', [
    ('api_key = "private-example-value"', 'api_key'),
    ('DB_PASSWORD: str = "private-example-value"', 'DB_PASSWORD'),
    ('settings.password = "private-example-value"', 'password'),
    ('settings["client_secret"] = "private-example-value"', 'client_secret'),
    ('config = {"api_key": "private-example-value"}', 'api_key'),
    ('def login(password="private-example-value"): pass', 'password'),
    ('def login(*, api_key="private-example-value"): pass', 'api_key'),
    ('login(password="private-example-value")', 'password'),
    ('(password := "private-example-value")', 'password'),
    ('name, (password, other) = "user", ("private-example-value", "x")', 'password'),
    ('api_key = "private-" + "example-value"', 'api_key'),
    ('api_key = f"private-example-value"', 'api_key'),
    ('password = b"private-example-value"', 'password'),
    ('text = "password=private-example-value"', None),
    ('text = "ghp_abcdefghijklmnopqrstuvwxyz012345"', None),
    ('text = "-----BEGIN PRIVATE KEY-----\\nprivate-example-value\\n-----END PRIVATE KEY-----"', None),
])
@pytest.mark.parametrize('effort', ['Full', 'Partial', 'None'])
def test_literal_credentials_are_reported_without_values_or_evidence(source, name, effort):
    provider = MemoryEvidenceProvider({})
    analyzer = Analyzer(evidence=provider)
    report = analyzer.analyze_python_report(source, '/work', effort=effort)
    found = [finding for finding in report.findings if finding.rule == 'hardcoded-secret']
    assert found
    assert all(f.level.name == 'MEDIUM' for f in found)
    assert all(f.data['language'] == 'python' and f.data['line'] == 1 for f in found)
    if name:
        assert any(name in finding.data['variables'] for finding in found)
    assert 'private-example-value' not in json.dumps(report.to_dict())
    assert 'abcdefghijklmnopqrstuvwxyz012345' not in json.dumps(report.to_dict())
    assert not provider.queries
    validate(report.to_dict(), analyzer.report_schema())


@pytest.mark.parametrize('source', [
    '# api_key="private-example-value"',
    'import os; api_key = os.environ.get("API_KEY")',
    'password = ""',
    'password = None',
    'api_key = runtime_value',
    'password_file = "config.txt"',
    'secret_count = 3',
    'api_key = f"{runtime_value}"',
])
def test_comments_and_nonliteral_credentials_are_not_reported(source):
    report = Analyzer(evidence=DisabledEvidenceProvider()).analyze_python_report(source, '/work')
    assert 'hardcoded-secret' not in {f.rule for f in report.findings}


@pytest.mark.parametrize('effort', ['Full', 'Partial', 'None'])
def test_file_credentials_require_content_evidence_but_inline_credentials_do_not(effort):
    source = 'def dormant():\n    api_key = "private-example-value"\n'
    provider = MemoryEvidenceProvider({'/work/tools/app.py': source})
    analyzer = Analyzer(evidence=provider)
    report = analyzer.analyze_report('python tools/app.py', '/work', shell='bash', effort=effort)
    found = [f for f in report.findings if f.rule == 'hardcoded-secret']
    assert bool(found) == (effort == 'Full')
    if found:
        assert found[0].data['source'] == '/work/tools/app.py'
        assert found[0].data['line'] == 2
    assert any(isinstance(q, ReadFile) for q in provider.queries) == (effort == 'Full')
    command = shlex.join(['python', '-c', source])
    inline = analyzer.analyze_report(command, '/work', shell='bash', effort=effort)
    assert 'hardcoded-secret' in {f.rule for f in inline.findings}


@pytest.mark.parametrize('shell,command,cwd,path', [
    ('bash', 'echo \'api_key="private-example-value"\' > config.py', '/work', '/work/config.py'),
    ('powershell', 'Set-Content config.py \'api_key="private-example-value"\'', r'C:\work', r'C:\work\config.py'),
    ('cmd', 'echo api_key="private-example-value" > config.py', r'C:\work', r'C:\work\config.py'),
    ('python', 'from pathlib import Path; Path("config.py").write_text(\'api_key="private-example-value"\')', '/work', '/work/config.py'),
    ('javascript', 'require("fs").writeFileSync("config.py",\'api_key="private-example-value"\')', '/work', '/work/config.py'),
])
def test_written_python_source_is_inspected_from_each_adapter(shell, command, cwd, path):
    report = Analyzer(evidence=DisabledEvidenceProvider()).analyze_report(command, cwd, shell=shell, effort='None')
    found = [f for f in report.findings if f.rule == 'hardcoded-secret' and f.data['source'] == path]
    assert found and found[0].data['context'] == 'written_content'
    assert 'private-example-value' not in json.dumps(report.to_dict())


@pytest.mark.parametrize('disabled', [False, True])
def test_secret_candidates_are_redacted_even_when_source_rule_is_disabled(disabled):
    source = '''from pathlib import Path
api_key = "firstPrivateValue"
api_key = "secondPrivateValue"
Path(api_key).read_text()
'''
    config = AnalyzerConfig(disabled_rules=frozenset({'hardcoded-secret'}) if disabled else frozenset())
    report = Analyzer(config, evidence=DisabledEvidenceProvider()).analyze_python_report(source, '/work')
    for finding in report.findings:
        if 'api_key' in finding.data.get('possible_values', {}):
            assert finding.data['possible_values']['api_key'] == ['[REDACTED]']
    assert ('hardcoded-secret' in {f.rule for f in report.findings}) != disabled
    assert 'firstPrivateValue' not in json.dumps(report.to_dict())
    assert 'secondPrivateValue' not in json.dumps(report.to_dict())


def test_literal_scanning_respects_value_budget_and_invalid_unicode():
    analyzer = Analyzer(AnalyzerConfig(value_bytes=8), evidence=DisabledEvidenceProvider())
    assert not analyzer.analyze_python('api_key = "private-example-value"', '/work')
    report = Analyzer(evidence=DisabledEvidenceProvider()).analyze_python_report('password="\\ud800"', '/work')
    assert 'hardcoded-secret' not in {f.rule for f in report.findings}
