"""JavaScript hard-coded credentials use the same source reporting contract."""
import json
import shlex

import pytest
from jsonschema import validate

pytest.importorskip('tree_sitter_javascript')

from command_inspector import Analyzer, AnalyzerConfig
from command_inspector.local_evidence import DisabledEvidenceProvider, MemoryEvidenceProvider, ReadFile


@pytest.mark.parametrize('source,name', [
    ('const apiKey="private-example-value";', 'apiKey'),
    ('let password; password="private-example-value";', 'password'),
    ('config.password="private-example-value";', 'password'),
    ('config["api_key"]="private-example-value";', 'api_key'),
    ('const config={"client_secret":"private-example-value"};', 'client_secret'),
    ('const config={password:"private-example-value"};', 'password'),
    ('function f(password="private-example-value") {}', 'password'),
    ('class C { apiKey="private-example-value"; }', 'apiKey'),
    ('const apiKey=`private-example-value`;', 'apiKey'),
    ('const apiKey="private-"+"example-value";', 'apiKey'),
    ('const password=("private-example-value");', 'password'),
    ('const text="password=private-example-value";', None),
    ('const text="ghp_abcdefghijklmnopqrstuvwxyz012345";', None),
    ('const text="password=\\u0070rivate-example-value";', None),
])
@pytest.mark.parametrize('effort', ['Full', 'Partial', 'None'])
def test_literal_credentials_are_reported_without_values_or_evidence(source, name, effort):
    provider = MemoryEvidenceProvider({})
    analyzer = Analyzer(evidence=provider)
    report = analyzer.analyze_javascript_report(source, '/work', effort=effort)
    found = [finding for finding in report.findings if finding.rule == 'hardcoded-secret']
    assert found
    assert all(f.level.name == 'MEDIUM' for f in found)
    assert all(f.data['language'] == 'javascript' and f.data['line'] == 1 for f in found)
    if name:
        assert any(name in finding.data['variables'] for finding in found)
    assert 'private-example-value' not in json.dumps(report.to_dict())
    assert 'abcdefghijklmnopqrstuvwxyz012345' not in json.dumps(report.to_dict())
    assert not provider.queries
    validate(report.to_dict(), analyzer.report_schema())


@pytest.mark.parametrize('source', [
    '// apiKey="private-example-value"',
    '/* password="private-example-value" */',
    'const apiKey=process.env.API_KEY;',
    'const apiKey=process.env["API_KEY"];',
    'const password="";',
    'const password=null;',
    'const password=runtime_value;',
    'const passwordFile="config.txt";',
    'const apiKey=`${runtime_value}`;',
])
def test_comments_and_nonliteral_credentials_are_not_reported(source):
    report = Analyzer(evidence=DisabledEvidenceProvider()).analyze_javascript_report(source, '/work')
    assert 'hardcoded-secret' not in {f.rule for f in report.findings}


@pytest.mark.parametrize('effort', ['Full', 'Partial', 'None'])
def test_file_credentials_require_content_evidence_but_inline_credentials_do_not(effort):
    source = 'function dormant() {\n    const apiKey="private-example-value";\n}'
    provider = MemoryEvidenceProvider({'/work/tools/app.js': source})
    analyzer = Analyzer(evidence=provider)
    report = analyzer.analyze_report('node tools/app.js', '/work', shell='bash', effort=effort)
    found = [f for f in report.findings if f.rule == 'hardcoded-secret']
    assert bool(found) == (effort == 'Full')
    if found:
        assert found[0].data['source'] == '/work/tools/app.js'
        assert found[0].data['line'] == 2
    assert any(isinstance(q, ReadFile) for q in provider.queries) == (effort == 'Full')
    inline = analyzer.analyze_report(shlex.join(['node', '-e', source]), '/work', shell='bash', effort=effort)
    assert 'hardcoded-secret' in {f.rule for f in inline.findings}


@pytest.mark.parametrize('disabled', [False, True])
def test_secret_candidate_metadata_is_redacted_with_disabled_rule(disabled):
    source = '''let apiKey="firstPrivateValue";
apiKey="secondPrivateValue";
require('fs').readFileSync(apiKey,'utf8');'''
    config = AnalyzerConfig(disabled_rules=frozenset({'hardcoded-secret'}) if disabled else frozenset())
    report = Analyzer(config, evidence=DisabledEvidenceProvider()).analyze_javascript_report(source, '/work')
    for finding in report.findings:
        if 'apiKey' in finding.data.get('possible_values', {}):
            assert finding.data['possible_values']['apiKey'] == ['[REDACTED]']
    assert ('hardcoded-secret' in {f.rule for f in report.findings}) != disabled
    assert 'firstPrivateValue' not in json.dumps(report.to_dict())
    assert 'secondPrivateValue' not in json.dumps(report.to_dict())
