"""Authentication-role detection, without running sudo or inspecting auth state."""
import json
import pytest

from command_inspector import Analyzer, AnalyzerConfig
from command_inspector.local_evidence import DisabledEvidenceProvider


def analyze(source, *, env=None, config=None, effort='full'):
    return Analyzer(config, evidence=DisabledEvidenceProvider()).analyze(source, '/work', shell='bash', env=env, effort=effort)


def rules(report):
    return {f['rule'] for f in report.get('findings', [])}


@pytest.mark.parametrize('source', [
    "printf '%s\\n' 'ordinary-value' | sudo -S -p '' pacman -Sy package",
    "echo ordinary-value | sudo --stdin --prompt='' true",
    "printf 'ordinary-value\\n' | sudo -kS -p '' true",
    "echo ordinary-value | sudo -S -v",
    "echo ordinary-value | /usr/bin/sudo -S true",
    "echo ordinary-value | timeout 10 sudo -S true",
    "echo ordinary-value | env X=1 sudo -S true",
    "sudo -S true <<'EOF'\nordinary-value\nEOF",
    "PW=ordinary-value; printf '%s\\n' \"$PW\" | sudo -S -p '' true",
])
@pytest.mark.parametrize('effort', ['full','partial','none'])
def test_visible_password_role_is_reported_without_disclosure(source, effort):
    report=analyze(source,effort=effort)
    found=[f for f in report['findings'] if f['rule']=='credentials-exposed']
    assert len(found)==1
    assert found[0]['level']=='HIGH'
    assert found[0]['data']['consumer']=='sudo'
    assert 'ordinary-value' not in json.dumps(report)


@pytest.mark.parametrize('source', [
    'sudo -S true', 'printf "" | sudo -S true', "printf '\\n' | sudo -S true",
    'echo ordinary-value | sudo true', "echo ordinary-value | sudo -p '-S' true",
    'echo ordinary-value | sudo -- -S', 'echo ordinary-value | sudo -nS true',
    'echo ordinary-value | sudo -AS true', 'echo ordinary-value | sudo -S --help',
    'echo ordinary-value | sudo -S true < /dev/null',
    'echo ordinary-value | cat | sudo -S true',
    "printf '%s\\n' \"$MISSING\" | sudo -S true",
    'cat password.txt | sudo -S true',
    'echo ordinary-value > output | sudo -S true',
    "echo ordinary-value | sudo -S true <<'EOF'\n\nEOF",
])
def test_no_confirmed_visible_password(source):
    assert 'credentials-exposed' not in rules(analyze(source,env={}))


def test_requested_example_keeps_package_and_privilege_findings():
    report=analyze("printf '%s\\n' 'passwd' | sudo -S -p '' pacman -Sy package")
    assert rules(report)=={'credentials-exposed','privilege-escalation','package-install'}
    assert 'passwd' not in json.dumps(report)


def test_password_stdin_is_not_reinterpreted_as_shell_source():
    report=analyze("printf '%s\\n' 'rm -rf /etc' | sudo -S bash")
    assert 'credentials-exposed' in rules(report)
    assert 'delete-protected-root' not in rules(report)
    assert 'execution-content-unavailable' in rules(report)


def test_nested_wrapper_password_stdin_is_not_shell_source():
    report=analyze("printf '%s\\n' 'rm -rf /etc' | timeout 10 sudo -S bash")
    assert 'credentials-exposed' in rules(report)
    assert 'delete-protected-root' not in rules(report)


def test_rule_can_be_disabled():
    report=analyze('echo ordinary-value | sudo -S true',config=AnalyzerConfig(disabled_rules=frozenset({'credentials-exposed'})))
    assert 'credentials-exposed' not in rules(report)
    assert 'ordinary-value' not in json.dumps(report)


def test_catalog_versions_new_rule():
    catalog=Analyzer().rule_catalog()
    rule=next(r for r in catalog['rules'] if r['rule']=='credentials-exposed')
    assert rule['introduced_in']=='1.10.0'
    assert rule['levels']==['HIGH']
    assert not rule['is_deprecated']


@pytest.mark.parametrize('disabled',[False,True])
def test_possible_password_values_are_redacted_across_report(disabled):
    config=AnalyzerConfig(disabled_rules=frozenset({'credentials-exposed'}) if disabled else frozenset())
    source='if true; then P=ordinary-one; else P=ordinary-two; fi; printf "%s\\n" "$P" | sudo -S true'
    report=analyze(source,config=config)
    assert ('credentials-exposed' in rules(report)) is not disabled
    assert 'ordinary-one' not in json.dumps(report)
    assert 'ordinary-two' not in json.dumps(report)
