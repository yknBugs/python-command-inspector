"""Pinned Bash grammar recovery keeps assignments, commands and source spans."""
import pytest

from command_inspector import Analyzer
from command_inspector.local_evidence import MemoryEvidenceProvider
from command_inspector.bash.syntax import BashFrontend, ParseBudgetExceeded


SAMPLE = """W = /home/usr/files
A = $W/scripts
rg -n -B3 -A12 'def' $A/app.py
PYTHONPATH=$W/module:$W/src python3 - << 'PY'
print("Hello world")"""


def nodes(root):
    pending = [root]
    while pending:
        node = pending.pop()
        yield node
        pending.extend(reversed(node.children))


def analyze(text, *, files=None, cwd="/work", env=None):
    return Analyzer(evidence=MemoryEvidenceProvider(files or {})).analyze_report(text, cwd, env=env)


@pytest.mark.parametrize("ending", ["", "\n", "\nPY", "\nPY\n"])
def test_user_sample_retains_real_commands_and_unresolved_bindings(ending):
    report = analyze(SAMPLE + ending)
    assert report.level.name == "LOW"
    unknown = [f.data["command"] for f in report.findings if f.rule == "unknown-command"]
    assert unknown == ["W", "A"]
    assert {f.data["interpreters"][0] for f in report.findings if f.rule == "uses-interpreter"} == {"python3"}
    assert bool([f for f in report.findings if f.rule == "unsupported-syntax"]) is ("PY" not in ending)
    variables = {name for f in report.findings for name in f.data.get("variables", [])}
    assert variables == {"W", "A"}
    assert not any(f.rule.startswith("execution-path-") or f.rule == "execute-missing-file" for f in report.findings)


def test_correct_assignments_and_closed_heredoc_have_only_interpreter_notice():
    source = SAMPLE.replace("W = /home/usr/files", "W=/home/usr/files").replace("A = ", "A=") + "\nPY"
    report = analyze(source, cwd="/home/usr/files", files={"/home/usr/files/scripts/app.py": "def main():\n    pass\n"})
    assert [f.rule for f in report.findings] == ["uses-interpreter"]


@pytest.mark.parametrize("prefix", [
    "X=$W/a:$W/b", "X=$W/a:$W/b Y=$A/c:$A/d", "X=${W}/a:$W/b",
    "X=$W/a:$W/b:$A/c", "X=$W/a:$W/b:$W/c",
])
@pytest.mark.parametrize("body", ["rm -rf /etc", "bash -c 'rm -rf /etc'", "/usr/bin/rm -rf /etc"])
def test_prefix_recovery_cannot_hide_visible_destructive_operations(prefix, body):
    report = analyze(prefix + " " + body)
    assert any(f.rule == "delete-protected-root" and f.level.name == "BLOCK" for f in report.findings)
    assert not any(f.rule == "unknown-command" for f in report.findings)


@pytest.mark.parametrize("spelling", ["$W/a:$W/b", "${W}/a:$W/b", "$W/a:${W}/b"])
def test_recovered_standalone_assignment_keeps_full_value(spelling):
    report = analyze(f'W=/work; X={spelling}; rm -rf "$X"')
    deletion, = [f for f in report.findings if f.rule == "delete-inside-workspace"]
    assert deletion.data["target"] == "/work/a:/work/b"
    assert not any(f.rule == "unknown-command" for f in report.findings)


def test_prefix_environment_values_reach_child_and_do_not_change_parent():
    report = analyze('W=/etc; X=$W/a:$W/b bash -c \'rm -rf "$X"\'; rm -rf "$X"', env={"X": "/work/safe"})
    assert {f.data["target"] for f in report.findings if f.rule.startswith("delete-") and "target" in f.data} == {
        "/etc/a:/etc/b", "/work/safe"}


@pytest.mark.parametrize("ending", ["", "\n", "\nPY"])
def test_heredoc_python_effects_are_inspected_even_without_eof_delimiter(ending):
    report = analyze("PYTHONPATH=$W/a:$W/b python3 - <<'PY'\nimport os; os.remove('/etc/passwd')" + ending)
    deletion, = [f for f in report.findings if f.rule == "delete-outside-workspace"]
    assert deletion.data["target"] == "/etc/passwd"
    assert any(f.rule == "uses-interpreter" for f in report.findings)
    assert not any(f.rule == "unknown-command" for f in report.findings)


@pytest.mark.parametrize("text", [
    "X=$W/a:$W/b rm -rf /etc",
    "# 非ASCII\nX=$W/模块:$W/源 python3 - <<'PY'\nprint('你好')\nPY",
    "X=$W/a:$W/b Y=$A/c:$A/d rm -rf /etc",
    "cat <<'EOF'\n最后一行",
])
def test_recovery_preserves_original_character_spans(text):
    parsed = BashFrontend().parse(text)
    for node in nodes(parsed.root):
        assert 0 <= node.span.start <= node.span.end <= len(text)
        assert node.text == text[node.span.start:node.span.end]
    assert all(0 <= span.start <= span.end <= len(text) for span in parsed.diagnostics)


@pytest.mark.parametrize("text", ["X=$W/a:$W/b rm -rf /etc", "cat <<'EOF'\nlast line"])
def test_recovery_respects_node_budget(text):
    with pytest.raises(ParseBudgetExceeded):
        BashFrontend().parse(text, max_nodes=10)
    assert BashFrontend().parse(text, max_nodes=500).root.text == text


@pytest.mark.parametrize("text,commands", [
    ("W = /etc", ["W"]),
    ("X=$W/a:$W/b echo '$Y/a:$Y/b'", ["echo"]),
    ("X=$W/a:$W/b printf '%s' '${Z}'", ["printf"]),
    ("X=$W/a:$W/b git push", ["git"]),
])
def test_recovery_keeps_actual_command_and_literal_arguments(text, commands):
    parsed = BashFrontend().parse(text)
    assert [n.text for n in nodes(parsed.root) if n.kind == "command_name"] == commands
    for node in nodes(parsed.root):
        assert node.text == text[node.span.start:node.span.end]
