"""Regressions for the reported semantic defects.

Each test names the symptom that was reported and the behavior the fix must
produce, so the claim stays traceable to its report. These are expected to fail
until the corresponding fix lands; they are not skipped or xfailed on purpose.

Two of them are contrast cases (``test_bug7b``, ``test_bug8_...``'s second half)
that already pass: they pin the direction the fix must not break.
"""
import pytest
from command_inspector import Analyzer
from command_inspector.local_evidence import DisabledEvidenceProvider, MemoryEvidenceProvider, ReadFile, StatTarget


def rules(report):
    return {f["rule"] for f in report.get("findings", [])}


def targets(report):
    return {f.get("data", {}).get("target") for f in report.get("findings", [])}


def read_paths(provider):
    return [q.path for q in getattr(provider, "queries", []) if isinstance(q, ReadFile)]


def analyze(command, *, files=None, env=None, cwd="/work", evidence=True):
    provider = MemoryEvidenceProvider(files or {}) if evidence else DisabledEvidenceProvider()
    report = Analyzer(evidence=provider).analyze(command, cwd, env=env, shell="bash")
    return report, provider


# 1. "sudo rm -rf /etc produces privilege escalation and an unknown option, but
#    misses the protected-root deletion. parse_options reads rm's -rf as sudo
#    options and returns before analysing rm."
def test_bug1_wrapper_options_do_not_consume_the_wrapped_command():
    report, _ = analyze("sudo rm -rf /etc", evidence=False)
    assert "delete-protected-root" in rules(report)
    assert "unknown-option" not in rules(report)


def test_bug1b_wrapper_consumes_its_own_value_options_first():
    # `-u root` belongs to sudo; `rm -rf /etc` must still be analysed.
    report, _ = analyze("sudo -u root rm -rf /etc", evidence=False)
    assert "delete-protected-root" in rules(report)
    assert "unknown-option" not in rules(report)


# `sudo -i` starts a login shell even without an explicit command operand.
# This case pins elevation only; it does not assert that no shell runs.
def test_bug1c_login_shell_requests_elevation():
    report, _ = analyze("sudo -i", evidence=False)
    assert "privilege-escalation" in rules(report)


def test_bug1d_wrapper_with_an_unknown_option_does_not_guess_a_command():
    report, _ = analyze("sudo -Z rm -rf /etc", evidence=False)
    assert "delete-protected-root" not in rules(report)
    assert "execution-content-unavailable" in rules(report)


# 2a. "With sudo reboot in B.sh, `bash B.sh -c true` only reports interpreter use
#     and never reads B.sh: the later -c is wrongly treated as Bash's inline-code
#     option."
def test_bug2a_interpreter_options_stop_at_the_script_operand():
    report, provider = analyze("bash B.sh -c true", files={"/work/B.sh": "sudo reboot\n"})
    assert "privilege-escalation" in rules(report)
    assert "machine-power-change" in rules(report)
    assert "/work/B.sh" in read_paths(provider)


# 2b. "python demo.py --help treats script arguments as unsupported interpreter
#     options."
def test_bug2b_script_arguments_are_not_interpreter_options():
    report, provider = analyze(
        "python demo.py --help", files={"/work/demo.py": "import os\nos.system('sudo true')\n"})
    assert "privilege-escalation" in rules(report)
    assert "unknown-option" not in rules(report)
    assert "execution-content-unavailable" not in rules(report)
    assert "/work/demo.py" in read_paths(provider)


# 3a. "A=\"$(sudo reboot)\" returns {} because assignment() only inspects direct
#      command_substitution children; the quotes introduce an intermediate string
#      node."
def test_bug3a_substitution_inside_a_quoted_assignment_is_visible():
    report, _ = analyze('A="$(sudo reboot)"')
    assert "privilege-escalation" in rules(report)
    assert "machine-power-change" in rules(report)


# 3b. "Redirect targets such as echo ok > \"$(sudo reboot)\" also miss the visible
#      operation."
def test_bug3b_substitution_inside_a_redirect_target_is_visible():
    report, _ = analyze('echo ok > "$(sudo reboot)"')
    assert "privilege-escalation" in rules(report)
    assert "machine-power-change" in rules(report)


# 4. "A quoted here-document containing sudo reboot passed to bash produces only
#    uses-interpreter. The literal payload is extracted here but attached only to
#    a file-write fact, so executable stdin content disappears."
def test_bug4_quoted_heredoc_stdin_to_an_interpreter_is_executable_content():
    report, _ = analyze("bash <<'EOF'\nsudo reboot\nEOF")
    assert "privilege-escalation" in rules(report)
    assert "machine-power-change" in rules(report)


# 5a. "cat secrets 2> errors, where secrets holds credentials, suppresses
#     credentials-read even though stdout still exposes the content: any write
#     redirection marks every read as output_consumed."
def test_bug5a_stderr_redirection_does_not_consume_stdout():
    report, _ = analyze("cat secrets 2> errors", files={"/work/secrets": "password=abcdefg\n"})
    assert "credentials-read" in rules(report)


# Credential-source inspection is independent of the output destination.
def test_stdout_discarded_still_checks_credentials():
    report, _ = analyze("cat secrets > /dev/null", files={"/work/secrets": "password=abcdefg\n"})
    assert "credentials-read" in rules(report)


# 5c. The same descriptor model: duplicating stderr is not suppression, while
#     discarding both streams is. `2>&1` used to be reported as errors-suppressed.
def test_bug5c_duplicating_stderr_is_not_error_suppression():
    report, _ = analyze("cat secrets 2>&1", files={"/work/secrets": "password=abcdefg\n"})
    assert "errors-suppressed" not in rules(report)
    assert "credentials-read" in rules(report)


def test_bug5d_discarding_both_streams_suppresses_errors():
    report, _ = analyze("true &> /dev/null")
    assert "errors-suppressed" in rules(report)


# 6. "i=/etc; for i in /work/cache; do rm -rf \"$i\"; done reports BLOCK because
#    the loop body inherited the pre-loop value even though the loop overwrites
#    i. An unsupported-syntax notice is not a reason to keep a false concrete
#    deletion target."
def test_bug6_loop_variable_does_not_inherit_the_pre_loop_value():
    report, _ = analyze('i=/etc; for i in /work/cache; do rm -rf "$i"; done', evidence=False)
    assert "delete-protected-root" not in rules(report)
    assert "delete-variable-unresolved" not in rules(report)
    assert '/work/cache' in targets(report)
    assert '/etc' not in targets(report)


def test_bug6b_literal_loop_values_are_not_enumerated():
    report, _ = analyze("for d in /work/cache /etc; do rm -rf \"$d\"; done", evidence=False)
    assert "delete-variable-unresolved" not in rules(report)
    assert "delete-protected-root" in rules(report)
    assert {"/etc", "/work/cache"} <= targets(report)


def test_bug6c_unresolved_loop_list_does_not_become_a_concrete_target():
    report, _ = analyze('i=/etc; for i in $(ls); do rm -rf "$i"; done', evidence=False)
    assert "delete-protected-root" not in rules(report)
    assert "delete-variable-unresolved" in rules(report)


# 7. "TARGET=/etc; bash -c 'rm -rf \"$TARGET\"' reports a confirmed deletion of
#    /etc because every shell binding is copied into the child environment. A
#    plain assignment does not export TARGET."
def test_bug7_plain_assignment_is_not_exported_to_the_child_shell():
    report, _ = analyze("TARGET=/etc; bash -c 'rm -rf \"$TARGET\"'", evidence=False)
    assert "delete-protected-root" not in rules(report)
    assert "delete-variable-unresolved" in rules(report)


# 7b. Contrast case, already correct: an exported binding IS visible to the child.
def test_bug7b_exported_assignment_reaches_the_child_shell():
    report, _ = analyze("export TARGET=/etc; bash -c 'rm -rf \"$TARGET\"'", evidence=False)
    assert "delete-protected-root" in rules(report)


# 8. "For B.sh containing rm -rf \"$TARGET\", `TARGET=/tmp bash B.sh;
#    TARGET=/etc bash B.sh` analyses only the first invocation: the inspection
#    cache is keyed by path and language alone, hiding the second protected-root
#    deletion."
def test_bug8_invocations_with_different_bindings_are_both_analysed():
    report, _ = analyze("TARGET=/tmp bash B.sh; TARGET=/etc bash B.sh",
                        files={"/work/B.sh": 'rm -rf "$TARGET"\n'})
    assert "/tmp" in targets(report)
    assert "/etc" in targets(report)
    assert "delete-protected-root" in rules(report)


# 8b. The same cache key also hides a second invocation whose *cwd* differs: an
#     absolute script path resolves identically, but the relative references
#     inside it do not. The second `secrets` is never read.
def test_bug8b_invocations_from_different_cwd_are_both_analysed():
    report, provider = analyze("(cd a && bash /work/B.sh); (cd b && bash /work/B.sh)",
                               files={"/work/B.sh": "cat secrets\n",
                                      "/work/a/secrets": "password=aaa\n",
                                      "/work/b/secrets": "password=bbb\n"})
    assert StatTarget("/work/a/secrets") in provider.queries
    assert StatTarget("/work/b/secrets") in provider.queries
    assert read_paths(provider) == ["/work/B.sh"]
    assert len([f for f in report['findings'] if f['rule'] == 'ingestion-inspection-incomplete']) == 2


# 9. "readonly target=/etc; target=/tmp; rm -rf \"$target\" is reported as deleting
#    /tmp with no assignment-failure finding: a readonly declaration currently
#    becomes a plain assignment and the later write overwrites its value."
def test_bug9_readonly_declaration_rejects_the_later_assignment():
    report, _ = analyze("readonly target=/etc; target=/tmp; rm -rf \"$target\"", evidence=False)
    assert "readonly-assignment-failed" in rules(report)
    assert "/tmp" not in targets(report)
    # A standalone assignment error stops noninteractive Bash before rm.
    assert not any(rule.startswith("delete-") for rule in rules(report))


def test_bug9b_readonly_without_a_value_still_protects_the_binding():
    report, _ = analyze("target=/etc; readonly target; target=/tmp; rm -rf \"$target\"", evidence=False)
    assert "readonly-assignment-failed" in rules(report)
    assert "/tmp" not in targets(report)
    assert not any(rule.startswith("delete-") for rule in rules(report))


# 10. "A here-document overrides the actual executable source: `bash B.sh
#     <<'EOF' …` skips B.sh, and `bash -c '…' <<'EOF' …` skips the inline code.
#     Both can wrongly return {}."
def test_bug10_heredoc_does_not_replace_a_script_operand():
    report, provider = analyze("bash B.sh <<'EOF'\ntrue\nEOF", files={"/work/B.sh": "sudo reboot\n"})
    assert "privilege-escalation" in rules(report)
    assert "machine-power-change" in rules(report)
    assert "/work/B.sh" in read_paths(provider)


def test_bug10b_heredoc_does_not_replace_inline_code():
    report, _ = analyze("bash -c 'sudo reboot' <<'EOF'\ntrue\nEOF")
    assert "privilege-escalation" in rules(report)
    assert "machine-power-change" in rules(report)


# 11. "Here-document execution loses the uses-interpreter finding: a benign Bash
#     here-document returns {} instead of LOW."
def test_bug11_heredoc_program_still_reports_interpreter_use():
    report, _ = analyze("bash <<'EOF'\ntrue\nEOF")
    assert rules(report) == {"uses-interpreter"}


def test_bug11b_heredoc_program_reports_interpreter_use_with_its_effects():
    report, _ = analyze("bash <<'EOF'\nsudo reboot\nEOF")
    assert "uses-interpreter" in rules(report)
    assert "privilege-escalation" in rules(report)
    assert "machine-power-change" in rules(report)


# 12. "An attached sudo option (such as -uroot) stops wrapped-command analysis:
#     `sudo -uroot reboot` loses its reboot finding."
def test_bug12_attached_wrapper_option_value_keeps_the_command():
    report, _ = analyze("sudo -uroot reboot", evidence=False)
    assert "machine-power-change" in rules(report)
    assert "unknown-option" not in rules(report)
    assert "execution-content-unavailable" not in rules(report)


# 12b. The same attached-value form appears in an interpreter's own options.
def test_bug12b_attached_interpreter_option_value_keeps_the_script():
    report, provider = analyze("python -Wignore demo.py",
                               files={"/work/demo.py": "import os\nos.system('sudo true')\n"})
    assert "privilege-escalation" in rules(report)
    assert "unknown-option" not in rules(report)
    assert "/work/demo.py" in read_paths(provider)


def test_bug12c_attached_shell_option_value_keeps_the_script():
    report, provider = analyze("bash -oerrexit B.sh", files={"/work/B.sh": "sudo reboot\n"})
    assert "privilege-escalation" in rules(report)
    assert "unknown-option" not in rules(report)
    assert "/work/B.sh" in read_paths(provider)
