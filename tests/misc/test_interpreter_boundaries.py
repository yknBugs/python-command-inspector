"""Executable-source selection and option binding around the reviewed fixes."""
import pytest

from command_inspector import Analyzer
from command_inspector.local_evidence import MemoryEvidenceProvider, ReadFile


def analyze(command, files=None):
    provider = MemoryEvidenceProvider(files or {})
    result = Analyzer(evidence=provider).analyze(command, "/work", shell="bash")
    return {f["rule"] for f in result.get("findings", [])}, provider


@pytest.mark.parametrize("command", [
    "bash -s ignored <<'EOF'\nsudo reboot\nEOF",
    "bash -s -- ignored <<'EOF'\nsudo reboot\nEOF",
    "bash - <<'EOF'\nsudo reboot\nEOF",
    "sudo bash <<'EOF'\nsudo reboot\nEOF",
    "env TARGET=/etc bash <<'EOF'\nsudo reboot\nEOF",
    "bash > log <<'EOF'\nsudo reboot\nEOF",
    "bash <<'EOF' > log\nsudo reboot\nEOF",
])
def test_literal_stdin_program_is_inspected(command):
    emitted, provider = analyze(command)
    assert {"uses-interpreter", "privilege-escalation", "machine-power-change"} <= emitted
    assert not any(isinstance(q, ReadFile) for q in provider.queries)


@pytest.mark.parametrize("command", [
    "bash B.sh <<'EOF'\nsudo reboot\nEOF",
    "bash -c true <<'EOF'\nsudo reboot\nEOF",
    "python -c pass <<'EOF'\nsudo reboot\nEOF",
])
def test_program_input_is_not_treated_as_executable_source(command):
    emitted, _ = analyze(command, {"/work/B.sh": "true"})
    assert "uses-interpreter" in emitted
    assert "privilege-escalation" not in emitted
    assert "machine-power-change" not in emitted


def test_heredoc_source_preserves_full_until_first_file_read():
    emitted, provider = analyze("bash <<'EOF'\nsudo python A.py\nEOF", {"/work/A.py": "import os; os.system('reboot')"})
    assert emitted == {"privilege-escalation", "uses-interpreter", "machine-power-change"}
    assert provider.queries == [ReadFile("/work/A.py", 524288)]


def test_wrapped_heredoc_preserves_child_environment():
    emitted, _ = analyze("env TARGET=/etc bash <<'EOF'\nrm -rf \"$TARGET\"\nEOF")
    assert "delete-protected-root" in emitted


def test_later_stdin_redirection_does_not_execute_replaced_heredoc():
    emitted, _ = analyze("bash <<'EOF' < input\nsudo reboot\nEOF", {"/work/input": "true"})
    assert "privilege-escalation" not in emitted
    assert "machine-power-change" not in emitted
    assert "execution-content-unavailable" not in emitted


def test_later_heredoc_replaces_earlier_stdin_redirection():
    emitted, _ = analyze("bash < input <<'EOF'\nsudo reboot\nEOF", {"/work/input": "true"})
    assert "privilege-escalation" in emitted
    assert "machine-power-change" in emitted


def test_heredoc_on_stderr_is_not_executable_stdin():
    emitted, _ = analyze("bash 2<<'EOF'\nsudo reboot\nEOF")
    assert "privilege-escalation" not in emitted
    assert "machine-power-change" not in emitted


@pytest.mark.parametrize("command", [
    "sudo -uroot reboot", "sudo -nuroot reboot", "sudo --user=root reboot",
    "sudo -nu root reboot", "sudo -- reboot",
])
def test_wrapper_value_and_cluster_keep_command_binding(command):
    emitted, _ = analyze(command)
    assert emitted == {"privilege-escalation", "machine-power-change"}


@pytest.mark.parametrize("command", [
    "bash -eu B.sh", "bash -eoerrexit B.sh", "bash +o errexit B.sh",
    "python -BWignore demo.py", "python -Wignore demo.py",
])
def test_interpreter_clusters_keep_script_binding(command):
    emitted, provider = analyze(command, {"/work/B.sh": "sudo reboot", "/work/demo.py": "import os; os.system('sudo reboot')"})
    assert {"uses-interpreter", "privilege-escalation", "machine-power-change"} <= emitted
    assert "unknown-option" not in emitted
    assert len([q for q in provider.queries if isinstance(q, ReadFile)]) == 1


@pytest.mark.parametrize("command", ["sudo -u", "sudo -nu", "python -W", "bash -o"])
def test_missing_required_option_value_stays_visible(command):
    emitted, provider = analyze(command)
    assert "unknown-option" in emitted
    assert "execution-content-unavailable" in emitted
    assert provider.queries == []


def test_python_attached_inline_code_is_inspected():
    emitted, _ = analyze('python -c"import os; os.system(\'sudo reboot\')"')
    assert {"uses-interpreter", "privilege-escalation", "machine-power-change"} <= emitted
