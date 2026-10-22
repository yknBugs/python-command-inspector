"""Literal pipeline programs and stdin precedence around wrappers."""
import pytest

from command_inspector import Analyzer, AnalyzerConfig
from command_inspector.local_evidence import MemoryEvidenceProvider, ReadFile


def analyze(command, files=None, config=None):
    provider = MemoryEvidenceProvider(files or {})
    report = Analyzer(config, evidence=provider).analyze_report(command, "/work", shell="bash")
    return report, provider


@pytest.mark.parametrize("command", [
    "echo 'rm -rf /*' | bash", "echo 'rm -rf /etc' | sh", "printf '%s\\n' 'rm -rf /etc' | bash -s",
    "printf 'rm -rf /etc\\n' | bash -", "echo 'rm -rf /etc' | sudo bash",
    "echo 'rm -rf /etc' | timeout 10 bash", "echo 'rm -rf /etc' | env -i bash",
    "echo 'rm -rf /etc' | env -C /tmp bash", "echo 'rm -rf /etc' | timeout 10 env -C /tmp bash",
    "echo 'rm -rf /etc' | bash -s ignored", "echo 'rm -rf /etc' | zsh",
])
def test_literal_pipeline_code_is_inspected(command):
    report, provider = analyze(command)
    assert report.level.name == "BLOCK"
    assert any(f.rule == "delete-protected-root" for f in report.findings)
    assert not any(isinstance(q, ReadFile) for q in provider.queries)


@pytest.mark.parametrize("command", [
    "cat input | bash", "echo 'rm -rf /etc' | sed 's/rm/echo/' | bash",
    "echo 'rm -rf /etc' > log | bash",
    "echo 'rm -rf /etc' | timeout 10 bash < input", "echo -e 'rm -rf /etc' | bash",
    "echo 'rm -rf /etc' | xargs -I {} bash",
])
def test_unknown_or_replaced_pipe_source_is_medium(command):
    report, _ = analyze(command)
    assert not any(f.rule == "delete-protected-root" for f in report.findings)
    assert any(f.rule == "execution-content-unavailable" for f in report.findings)
    assert report.level.name == "MEDIUM"


@pytest.mark.parametrize("command", [
    "echo 'rm -rf /etc' | bash -c true", "echo 'rm -rf /etc' | bash safe.sh",
    "echo 'rm -rf /etc' | timeout 10 bash safe.sh", "echo 'rm -rf /etc' | bash <<'EOF'\ntrue\nEOF",
    "echo 'rm -rf /etc' | timeout 10 bash <<'EOF'\ntrue\nEOF",
    "echo 'rm -rf /etc' | env -C /tmp bash <<'EOF'\ntrue\nEOF",
])
def test_explicit_program_or_heredoc_overrides_pipeline(command):
    report, _ = analyze(command, {"/work/safe.sh": "true"})
    assert not any(f.rule in {"delete-protected-root", "execution-content-unavailable"} for f in report.findings)


def test_wrapper_heredoc_preserves_working_directory_payload():
    report, _ = analyze("timeout 10 env -C /tmp bash <<'EOF'\nrm file\nEOF")
    deletion, = [f for f in report.findings if f.rule == "delete-outside-workspace"]
    assert deletion.data["target"] == "/tmp/file"


def test_literal_output_does_not_leak_into_substitution():
    report, _ = analyze("echo 'rm -rf /etc' | echo $(bash)")
    assert not any(f.rule == "delete-protected-root" for f in report.findings)


def test_literal_pipe_obeys_inspection_budget():
    report, _ = analyze("echo 'rm -rf /etc' | timeout 1 bash", config=AnalyzerConfig(inline_depth=1))
    assert not any(f.rule == "delete-protected-root" for f in report.findings)
    assert any(f.rule == "unreadable-payload" for f in report.findings)


def test_clear_environment_keeps_new_assignments_and_drops_inherited_values():
    report, _ = analyze("export TARGET=/etc; echo 'rm -rf \"$TARGET\"' | env -i TARGET=/tmp bash")
    assert not any(f.rule == "delete-protected-root" for f in report.findings)
    assert any(f.rule == "delete-outside-workspace" and f.data["target"] == "/tmp" for f in report.findings)


def test_final_heredoc_does_not_override_earlier_pipeline_program():
    report, _ = analyze("echo 'rm -rf /etc' | bash | bash <<'EOF'\ntrue\nEOF")
    assert any(f.rule == "delete-protected-root" for f in report.findings)


def test_conda_wrapper_preserves_stdin_source():
    report, _ = analyze("echo 'rm -rf /etc' | conda run -n demo bash")
    assert any(f.rule == "delete-protected-root" for f in report.findings)
