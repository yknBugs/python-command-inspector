"""Policy regressions analyze text only, including Windows calls on Linux."""
import json
import pytest
from command_inspector import Analyzer, AnalyzerConfig
from command_inspector.local_evidence import DisabledEvidenceProvider, MemoryEvidenceProvider
from command_inspector.python.semantics import PythonBuilder


SHELLS = ["bash", "powershell", "cmd"]


def analyze(command, shell="bash", *, env=None, config=None, provider=None):
    return Analyzer(config, evidence=provider or DisabledEvidenceProvider()).analyze_report(
        command, "/work" if shell == "bash" else r"D:\work", shell=shell, env=env)


def one(report, rule, level):
    matches = [f for f in report.findings if f.rule == rule]
    assert len(matches) == 1, report.to_dict()
    assert matches[0].level.name == level
    return matches[0]


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("command", [
    "git push --force origin main", "git push -vf origin main",
    'git push "--force-with-lease=main:abc" origin main',
    "git push --force-with-lease --force-if-includes origin main",
    "git push origin --delete release", "git push -d origin release",
    "git push origin :release", "git push origin +main:main",
    "git push --mirror", "git push --prune origin",
    "git -C repo push -f", "git -c user.name=Example push -f origin main",
    'git "--git-dir=repo/.git" push --force', "git push --no-force --force origin main",
])
def test_remote_history_changes_are_high(shell, command):
    result = analyze(command, shell)
    assert result.num_findings == 1
    assert one(result, "git-history-rewrite", "HIGH").data["history_scope"] == "remote"


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("command", [
    "git push", "git push origin main", "git push --force-if-includes origin main",
    "git push -o --force origin main", "git push --force --no-force origin main",
    "git push --force-with-lease --no-force-with-lease origin main",
    "git -C repo -c user.name=Example push origin main",
])
def test_ordinary_publication_keeps_git_push_medium(shell, command):
    result = analyze(command, shell)
    one(result, "git-push", "MEDIUM")
    assert result.num_findings == 1


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("command", ["git push --dry-run --force", "git push -nvf origin main",
                                         "git push --help", "git --help push", "git config --help"])
def test_git_help_and_dry_run_do_not_mutate(shell, command):
    assert analyze(command, shell).to_dict() == {}


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("args,level,scope,importance", [
    ("user.name Example", "MEDIUM", "local", "important"),
    ("--global user.name Example", "HIGH", "global", "important"),
    ("--system user.email example@example.invalid", "HIGH", "system", "important"),
    ("--local core.fileMode false", "LOW", "local", "minor"),
    ("--global core.fileMode false", "MEDIUM", "global", "minor"),
    ("i18n.commitEncoding UTF-8", "LOW", "local", "minor"),
    ("--global i18n.logOutputEncoding UTF-8", "MEDIUM", "global", "minor"),
    ("--worktree core.autocrlf false", "LOW", "worktree", "minor"),
    ("color.ui auto", "LOW", "local", "minor"),
    ("credential.helper store", "HIGH", "local", "sensitive"),
    ("--global credential.helper store", "HIGH", "global", "sensitive"),
    ("http.sslVerify false", "HIGH", "local", "sensitive"),
    ("core.hooksPath hooks", "HIGH", "local", "sensitive"),
    ("--global url.https://example.invalid/.insteadOf https://github.com/", "HIGH", "global", "important"),
    ("set --global user.name Example", "HIGH", "global", "important"),
    ("--global set core.fileMode false", "MEDIUM", "global", "minor"),
    ("--unset core.fileMode", "LOW", "local", "minor"),
    ("unset --global credential.helper", "HIGH", "global", "sensitive"),
    ("--file arbitrary.config user.name Example", "HIGH", "file", "important"),
    ("--global --edit", "HIGH", "global", "important"),
    ("user.name get", "MEDIUM", "local", "important"),
    ("--remove-section credential", "HIGH", "local", "sensitive"),
    ("set remote.origin.url https://user:password@example.invalid/", "HIGH", "local", "sensitive"),
])
def test_git_config_scope_and_importance(shell, args, level, scope, importance):
    result = analyze("git config " + args, shell)
    config = one(result, "git-config-modified", level)
    assert config.data["scope"] == scope
    assert config.data["importance"] == importance
    assert "Example" not in json.dumps(config.to_dict())


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("args", ["user.name", "--global user.name", "--get credential.helper",
                                  "--get-regexp user", "--get-urlmatch http https://example.invalid",
                                  "--list --global", "get --global user.name", "list --show-origin"])
def test_git_config_queries_are_quiet(shell, args):
    assert analyze("git config " + args, shell).to_dict() == {}


def test_filter_branch_describes_local_history_and_does_not_run_filter():
    result = analyze("git filter-branch --tree-filter 'rm -rf /' HEAD")
    assert result.num_findings == 1
    assert one(result, "git-history-rewrite", "HIGH").data["history_scope"] == "local"


def test_git_config_supplied_file_override_has_unknown_broad_scope():
    finding = one(analyze("git config user.name Example", env={"GIT_CONFIG": "/global/config"}), "git-config-modified", "HIGH")
    assert finding.data["scope"] == "file"


def test_git_config_environment_name_is_case_sensitive_in_bash():
    finding = one(analyze("git config user.name Example", env={"git_config": "/config"}), "git-config-modified", "MEDIUM")
    assert finding.data["scope"] == "local"


@pytest.mark.parametrize("prefix,level", [("GIT_CONFIG=/config; ", "MEDIUM"),
                                          ("GIT_CONFIG=/config ", "HIGH"),
                                          ("export GIT_CONFIG=/config; ", "HIGH")])
def test_git_config_override_uses_child_environment(prefix, level):
    finding = one(analyze(prefix + "git config user.name Example"), "git-config-modified", level)
    assert finding.data["scope"] == ("file" if level == "HIGH" else "local")

