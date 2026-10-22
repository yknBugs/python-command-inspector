"""Discard destinations, write exemptions, clone downloads and su programs."""
import os
import subprocess

import pytest

from command_inspector import Analyzer, AnalyzerConfig
from command_inspector.config import load_config
from command_inspector.local_evidence import MemoryEvidenceProvider, ReadFile, StatTarget
from command_inspector.models import ConfigurationError


@pytest.fixture(autouse=True)
def forbid_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Analysis executed a proposed command")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "system", forbidden)


def analyze(command, shell="bash", *, cwd=None, env=None, config=None, files=None):
    cwd = cwd or ("/work" if shell == "bash" else r"C:\work")
    provider = MemoryEvidenceProvider(files or {})
    report = Analyzer(config, evidence=provider).analyze_report(command, cwd, shell=shell, env=env)
    return report, provider


def entries(report, rule):
    return [f for f in report.findings if f.rule == rule]


@pytest.mark.parametrize("shell", ["bash", "powershell", "cmd"])
@pytest.mark.parametrize("repository", ["https://example.invalid/org/repo.git", "http://example.invalid/repo.git",
    "ssh://git@example.invalid/org/repo.git", "git://example.invalid/org/repo.git", "git@example.invalid:org/repo.git",
    "example.invalid:org/repo.git"])
def test_remote_git_clone_downloads_with_concrete_destination(shell, repository):
    report, provider = analyze("git clone " + repository, shell)
    download, = entries(report, "download-content")
    assert download.level.name == "MEDIUM"
    assert download.data["repository"] == repository
    assert download.data["download_target"] == ("/work/repo" if shell == "bash" else r"C:\work\repo")
    assert not entries(report, "unknown-command")
    assert provider.queries == []


@pytest.mark.parametrize("option", ["--depth 1", "--depth=1", "-b main", "--branch=main", "-qv", "--no-checkout",
    "--single-branch", "--filter=blob:none", "--recurse-submodules=lib/*", "-j4", "--reference ../cache", "--origin upstream"])
def test_clone_options_bind_repository_correctly(option):
    report, _ = analyze(f"git clone {option} https://example.invalid/repo.git custom")
    download, = entries(report, "download-content")
    assert download.data["repository"] == "https://example.invalid/repo.git"
    assert download.data["download_target"] == "/work/custom"
    assert not entries(report, "unknown-option")


@pytest.mark.parametrize("shell,repository", [("bash", "./source"), ("bash", "file:///work/source"),
    ("bash", "./foo:bar"), ("cmd", r"C:\work\source"), ("powershell", "file:///C:/work/source")])
def test_local_git_clone_is_not_network_download(shell, repository):
    report, _ = analyze("git clone " + repository + " local", shell)
    assert not entries(report, "download-content")
    assert not entries(report, "network-request")
    assert not entries(report, "unknown-command")


@pytest.mark.parametrize("options,destination", [("--bare", "/work/repo.git"), ("--mirror", "/work/repo.git"), ("", "/work/repo")])
def test_clone_default_bare_directory(options, destination):
    report, _ = analyze(f"git clone {options} https://example.invalid/org/repo.git/")
    assert entries(report, "download-content")[0].data["download_target"] == destination


@pytest.mark.parametrize("shell,command,target", [
    ("bash", "git -C /outside clone https://example.invalid/repo.git", "/outside/repo"),
    ("bash", "git -C /outside -C child clone https://example.invalid/repo.git", "/outside/child/repo"),
    ("bash", "git -C/outside clone https://example.invalid/repo.git", "/outside/repo"),
    ("cmd", r"git -C C:\outside clone https://example.invalid/repo.git", r"C:\outside\repo"),
    ("powershell", r"git clone https://example.invalid/repo.git C:\outside\repo", r"C:\outside\repo"),
])
def test_clone_directory_overrides_are_concrete(shell, command, target):
    report, _ = analyze(command, shell)
    assert entries(report, "download-content")[0].data["download_target"] == target
    assert entries(report, "write-outside-workspace")[0].data["target"] == target


def test_clone_separate_git_directory_is_a_visible_write():
    report, _ = analyze("git clone --separate-git-dir=/outside/git-dir https://example.invalid/repo.git")
    assert entries(report, "write-outside-workspace")[0].data["target"] == "/outside/git-dir"


@pytest.mark.parametrize("shell,command,target", [
    ("bash", "git clone https://example.invalid/repo.git; bash repo/run.sh", "/work/repo/run.sh"),
    ("powershell", "git clone https://example.invalid/repo.git; pwsh -File repo/run.ps1", r"C:\work\repo\run.ps1"),
    ("cmd", r"git clone https://example.invalid/repo.git & repo\run.cmd", r"C:\work\repo\run.cmd"),
])
def test_clone_invalidates_preexisting_destination_source(shell, command, target):
    report, provider = analyze(command, shell, files={target: "echo old"})
    assert entries(report, "execution-content-unavailable")[0].data["reason"] == "changed_earlier"
    assert not any(isinstance(q, ReadFile) for q in provider.queries)


def test_clone_preserves_distinct_download_operations_and_credentials():
    report, _ = analyze("git clone https://example.invalid/a.git; git clone https://example.invalid/b.git")
    assert len(entries(report, "download-content")) == 2
    report, _ = analyze("git clone https://user:secret@example.invalid/repo.git")
    assert entries(report, "credentials-sent")[0].level.name == "HIGH"
    assert "user:secret" not in str(report.to_dict())


def test_clone_unknown_options_and_dynamic_sources_remain_visible():
    report, _ = analyze("git clone --invented https://example.invalid/repo.git")
    assert entries(report, "unknown-option")
    assert entries(report, "unresolved-value")
    report, _ = analyze("git clone \"$REPOSITORY\" \"$DEST\"")
    assert entries(report, "download-content")[0].data["source_resolved"] is False
    assert entries(report, "download-content")[0].data["download_target"] is None
    assert any({"REPOSITORY", "DEST"} <= set(f.data["variables"]) for f in entries(report, "unresolved-value"))


@pytest.mark.parametrize("command", ["git clone --help", "git clone -h", "git --help clone"])
def test_clone_help_has_no_effect(command):
    assert analyze(command)[0].to_dict() == {}


def test_clone_bundle_uri_models_additional_network_download():
    report, _ = analyze("git clone --bundle-uri=https://example.invalid/bundle ./source local")
    download, = entries(report, "download-content")
    assert download.data["bundle_uri"] is True
    assert download.data["repository"] == "https://example.invalid/bundle"

