"""GCC/Clang output and uncertainty contracts; no compiler ever runs."""
import os
import subprocess

import pytest

from command_inspector import Analyzer, AnalyzerConfig
from command_inspector.local_evidence import MemoryEvidenceProvider, ReadFile, StatTarget


CWD = "/data/data/com.termux/files/home/project"
COMPILERS = ["gcc", "g++", "cc", "c++", "clang", "clang++"]


@pytest.fixture(autouse=True)
def no_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Compiler or submitted executable was run")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "system", forbidden)


def analyze(command, *, files=None, effort="Full", env=None, config=None):
    provider = MemoryEvidenceProvider(files if files is not None else {CWD + "/app.c": "int main(){return 0;}"})
    return Analyzer(config, evidence=provider).analyze_report(command, CWD, effort=effort, env=env), provider


@pytest.mark.parametrize("name", COMPILERS)
@pytest.mark.parametrize("tail", [
    "app.c -o app", "-Wall -Wextra -Werror -O2 -g -std=c11 app.c -oapp",
    "-c app.c", "-S app.c", "-E app.c", "-fsyntax-only app.c", "app.c",
    "-Iinclude -Llib -lm -DTEST=1 -UOLD -fPIC -shared app.c -o libapp.so",
    "-x c - -o app", "--sysroot=/data/data/com.termux/files/usr -target aarch64-linux-android app.c -o app",
    "-Wno-unused-parameter -fno-exceptions -fno-rtti -fsanitize=address app.c -o app",
])
def test_compiler_aliases_share_quiet_standard_models(name, tail):
    report, provider = analyze(name + " " + tail)
    assert report.to_dict() == {}
    if "-E " not in tail:
        assert all(isinstance(q, StatTarget) for q in provider.queries)


@pytest.mark.parametrize("name", COMPILERS)
@pytest.mark.parametrize("option", ["--version", "--help", "-dumpmachine", "-dumpversion", "-print-search-dirs"])
def test_compiler_queries_are_quiet_without_evidence(name, option):
    report, provider = analyze(name + " " + option)
    assert report.to_dict() == {} and provider.queries == []


@pytest.mark.parametrize("tail,path", [
    ("app.c", "a.out"), ("-c app.c", "app.o"), ("-S app.c", "app.s"),
    ("-c src/app.c", "app.o"), ("app.c -o build/app", "build/app"),
    ("-E app.c -o app.i", "app.i"), ("-c app.c -o app.o -MMD -MF app.d", "app.d"),
])
@pytest.mark.parametrize("effort", ["Full", "Partial", "None"])
def test_primary_and_dependency_outputs_follow_overwrite_effort(tail, path, effort):
    target = CWD + "/" + path
    report, provider = analyze("clang " + tail, files={target: "old"}, effort=effort)
    overwrite = [f for f in report.findings if f.rule == "overwrite-existing-file"]
    if effort == "None":
        assert overwrite == [] and provider.queries == []
    else:
        finding, = overwrite
        assert finding.data["target"] == target
        assert ("existing_bytes" in finding.data) is (effort == "Full")


@pytest.mark.parametrize("name", ["gcc", "clang"])
@pytest.mark.parametrize("tail", ["-o /etc/passwd app.c", "--output=/etc/passwd app.c", "-o/dev/block/by-name/system app.c", "-MF /etc/passwd -M app.c"])
def test_compiler_outputs_cannot_bypass_sensitive_write_checks(name, tail):
    report, _ = analyze(name + " " + tail, effort="None")
    assert {f.rule for f in report.findings} & {"modify-sensitive-file", "raw-device-write"}
    assert report.level.name in {"HIGH", "BLOCK"}


@pytest.mark.parametrize("tail", ["-fsyntax-only app.c -o old", "-E app.c", "-### app.c -o old"])
def test_no_output_modes_do_not_claim_file_writes(tail):
    report, provider = analyze("clang " + tail, files={CWD + "/old": "existing", CWD + "/app.c": "benign"})
    assert report.to_dict() == {}
    assert not any(isinstance(q, StatTarget) and q.path == CWD + "/old" for q in provider.queries)


@pytest.mark.parametrize("command", ["clang app.c -o $OUT", "clang -c $SRC"])
def test_unresolved_compiler_outputs_keep_variable_metadata(command):
    report, _ = analyze(command)
    assert "write-variable-unresolved" in {f.rule for f in report.findings}
    expected = ["OUT"] if "$OUT" in command else ["SRC"]
    assert next(f for f in report.findings if f.rule == "write-variable-unresolved").data["variables"] == expected


@pytest.mark.parametrize("tail", ["--invented app.c", "-fplugin=plugin.so app.c", "-Xclang -load app.c", "-specs custom.specs app.c", "@args.rsp", "-c app.c -MMD", "-c header.h", "-Btools app.c", "-Wl,-plugin,plugin.so app.c", "-Wa,--alternate app.c"])
def test_unmodeled_compiler_effects_invalidate_later_evidence(tail):
    report, provider = analyze("clang " + tail + "; bash later.sh", files={CWD + "/later.sh": "rm -rf /system"})
    assert "unresolved-value" in {f.rule for f in report.findings}
    assert "execution-content-unavailable" in {f.rule for f in report.findings}
    assert "delete-protected-root" not in {f.rule for f in report.findings}
    assert not any(isinstance(q, ReadFile) for q in provider.queries)


def test_known_primary_output_is_dirty_after_compilation():
    report, provider = analyze("clang app.c -o later.sh; bash later.sh", files={CWD + "/later.sh": "rm -rf /system"})
    assert "execution-content-unavailable" in {f.rule for f in report.findings}
    assert "delete-protected-root" not in {f.rule for f in report.findings}
    assert not any(isinstance(q, ReadFile) for q in provider.queries)


def test_source_content_is_not_treated_as_executed_code_or_ingestion():
    report, provider = analyze("clang app.c -o app", files={CWD + "/app.c": '/* password=abcdefghijk; rm -rf /system */'})
    assert report.to_dict() == {}
    assert not any(isinstance(q, ReadFile) for q in provider.queries)


def test_compiler_path_and_catalog_precedence():
    report, _ = analyze("/data/data/com.termux/files/usr/bin/clang app.c -o app", effort="None", config=AnalyzerConfig(known_tools={"clang": "compiler"}))
    assert [f.rule for f in report.findings] == ["command-via-path"]


def test_compiler_unknown_options_keep_identity_and_coverage():
    report, _ = analyze("clang --invented app.c")
    assert "unknown-option" in {f.rule for f in report.findings}
    assert "unknown-command" not in {f.rule for f in report.findings}


@pytest.mark.parametrize("command", ["clang -fsyntax-only app.c -MF ignored.d", "clang -E app.c -MF ignored.d", "clang -c app.c -MF ignored.d"])
def test_mf_without_dependency_generation_does_not_write_file(command):
    report, provider = analyze(command, files={CWD + "/ignored.d": "existing", CWD + "/app.c": "benign"})
    assert report.to_dict() == {}
    assert not any(isinstance(q, StatTarget) and q.path == CWD + "/ignored.d" for q in provider.queries)


@pytest.mark.parametrize("effort", ["Full", "Partial", "None"])
def test_compiler_preprocessing_keeps_text_ingestion_effort(effort):
    report, provider = analyze("clang -E app.c", files={CWD + "/app.c": "/* password=abcdefghijk */"}, effort=effort)
    assert ("credentials-read" in {f.rule for f in report.findings}) is (effort == "Full")
    assert any(isinstance(q, ReadFile) for q in provider.queries) is (effort == "Full")


def test_preprocessed_file_output_consumes_source_instead_of_ingesting_it():
    report, provider = analyze("clang -E app.c -o app.i", files={CWD + "/app.c": "/* password=abcdefghijk */"})
    assert report.to_dict() == {}
    assert not any(isinstance(q, ReadFile) for q in provider.queries)


def test_compile_globs_do_not_invent_literal_glob_outputs_or_use_stale_files():
    report, provider = analyze("clang -c *.c; bash later.sh", files={CWD + "/app.c": "benign", CWD + "/later.sh": "rm -rf /system"})
    assert "unresolved-value" in {f.rule for f in report.findings}
    assert "execution-content-unavailable" in {f.rule for f in report.findings}
    assert "delete-protected-root" not in {f.rule for f in report.findings}
    assert not any(isinstance(q, ReadFile) for q in provider.queries)
    assert not any(isinstance(q, StatTarget) and "*" in q.path for q in provider.queries)


def test_x_none_does_not_compile_an_object_file_into_another_object():
    report, provider = analyze("clang -x none -c app.o", files={CWD + "/app.o": "existing"})
    assert report.to_dict() == {}
    assert [q.path for q in provider.queries if isinstance(q, StatTarget)] == [CWD + "/app.o"]
