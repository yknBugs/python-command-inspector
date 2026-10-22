"""File inspection and scoped Bash termination without executing commands."""
import os
import subprocess
import pytest
from command_inspector import Analyzer
from command_inspector.local_evidence import MemoryEvidenceProvider, ReadFile


@pytest.fixture(autouse=True)
def no_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('Submitted command was executed')
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    monkeypatch.setattr(os, 'system', forbidden)


def analyze(command, effort='full'):
    provider=MemoryEvidenceProvider({'/work/input':b'password=private-example\n','/outside/input':b'hello'})
    return Analyzer(evidence=provider).analyze(command,'/work',shell='bash',effort=effort),provider


def rules(report):
    return {f['rule'] for f in report.get('findings',[])}


@pytest.mark.parametrize('command', [
    'stat input','stat -c %s input','stat --format=%a input','stat --printf="%s\\n" input',
    'stat -f -t input','stat -L --cached=always input','stat -- --name','stat -',
    'stat --help','stat --version',
    'file input','file -b input','file -bi input','file --mime-type input',
    'file --mime-encoding input','file -L -k --extension input','file -h input',
    'file -0 -N -F : input','file -P bytes=4096 input','file -e ascii input',
    'file --exclude-quiet=ascii input','file -m magic:other input',
    'file -- -name','file -','file --help','file -v',
])
@pytest.mark.parametrize('effort',['full','partial','none'])
def test_metadata_output_is_quiet_and_does_not_ingest_secrets(command, effort):
    report,provider=analyze(command,effort)
    assert report=={}
    assert not any(isinstance(q,ReadFile) for q in provider.queries)


@pytest.mark.parametrize('command', ['stat /outside/input','file /outside/input','stat -c %s /outside/input','file -b /outside/input'])
def test_outside_workspace_read(command):
    report,_=analyze(command)
    assert rules(report)=={'read-outside-workspace'}


@pytest.mark.parametrize('command', ['stat','file','stat --unknown input','file --unknown input','stat -c','file -m','stat "$MISSING"','file "$MISSING"'])
def test_invalid_or_unknown_forms_are_not_silent(command):
    assert rules(analyze(command)[0]) & {'unknown-option','unresolved-value'}


@pytest.mark.parametrize('command', ['file -f paths.txt','file --files-from=-'])
def test_filename_lists_remain_unresolved(command):
    assert 'unresolved-value' in rules(analyze(command)[0])


def test_compile_is_not_classified_as_only_reading():
    report,_=analyze('file -C -m magic; python input')
    assert 'file-operation-unresolved' in rules(report)
    assert 'execution-content-unavailable' in rules(report)


@pytest.mark.parametrize('command',['file -z input','file -Z input','file --uncompress input'])
def test_decompression_coverage_is_explicit(command):
    assert 'execution-content-unavailable' in rules(analyze(command)[0])


def test_format_and_separator_are_not_paths():
    assert analyze("stat -c /outside/format input")[0]=={}
    assert analyze("file -F /outside/separator input")[0]=={}


@pytest.mark.parametrize('prefix', ['exit','exit 0','exit 1','exit -1','exit -- 0','exit invalid','{ exit 0; }'])
def test_unconditional_exit_stops_following_command(prefix):
    assert analyze(prefix+'; rm -rf /etc')[0]=={}


@pytest.mark.parametrize('prefix', [
    '(exit 0)', 'exit 0 | cat', 'false && exit 1', 'true || exit 0',
    'if test -f x; then exit 0; fi', 'exit 1 2', 'exit "$MISSING"',
    'exit --help', 'echo "$(exit 0)"',
])
def test_exit_does_not_suppress_other_scopes_or_uncertain_branches(prefix):
    assert 'delete-protected-root' in rules(analyze(prefix+'; rm -rf /etc')[0])


@pytest.mark.parametrize('command', ['exit 0 & rm -rf /etc', '{ exit 0 & rm -rf /etc; }'])
def test_background_exit_does_not_stop_parent(command):
    assert 'delete-protected-root' in rules(analyze(command)[0])


def test_exit_stops_own_subshell_only():
    report,_=analyze('(exit 0; rm -rf /etc); stat input')
    assert report=={}


def test_exit_redirect_still_has_its_effect():
    assert 'write-outside-workspace' in rules(analyze('exit 0 > /outside/log; rm -rf /etc')[0])
    assert 'delete-protected-root' not in rules(analyze('exit 0 > /outside/log; rm -rf /etc')[0])


@pytest.mark.parametrize('command', ['file -s /dev/sda','file --special-files /dev/nvme0n1'])
def test_file_special_device_content_probe(command):
    report,provider=analyze(command)
    assert 'raw-device-read' in rules(report)
    assert not any(isinstance(q,ReadFile) for q in provider.queries)


@pytest.mark.parametrize('command', ['file /dev/sda','stat /dev/sda'])
def test_device_metadata_is_not_raw_content_ingestion(command):
    assert 'raw-device-read' not in rules(analyze(command)[0])
