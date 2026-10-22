"""Order-independent Python review regressions; never execute submitted code."""
import pytest
from command_inspector import Analyzer
from command_inspector.local_evidence import MemoryEvidenceProvider, ReadFile


def check(source, *, files=None, cwd='/work', effort='Full'):
    provider = MemoryEvidenceProvider(files or {})
    report = Analyzer(evidence=provider).analyze_report(source, cwd, shell='python', effort=effort)
    return report, provider


def rules(report):
    return {f.rule for f in report.findings}


@pytest.mark.parametrize('mutation', ["paths[0]='/etc'", "paths[:]=['/etc']", "paths.append('/etc')", "paths.extend(['/etc'])", "del paths[0]", "alias=paths; alias[0]='/etc'", "alias=paths; other=alias; other.clear()"])
@pytest.mark.parametrize('reverse', [False, True])
def test_container_mutations_never_retain_safe_literal_elements(mutation, reverse):
    effect = 'shutil.rmtree(paths[0])'
    body = [mutation, effect] if not reverse else [effect, mutation]
    report, _ = check("import shutil; paths=['cache']; " + '; '.join(body), effort='None')
    assert 'delete-inside-workspace' not in rules(report)
    assert 'unresolved-value' in rules(report)


def test_unchanged_sequence_stays_concrete():
    report, _ = check("import shutil; paths=['cache']; shutil.rmtree(paths[0])", effort='None')
    assert 'delete-inside-workspace' in rules(report)
    assert 'unresolved-value' not in rules(report)


@pytest.mark.parametrize('evaluator', ['exec', 'eval'])
@pytest.mark.parametrize('namespace', ["{'os':os, 'p':'/etc/passwd'}", "{}, {'os':os, 'p':'/etc/passwd'}", "None, {'os':os, 'p':'/etc/passwd'}"])
def test_explicit_evaluation_namespace_replaces_caller_path(evaluator, namespace):
    report, _ = check(f"import os; p='cache'; {evaluator}('os.remove(p)', {namespace})", effort='None')
    assert 'delete-outside-workspace' in rules(report)
    assert 'delete-inside-workspace' not in rules(report)


@pytest.mark.parametrize('evaluator', ['exec', 'eval'])
def test_unknown_evaluation_namespace_cannot_borrow_caller_path(evaluator):
    report, _ = check(f"import os; p='cache'; {evaluator}('os.remove(p)', namespace)", effort='None')
    assert 'execution-content-unavailable' in rules(report)
    assert 'delete-inside-workspace' not in rules(report)


def test_file_evaluation_uses_explicit_namespace():
    report, _ = check("import os; p='cache'; exec(open('code').read(), {'os':os, 'p':'/etc/passwd'})",
                      files={'/work/code': 'os.remove(p)'})
    assert 'delete-outside-workspace' in rules(report)
    assert 'delete-inside-workspace' not in rules(report)


def test_explicit_locals_keep_global_import_alias():
    report, _ = check("import os as o; exec('o.remove(p)', None, {'p':'/etc/passwd'})", effort='None')
    assert 'delete-outside-workspace' in rules(report)


@pytest.mark.parametrize('operation', ["os.unlink('passwd', dir_fd=fd)", "os.remove('passwd', dir_fd=fd)", "shutil.rmtree('cache', dir_fd=fd)", "os.rename('a','b',src_dir_fd=fd)", "os.replace('a','b',dst_dir_fd=fd)"])
def test_directory_descriptor_does_not_invent_workspace_targets(operation):
    report, _ = check('import os, shutil; ' + operation, effort='None')
    assert 'file-operation-unresolved' in rules(report)
    assert 'delete-inside-workspace' not in rules(report)
    assert not any(f.data.get('target', '').startswith('/work/') for f in report.findings)


@pytest.mark.parametrize('source,rule', [("os.unlink('/etc/passwd',dir_fd=fd)", 'delete-outside-workspace'), ("os.unlink('cache',dir_fd=None)", 'delete-inside-workspace')])
def test_absolute_and_none_descriptor_paths_remain_concrete(source, rule):
    report, _ = check('import os; ' + source, effort='None')
    assert rule in rules(report)


@pytest.mark.parametrize('effort', ['Full', 'Partial', 'None'])
def test_windows_command_string_is_execution_uncertainty_not_filename(effort):
    report, _ = check(r"import subprocess; subprocess.run(r'cmd /c rd /s /q C:\Windows')", cwd=r'C:\work', effort=effort)
    assert 'execution-content-unavailable' in rules(report)
    assert 'executable-via-path' not in rules(report)


def test_windows_explicit_argv_still_inspects_cmd():
    report, _ = check(r"import subprocess; subprocess.run(['cmd','/c',r'rd /s /q C:\Windows'])", cwd=r'C:\work', effort='None')
    assert 'delete-protected-root' in rules(report)


@pytest.mark.parametrize('position_effect', ['f.seek(100)', 'f.read(100)', 'next(f)', 'for line in f: pass'])
@pytest.mark.parametrize('reverse', [False, True])
def test_position_dependent_read_does_not_claim_prefix_selection(position_effect, reverse):
    operations = [position_effect, 'print(f.read(32))']
    if reverse:
        operations.reverse()
    source = "f=open('data')\n" + '\n'.join(operations)
    report, _ = check(source, files={'/work/data': 'x'*100 + '\npassword=abcdefghijk\n'})
    assert 'credentials-read' in rules(report)
    assert next(f for f in report.findings if f.rule == 'credentials-read').data['selection'] == 'conservative'


def test_single_bounded_read_still_has_precise_window():
    report, _ = check("print(open('data').read(32))", files={'/work/data': 'x'*100+'password=abcdefghijk'})
    assert report.to_dict() == {}


@pytest.mark.parametrize('called', [False, True])
def test_dormant_call_chain_keeps_definition_context(called):
    source = "import os\ndef helper(): os.remove('data')\ndef outer(): helper()\n"
    source += 'outer()\n' if called else ''
    source += "print(open('data').read())"
    report, provider = check(source, files={'/work/data': 'password=abcdefghijk'})
    assert ('credentials-read' in rules(report)) == (not called)
    assert ('ingestion-inspection-incomplete' in rules(report)) == called
    deletion = next(f for f in report.findings if f.rule == 'delete-inside-workspace')
    assert deletion.data['context'] == ('invoked_now' if called else 'defined_body')
    assert bool([q for q in provider.queries if isinstance(q, ReadFile)]) == (not called)


@pytest.mark.parametrize('consumer', ["exec(f.read())", "eval(f.read())", "os.system(f.read())", "subprocess.run(['python','-'], stdin=f)", "subprocess.run(['python','-'], input=f.read(), text=True)"])
def test_position_dependent_code_stream_does_not_execute_whole_file_evidence(consumer):
    report, _ = check("import os, subprocess\nf=open('code')\nf.seek(100)\n" + consumer,
                      files={'/work/code': "import shutil; shutil.rmtree('/etc')"})
    assert 'execution-content-unavailable' in rules(report)
    assert 'delete-protected-root' not in rules(report)
