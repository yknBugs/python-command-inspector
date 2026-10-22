"""The Python AST layer is independent of evidence and execution policies."""
import ast
import builtins
import shlex
import subprocess
import warnings

import pytest

from command_inspector import Analyzer
from command_inspector.local_evidence import DisabledEvidenceProvider, MemoryEvidenceProvider, ReadFile, StatTarget
from command_inspector.paths import PathStyle
from command_inspector.python.semantics import PythonBuilder
from command_inspector.python.syntax import PythonFrontend
from command_inspector.bash.syntax import ParseBudgetExceeded


def facts(source, *, context="invoked_now", cwd="/work", paths=None, env=None):
    parsed = PythonFrontend().parse(source)
    assert not parsed.diagnostics
    return PythonBuilder(cwd, env or {}, source="source.py", context=context, paths=paths).build(parsed.root)


def analyze(source, *, files=None, config=None):
    provider = MemoryEvidenceProvider(files) if files is not None else DisabledEvidenceProvider()
    command = shlex.join(["python", "-c", source])
    result = Analyzer(config, evidence=provider).analyze_report(command, "/work", shell="bash")
    return result, provider


def test_python_frontend_parses_without_exposing_source_in_repr():
    source = 'secret = "password=private-value"\nprint("文字")'
    parsed = PythonFrontend().parse(source)
    assert isinstance(parsed.root, ast.Module)
    assert parsed.backend == 'python-ast'
    assert not parsed.diagnostics
    assert 'private-value' not in repr(parsed)


@pytest.mark.parametrize('source', ['def broken(:', 'a=\x00', 'x = (' * 300])
def test_python_frontend_has_explicit_parse_diagnostics(source):
    parsed = PythonFrontend().parse(source)
    assert parsed.root is None
    assert parsed.diagnostics


def test_python_frontend_bounds_ast_nodes():
    with pytest.raises(ParseBudgetExceeded):
        PythonFrontend().parse('print("hello")', max_nodes=2)


def test_python_parser_does_not_deliver_source_warnings():
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter('always')
        PythonFrontend().parse('1 is 1')
    assert not caught


@pytest.mark.parametrize('call,recursive', [
    ("shutil.rmtree('/etc')", True), ("os.removedirs('/etc')", False),
    ("os.rmdir('/etc')", False), ("os.remove(path='/etc/a')", False),
    ("os.unlink('/etc/a')", False),
])
def test_python_filesystem_facts(call, recursive):
    (fact,) = facts(call)
    assert fact.kind == 'delete'
    assert bool(fact.flags & {'-r', '-R'}) is recursive
    assert fact.flags & {'unconditional'}
    assert fact.source == 'source.py'
    assert fact.cwd == '/work'


@pytest.mark.parametrize('source,payload', [
    ("os.truncate('/etc/passwd', 0)", ''),
    ("os.truncate(path='/etc/passwd', length=1)", None),
])
def test_truncate_remains_a_write_fact(source, payload):
    (fact,) = facts(source)
    assert (fact.kind, fact.operation, fact.targets, fact.payload) == ('write', 'overwrite', ('/etc/passwd',), payload)


def test_python_builder_uses_explicit_windows_path_rules():
    (fact,) = facts("os.remove('folder/file')", cwd=r'D:\work', paths=PathStyle(True))
    assert fact.targets == (r'D:\work\folder\file',)


@pytest.mark.parametrize('call,payload', [
    ("os.system('sudo true')", 'sudo true'),
    ("subprocess.run(['sudo','true'])", 'sudo true'),
    ("subprocess.call(args=('sudo','true'))", 'sudo true'),
    ("subprocess.Popen('sudo true', shell=True)", 'sudo true'),
    ("subprocess.run(['sudo true','ignored'], shell=True)", 'sudo true'),
    ("subprocess.run('sudo true', shell=False)", "'sudo true'"),
])
def test_python_subprocess_facts_preserve_shell_and_argv_roles(call, payload):
    (fact,) = facts(call, env={'TARGET': '/etc'})
    if call.startswith('os.system') or 'shell=True' in call:
        assert (fact.kind, fact.operation, fact.payload) == ('inline', 'shell', payload)
    else:
        assert fact.kind == 'invoke'
        expected = ['sudo true'] if "'sudo true'" in call else ['sudo', 'true']
        assert [fact.operation, *(v.text for v in fact.values)] == expected
    assert fact.source == 'source.py:subprocess'
    assert dict(fact.bindings) == {'TARGET': '/etc'}


@pytest.mark.parametrize('call,rule', [
    ('subprocess.run(command)', 'unresolved-value'),
    ("subprocess.run('sudo true', shell=dynamic)", 'unresolved-value'),
    ('os.remove(target)', 'unresolved-value'),
    ('eval(expression)', 'execution-content-unavailable'),
    ('exec(expression)', 'execution-content-unavailable'),
])
def test_python_dynamic_operations_remain_unresolved(call, rule):
    fact, *effects = facts(call)
    assert (fact.kind, fact.operation) == ('unresolved', rule)
    if call == 'os.remove(target)':
        assert len(effects) == 1 and effects[0].kind == 'delete'
    else:
        assert not effects


@pytest.mark.parametrize('definition', [
    "def task():\n    os.system('sudo true')",
    "async def task():\n    os.system('sudo true')",
    "task = lambda: os.system('sudo true')",
])
def test_python_defined_bodies_are_labeled(definition):
    (invoked,) = facts(definition, context='direct_artifact')
    (written,) = facts(definition, context='written_content')
    assert invoked.context == 'defined_body'
    assert written.context == 'written_content'


def test_python_layer_never_imports_or_executes_submitted_code(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('Python source analysis executed or imported submitted code')
    real_import = builtins.__import__
    def guarded_import(name, *args, **kwargs):
        if name in {'imaginary_project_module', 'bandit', 'hexora', 'codecheck', 'os'}:
            forbidden()
        return real_import(name, *args, **kwargs)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    monkeypatch.setattr(builtins, '__import__', guarded_import)
    assert facts('import imaginary_project_module\nimport bandit\nimport hexora\nprint(sum([1,2]))') == ()
    (fact,) = facts("import os\nos.system('sudo true')")
    assert fact.kind == 'inline'


def test_coding_agent_imports_and_normal_math_have_no_sandbox_policy():
    result, _ = analyze('import pathlib\nimport socket\nimport numpy\nprint(1 + 2)')
    assert [f.rule for f in result.findings] == ['uses-interpreter']


def test_python_direct_source_does_not_follow_subprocess_script():
    provider = MemoryEvidenceProvider({'/work/main.py': "import subprocess\nsubprocess.run(['python','nested.py'])",
                                       '/work/nested.py': "import os\nos.system('sudo reboot')"})
    result = Analyzer(evidence=provider).analyze_report('python main.py', '/work', shell='bash')
    assert [f.rule for f in result.findings] == ['execution-content-unavailable', 'uses-interpreter']
    assert [q.path for q in provider.queries if isinstance(q, ReadFile)] == ['/work/main.py']
    assert StatTarget('/work/nested.py') in provider.queries


def test_authored_python_subprocess_preserves_full_until_first_file_read():
    source = "import subprocess\nsubprocess.run(['python','nested.py'])"
    provider = MemoryEvidenceProvider({'/work/nested.py': "import os\nos.system('sudo reboot')"})
    command = "cat <<'EOF' > main.py\n" + source + '\nEOF'
    result = Analyzer(evidence=provider).analyze_report(command, '/work', shell='bash')
    assert [f.rule for f in result.findings] == ['unreadable-payload', 'uses-interpreter']
    assert result.findings[0].data['context'] == 'written_content'
    assert [q.path for q in provider.queries if isinstance(q, ReadFile)] == ['/work/nested.py']


def test_python_subprocess_inherits_supplied_child_environment():
    source = "import os; os.system('rm -rf \"$TARGET\"')"
    command = 'TARGET=/etc ' + shlex.join(['python', '-c', source])
    result = Analyzer(evidence=DisabledEvidenceProvider()).analyze_report(command, '/work', shell='bash')
    assert sorted(f.rule for f in result.findings) == ['delete-protected-root', 'uses-interpreter']


def test_python_direct_source_keeps_windows_invocation_paths():
    provider = MemoryEvidenceProvider({r'D:\work\source.py': "import os\nos.remove('folder/file')",
                                       r'D:\work\folder\file': 'hello'})
    result = Analyzer(evidence=provider).analyze_report('python source.py', r'D:\work', shell='cmd')
    assert sorted(f.rule for f in result.findings) == ['delete-inside-workspace', 'uses-interpreter']
    deletion = next(f for f in result.findings if f.rule == 'delete-inside-workspace')
    assert deletion.data['target'] == r'D:\work\folder\file'
    assert deletion.data['context'] == 'direct_artifact'


def test_python_defined_subprocess_retains_context_in_report():
    result, _ = analyze("def task():\n    import os\n    os.system('sudo true')")
    assert sorted(f.rule for f in result.findings) == ['privilege-escalation', 'uses-interpreter']
    elevation = next(f for f in result.findings if f.rule == 'privilege-escalation')
    assert elevation.data['context'] == 'defined_body'


def test_python_node_limit_remains_a_high_coverage_finding():
    from command_inspector import AnalyzerConfig
    # Exercise the AST limit directly through source inspection rather than
    # having the enclosing shell syntax consume the source-node budget first.
    from command_inspector.detectors import DetectorContext
    from command_inspector.local_evidence import CachedEvidenceProvider
    from command_inspector.bash.syntax import BashFrontend
    context = DetectorContext(AnalyzerConfig(source_nodes=2), '/work', {},
                              CachedEvidenceProvider(DisabledEvidenceProvider(), 100), BashFrontend())
    context.inspect('print("hello")', 'python', 'source.py', 'direct_artifact', '/work', 1)
    assert [(f.rule, f.level.name) for f in context.findings] == [('unreadable-payload', 'HIGH')]
