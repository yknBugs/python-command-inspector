"""Workspace membership is independent of invocation cwd and source location."""
import json

import pytest

import command_inspector as public
from command_inspector import Analyzer, AnalyzerConfig, InputError
from command_inspector.local_evidence import DisabledEvidenceProvider, MemoryEvidenceProvider, ReadFile


PROFILES = [
    ('bash', '/work/tools', '/work', 'echo hello > ../out.txt', 'rm -rf .', 'cat ../input.txt'),
    ('powershell', r'C:\work\tools', r'C:\work', "Set-Content ../out.txt hello", 'Remove-Item -Recurse -Force .', 'Get-Content ../input.txt'),
    ('cmd', r'C:\work\tools', r'C:\work', 'echo hello > ..\\out.txt', 'rd /s /q .', 'type ..\\input.txt'),
    ('python', '/work/tools', '/work', "from pathlib import Path; Path('../out.txt').write_text('hello')", "import shutil; shutil.rmtree('.')", "from pathlib import Path; Path('../input.txt').read_text()"),
    ('javascript', '/work/tools', '/work', "require('fs').writeFileSync('../out.txt','hello')", "require('fs').rmSync('.',{recursive:true,force:true})", "require('fs').readFileSync('../input.txt','utf8')"),
    ('python', r'C:\work\tools', r'C:\work', "from pathlib import Path; Path('../out.txt').write_text('hello')", "import shutil; shutil.rmtree('.')", "from pathlib import Path; Path('../input.txt').read_text()"),
    ('javascript', r'C:\work\tools', r'C:\work', "require('fs').writeFileSync('../out.txt','hello')", "require('fs').rmSync('.',{recursive:true,force:true})", "require('fs').readFileSync('../input.txt','utf8')"),
]


@pytest.mark.parametrize('shell,cwd,root,write,delete,read', PROFILES)
@pytest.mark.parametrize('effort', ['Full', 'Partial', 'None'])
def test_separate_root_changes_membership_without_rebasing_paths(shell, cwd, root, write, delete, read, effort):
    analyzer = Analyzer(evidence=DisabledEvidenceProvider())
    legacy = analyzer.analyze_report(write, cwd, shell=shell, effort=effort)
    explicit = analyzer.analyze_report(write, cwd, shell=shell, effort=effort, workspace_root=root)
    assert 'write-outside-workspace' in {f.rule for f in legacy.findings}
    assert 'write-outside-workspace' not in {f.rule for f in explicit.findings}
    # An omitted/None root preserves the complete previous result.
    assert legacy.to_dict() == analyzer.analyze(write, cwd, shell=shell, effort=effort, workspace_root=None)
    assert analyzer.analyze(write, cwd, shell=shell, effort=effort, workspace_root=cwd) == legacy.to_dict()
    report = analyzer.analyze_report(delete, cwd, shell=shell, effort=effort, workspace_root=root)
    assert 'delete-workspace-root' not in {f.rule for f in report.findings}
    assert 'delete-inside-workspace' in {f.rule for f in report.findings}
    assert any(f.data.get('target') == cwd for f in report.findings)
    report = analyzer.analyze_report(read, cwd, shell=shell, effort=effort, workspace_root=root)
    assert 'read-outside-workspace' not in {f.rule for f in report.findings}


@pytest.mark.parametrize('shell,cwd,root,write,delete,read', PROFILES)
def test_boundary_root_itself_and_protected_paths_are_still_distinct(shell, cwd, root, write, delete, read):
    analyzer = Analyzer(evidence=DisabledEvidenceProvider())
    # The parent now is the workspace root, rather than the invocation cwd.
    report = analyzer.analyze_report(delete.replace("'.'", "'..'") if shell in {'python', 'javascript'} else delete.replace(' .', ' ..'),
                                     cwd, shell=shell, workspace_root=root)
    assert 'delete-workspace-root' in {f.rule for f in report.findings}
    outside = analyzer.analyze_report(write.replace('../out.txt', '../../out.txt').replace('..\\out.txt', '..\\..\\out.txt'),
                                     cwd, shell=shell, workspace_root=root)
    assert 'write-outside-workspace' in {f.rule for f in outside.findings}


@pytest.mark.parametrize('shell,command,cwd,root,files', [
    ('bash', 'bash tools/script.sh', '/work', '/work', {'/work/tools/script.sh': 'echo hello > ../out.txt'}),
    ('bash', 'cd tools && bash script.sh', '/work', '/work', {'/work/tools/script.sh': 'echo hello > ../out.txt'}),
    ('powershell', '& .\\tools\\script.ps1', r'C:\work', r'C:\work', {r'C:\work\tools\script.ps1': 'Set-Content ../out.txt hello'}),
    ('cmd', 'tools\\script.bat', r'C:\work', r'C:\work', {r'C:\work\tools\script.bat': 'echo hello > ..\\out.txt'}),
    ('bash', 'python script.py', '/work/tools', '/work', {'/work/tools/script.py': "from pathlib import Path; Path('../out.txt').write_text('hello')"}),
    ('bash', 'node script.js', '/work/tools', '/work', {'/work/tools/script.js': "require('fs').writeFileSync('../out.txt','hello')"}),
    ('powershell', '& .\\script.ps1', r'C:\work\tools', r'C:\work', {r'C:\work\tools\script.ps1': 'Set-Content ../out.txt hello'}),
    ('cmd', 'script.bat', r'C:\work\tools', r'C:\work', {r'C:\work\tools\script.bat': 'echo hello > ..\\out.txt'}),
    ('powershell', 'python script.py', r'C:\work\tools', r'C:\work', {r'C:\work\tools\script.py': "from pathlib import Path; Path('../out.txt').write_text('hello')"}),
    ('cmd', 'python script.py', r'C:\work\tools', r'C:\work', {r'C:\work\tools\script.py': "from pathlib import Path; Path('../out.txt').write_text('hello')"}),
    ('bash', 'echo \'echo hello > ../out.txt\' > script.sh', '/work/tools', '/work', {}),
])
def test_nested_sources_inherit_execution_cwd_and_keep_workspace_root(shell, command, cwd, root, files):
    provider = MemoryEvidenceProvider(files)
    report = Analyzer(evidence=provider).analyze_report(command, cwd, shell=shell, workspace_root=root)
    outside = [f for f in report.findings if f.rule == 'write-outside-workspace']
    expected_outside = command in {'bash tools/script.sh', '& .\\tools\\script.ps1', 'tools\\script.bat'}
    assert bool(outside) == expected_outside
    if files:
        assert any(isinstance(query, ReadFile) for query in provider.queries)


@pytest.mark.parametrize('shell,cwd,bad', [
    ('bash', '/work', ''), ('bash', '/work', 'relative'), ('bash', '/work', 42),
    ('bash', '/work', '/bad\x00root'), ('bash', '/work', r'C:\work'),
    ('cmd', r'C:\work', '/work'), ('cmd', r'C:\work', 'C:relative'),
    ('powershell', r'C:\work', '\\rooted'), ('python', '/work', []),
])
def test_root_must_be_absolute_in_the_execution_path_profile(shell, cwd, bad):
    with pytest.raises(InputError, match='workspace_root'):
        Analyzer().analyze('', cwd, shell=shell, workspace_root=bad)


@pytest.mark.parametrize('method', ['analyze', 'analyze_json', 'analyze_report',
                                   'analyze_python', 'analyze_python_json', 'analyze_python_report',
                                   'analyze_javascript', 'analyze_javascript_json', 'analyze_javascript_report'])
def test_every_analyzer_facade_forwards_workspace_root(method):
    source = ("require('fs').writeFileSync('../out.txt','hello')" if 'javascript' in method
              else "from pathlib import Path; Path('../out.txt').write_text('hello')")
    kwargs = {} if 'python' in method or 'javascript' in method else {'shell': 'python'}
    result = getattr(Analyzer(evidence=DisabledEvidenceProvider()), method)(source, '/work/tools', workspace_root='/work', **kwargs)
    if isinstance(result, str):
        result = json.loads(result)
    elif hasattr(result, 'to_dict'):
        result = result.to_dict()
    assert result == {}


@pytest.mark.parametrize('method', ['analyze', 'analyze_json', 'analyze_python', 'analyze_python_json', 'analyze_javascript', 'analyze_javascript_json'])
def test_top_level_facades_forward_workspace_root(method):
    source = ("require('fs').writeFileSync('../out.txt','hello')" if 'javascript' in method
              else "from pathlib import Path; Path('../out.txt').write_text('hello')")
    kwargs = {} if 'python' in method or 'javascript' in method else {'shell': 'python'}
    result = getattr(public, method)(source, '/work/tools', workspace_root='/work', config=AnalyzerConfig(local_evidence=False), **kwargs)
    assert (json.loads(result) if isinstance(result, str) else result) == {}


def test_workspace_root_is_normalized_and_never_reused_between_calls():
    analyzer = Analyzer(evidence=DisabledEvidenceProvider())
    source = 'echo hello > ../out.txt'
    assert analyzer.analyze(source, '/work/tools', workspace_root='/work/tools/..') == {}
    assert 'write-outside-workspace' in {f.rule for f in analyzer.analyze_report(source, '/work/tools').findings}


def test_additional_paths_and_protected_roots_keep_their_independent_roles():
    analyzer = Analyzer(AnalyzerConfig(additional_paths=('/allowed',)), evidence=DisabledEvidenceProvider())
    assert analyzer.analyze('echo hello > /allowed/a', '/work/tools', workspace_root='/work') == {}
    report = analyzer.analyze_report('rm -rf /etc', '/work/tools', workspace_root='/')
    assert report.level.name == 'BLOCK'
