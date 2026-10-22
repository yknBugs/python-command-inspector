"""Compositional regressions from REVIEW.md; submitted commands never execute."""
import pytest

from command_inspector import Analyzer
from command_inspector.local_evidence import DisabledEvidenceProvider, MemoryEvidenceProvider, ReadFile, SummarizeDeletion
from command_inspector.models import Level
from command_inspector.bash.semantics import SemanticBuilder
from command_inspector.pwsh.semantics import PowerShellBuilder


def analyze(source, *, shell='bash', files=None, env=None, provider=None):
    provider = provider or (DisabledEvidenceProvider() if files is None else MemoryEvidenceProvider(files))
    return Analyzer(evidence=provider).analyze_report(source, '/work' if shell == 'bash' else r'D:\work', shell=shell, env=env)


def rules(report):
    return {f.rule for f in report.findings}


def facts(source, shell='bash'):
    root = Analyzer().parse(source, shell=shell).root
    builder = SemanticBuilder('/work', {}) if shell == 'bash' else PowerShellBuilder(r'D:\work', {})
    return builder.build(root)


@pytest.mark.parametrize('option', ['-o', '--output', '-L', '--log-file'])
def test_psql_output_options_keep_protected_writes(option):
    result = analyze(f'psql -c "SELECT 1" {option} /etc/passwd')
    assert {'modify-sensitive-file', 'write-outside-workspace'} <= rules(result)
    assert result.level == Level.HIGH
    assert not any(f.rule.startswith('sql-') for f in result.findings)


@pytest.mark.parametrize('shell', ['bash', 'powershell', 'cmd'])
@pytest.mark.parametrize('client, options', [('psql', '-c'), ('sqlcmd', '-Q')])
def test_sql_client_writes_work_in_all_shells_and_keep_sql_source(client, options, shell):
    result = analyze(f'{client} {options} "DROP TABLE t" -o ../out.txt', shell=shell, files={})
    assert {'sql-drop-object', 'write-outside-workspace'} <= rules(result)
    output = next(f for f in result.findings if f.rule == 'write-outside-workspace')
    assert output.data['target'] == ('/out.txt' if shell == 'bash' else r'D:\out.txt')


@pytest.mark.parametrize('option', ['-o out.txt', '--output=out.txt', '-oout.txt'])
def test_psql_existing_output_is_overwrite_evidence(option):
    result = analyze(f'psql -c "SELECT 1" {option}', files={'/work/out.txt': 'old'})
    assert rules(result) == {'overwrite-existing-file'}


def test_psql_log_appends_without_claiming_overwrite_or_authored_content():
    source = 'psql -c "SELECT 1" -L out.log'
    assert analyze(source, files={'/work/out.log': 'old'}).to_dict() == {}
    write = next(f for f in facts(source) if f.kind == 'write')
    assert write.operation == 'append'
    assert write.targets == ('/work/out.log',)
    assert write.payload is None


@pytest.mark.parametrize('client, code', [('psql', '-c'), ('sqlcmd', '-Q')])
def test_sql_client_unresolved_output_invalidates_execution_evidence(client, code):
    provider = MemoryEvidenceProvider({'/work/B.sh': 'true'})
    result = analyze(f'{client} {code} "SELECT 1" -o "$out"; bash B.sh', provider=provider)
    assert {'write-variable-unresolved', 'execution-content-unavailable'} <= rules(result)
    assert not any(isinstance(q, ReadFile) for q in provider.queries)


def test_sql_client_output_pipe_is_execution_coverage_and_unknown_mutation():
    provider = MemoryEvidenceProvider({'/work/B.sh': 'true'})
    result = analyze('psql -c "SELECT 1" -o "|cat"; bash B.sh', provider=provider)
    assert 'execution-content-unavailable' in rules(result)
    assert not any(f.data.get('target', '').endswith('|cat') for f in result.findings)
    assert not any(isinstance(q, ReadFile) for q in provider.queries)


def test_psql_pipe_character_inside_a_filename_remains_a_file():
    source = 'psql -c "SELECT 1" -o " |cat"'
    write = next(f for f in facts(source) if f.kind == 'write')
    assert write.targets == ('/work/ |cat',)
    assert 'execution-content-unavailable' not in rules(analyze(source))


def test_sql_output_does_not_reuse_same_file_as_sql_input():
    provider = MemoryEvidenceProvider({'/work/a.sql': 'DROP TABLE t;'})
    result = analyze('psql -f a.sql -o a.sql', provider=provider)
    assert 'sql-unresolved' in rules(result)
    assert 'sql-drop-object' not in rules(result)
    assert not any(isinstance(q, ReadFile) for q in provider.queries)


def test_psql_repeated_sources_outputs_and_log_selection():
    source = 'psql -c "SELECT 1" -o a.txt -c "DROP TABLE t" --output b.txt -L old.log --log-file new.log'
    writes = [f for f in facts(source) if f.kind == 'write']
    assert [f.targets for f in writes] == [('/work/a.txt',), ('/work/b.txt',), ('/work/new.log',)]
    assert 'sql-drop-object' in rules(analyze(source))


@pytest.mark.parametrize('source', ['psql -c "SELECT 1"', 'sqlcmd -Q "SELECT 1"'])
def test_readonly_sql_without_output_stays_quiet(source):
    assert analyze(source).to_dict() == {}


@pytest.mark.parametrize('mutation', ['find . -name B.sh -delete', 'sed -i s/a/b/ "$(printf B.sh)"'])
@pytest.mark.parametrize('followup, rule', [('bash B.sh', 'execution-content-unavailable'), ('cat B.sh', 'ingestion-inspection-incomplete')])
def test_possible_mutations_prevent_stale_read_or_execution(mutation, followup, rule):
    provider = MemoryEvidenceProvider({'/work/B.sh': 'password=abcdefghijk'})
    result = analyze(mutation + '; ' + followup, provider=provider)
    assert rule in rules(result)
    assert 'credentials-read' not in rules(result)
    assert not any(isinstance(q, ReadFile) for q in provider.queries)


def test_filtered_delete_invalidates_search_root_but_not_unrelated_sibling():
    provider = MemoryEvidenceProvider({'/work/search/B.sh': 'true', '/work/other.sh': 'true'})
    result = analyze('find search -name B.sh -delete; bash search/B.sh; bash other.sh', provider=provider)
    blocked = [f.data.get('target') for f in result.findings if f.rule == 'execution-content-unavailable']
    assert blocked == ['/work/search/B.sh']
    assert [q.path for q in provider.queries if isinstance(q, ReadFile)] == ['/work/other.sh']


@pytest.mark.parametrize('mutation', ['find search -name B.sh -delete', 'sed -i s/a/b/ "$(printf B.sh)"'])
def test_possible_mutation_invalidates_even_cached_evidence(mutation):
    provider = MemoryEvidenceProvider({'/work/search/B.sh': 'true'})
    result = analyze('cat search/B.sh; ' + mutation + '; bash search/B.sh', provider=provider)
    assert 'execution-content-unavailable' in rules(result)
    assert len([q for q in provider.queries if isinstance(q, ReadFile)]) == 1


@pytest.mark.parametrize('body', ['find . -name B.sh -delete', 'sed -i s/a/b/ "$(printf B.sh)"'])
@pytest.mark.parametrize('template', ['function unused() {{{body};}}; bash B.sh', "cat <<'EOF' > other.sh\n{body}\nEOF\nbash B.sh"])
def test_defined_and_written_mutations_do_not_change_invoking_evidence(body, template):
    provider = MemoryEvidenceProvider({'/work/B.sh': 'true'})
    result = analyze(template.format(body=body), provider=provider)
    assert 'execution-content-unavailable' not in rules(result)
    assert [q.path for q in provider.queries if isinstance(q, ReadFile)] == ['/work/B.sh']


@pytest.mark.parametrize('source, rule, expected', [
    ('systemctl start postgresql; systemctl stop ssh', 'service-change', [('start', ['postgresql']), ('stop', ['ssh'])]),
    ('docker start a; docker rm b', 'docker-change', [('start', ['a']), ('rm', ['b'])]),
    ('docker container start a; docker container stop b', 'docker-change', [('container start', ['a']), ('container stop', ['b'])]),
])
def test_distinct_actions_and_targets_survive_aggregation(source, rule, expected):
    result = analyze(source)
    findings = [f for f in result.findings if f.rule == rule]
    assert [(f.data['action'], f.data['targets']) for f in findings] == expected
    assert all(f.data['targets'][0] in f.title for f in findings)


@pytest.mark.parametrize('source, rule', [('systemctl start a', 'service-change'), ('docker start a', 'docker-change')])
def test_equivalent_system_operations_still_deduplicate(source, rule):
    assert len([f for f in analyze(source + '; ' + source).findings if f.rule == rule]) == 1


@pytest.mark.parametrize('shell', ['bash', 'powershell', 'cmd'])
def test_docker_structured_actions_are_shared_by_shell_adapters(shell):
    separator = '&' if shell == 'cmd' else ';'
    result = analyze('docker start a ' + separator + ' docker rm b', shell=shell)
    assert [(f.data['action'], f.data['targets']) for f in result.findings if f.rule == 'docker-change'] == [('start', ['a']), ('rm', ['b'])]


@pytest.mark.parametrize('source, rule', [
    ('systemctl --user start a; systemctl --system start a', 'service-change'),
    ('docker --context a start c; docker --context b start c', 'docker-change'),
    ('docker start a; docker start b', 'docker-change'),
    ('docker rm a; docker rm --force a', 'docker-change'),
])
def test_scope_options_and_resource_names_keep_distinct_effects(source, rule):
    assert len([f for f in analyze(source).findings if f.rule == rule]) == 2


def test_docker_option_values_are_not_resource_targets_or_leaked_passwords():
    result = analyze('docker login --username user --password never-export-this registry.example')
    item = next(f for f in result.findings if f.rule == 'docker-change')
    assert item.data['targets'] == ['registry.example']
    assert 'never-export-this' not in str(result.to_dict())


@pytest.mark.parametrize('source, target', [
    ('docker exec c program --password never-export-this', 'c'),
    ('docker run image program --password never-export-this', 'image'),
])
def test_docker_resource_targets_do_not_export_opaque_payload_arguments(source, target):
    result = analyze(source)
    assert result.findings[0].data['targets'] == [target]
    assert 'never-export-this' not in str(result.to_dict())


def test_docker_explicit_operand_boundary_preserves_dash_prefixed_resource():
    result = analyze('docker rm -- -resource')
    assert result.findings[0].data['targets'] == ['-resource']


def test_other_distinct_system_effects_do_not_collide_on_common_data():
    result = analyze('journalctl --rotate; ss -K; ss -K')
    effects = [f for f in result.findings if f.rule == 'system-settings-change']
    assert len(effects) == 2
    assert effects[0].title != effects[1].title


@pytest.mark.parametrize('branch', [
    'if true; then x=/etc; fi',
    'if true; then echo ok; else x=/etc; fi',
    'if true; then echo ok; elif false; then x=/etc; fi',
    'case "$key" in a) x=/etc;; b) echo ok;; esac',
    'case "$key" in a) x=/etc;; b) x=/work/cache;; esac',
    'if true; then x=/etc; if false; then x=/work/cache; fi; fi',
    'if true; then unset x; fi',
])
def test_bash_branch_mutations_do_not_restore_old_safe_target(branch):
    source = 'x=/work/cache; ' + branch + '; rm -rf "$x"'
    result = analyze(source)
    if 'unset' in branch:
        assert 'delete-variable-unresolved' in rules(result)
        assert 'delete-inside-workspace' not in rules(result)
    else:
        assert {'delete-protected-root', 'delete-inside-workspace'} <= rules(result)
        assert 'delete-variable-unresolved' not in rules(result)
        assert all(f.data['possible'] for f in result.findings if f.rule.startswith('delete-'))


def test_bash_alternative_bodies_do_not_inherit_other_arm_assignments():
    source = 'x=/work/cache; if true; then x=/etc; rm -rf "$x"; else rm -rf "$x"; fi'
    deletions = [f for f in facts(source) if f.kind == 'delete']
    assert [f.targets for f in deletions] == [('/etc',), ('/work/cache',)]


def test_elif_condition_changes_are_visible_to_later_else_body():
    source = 'x=/work/cache; if false; then true; elif x=/etc; false; then true; else rm -rf "$x"; fi'
    deletion = next(f for f in facts(source) if f.kind == 'delete')
    assert deletion.targets == ('/etc',)


@pytest.mark.parametrize('branch', ['if true; then echo ok; fi', 'case "$key" in a) echo ok;; esac', 'function unused() { x=/etc; }'])
def test_bash_unchanged_or_definition_only_bindings_stay_concrete(branch):
    source = 'x=/work/cache; ' + branch + '; rm -rf "$x"'
    deletion = next(f for f in facts(source) if f.kind == 'delete')
    assert deletion.targets == ('/work/cache',)


@pytest.mark.parametrize('branch', ['if true; then cd /etc; fi', 'case "$key" in a) cd /etc;; esac'])
def test_bash_branch_cwd_change_invalidates_later_relative_path(branch):
    deletion = next(f for f in facts(branch + '; rm -rf cache') if f.kind == 'delete')
    assert deletion.cwd is None
    assert deletion.targets == ()


def test_branch_condition_and_case_body_effects_are_visible():
    result = analyze('if rm -rf /etc; then true; fi; case "$key" in a) rm -rf /usr;; esac')
    targets = {f.data['target'] for f in result.findings if f.rule == 'delete-protected-root'}
    assert targets == {'/etc', '/usr'}


@pytest.mark.parametrize('terminator', [';&', ';;&'])
def test_case_fallthrough_does_not_invent_old_target_in_next_arm(terminator):
    source = f'x=/work/cache; case "$key" in a) x=/etc{terminator} b) rm -rf "$x";; esac'
    operations = [f for f in facts(source) if f.kind == 'delete']
    assert {p for f in operations for p in f.targets} == {'/etc', '/work/cache'}
    assert all('possible' in f.flags for f in operations)


def test_readonly_unset_does_not_invalidate_retained_binding():
    source = 'readonly x=/etc; if true; then unset x; fi; rm -rf "$x"'
    operation = next(f for f in facts(source) if f.kind == 'delete')
    assert operation.targets == ('/etc',)
    assert 'readonly-assignment-failed' in rules(analyze(source))


@pytest.mark.parametrize('prefix', ['CREATE PROCEDURE', 'CREATE PROC', 'ALTER PROCEDURE', 'CREATE OR ALTER PROCEDURE', 'CREATE FUNCTION', 'CREATE TRIGGER'])
@pytest.mark.parametrize('body', ['AS BEGIN DELETE FROM t; DROP TABLE t; END;', 'AS DELETE FROM t;\nDROP TABLE t;'])
def test_tsql_routine_semicolons_never_expose_body_as_immediate_effects(prefix, body):
    result = Analyzer().analyze_sql_report(prefix + ' p ' + body, dialect='tsql')
    assert rules(result) == {'sql-unresolved'}
    assert result.level == Level.LOW
    assert result.findings[0].data['reason'] == 'routine_body_uninspected'


@pytest.mark.parametrize('separator', ['\nGO\n', '\ngo\n', '\n  GO  \n'])
def test_tsql_real_post_batch_operations_remain_visible(separator):
    source = 'CREATE PROC p AS BEGIN DROP TABLE hidden; END;' + separator + 'DROP TABLE visible;'
    result = Analyzer().analyze_sql_report(source, dialect='tsql')
    drops = [f for f in result.findings if f.rule == 'sql-drop-object']
    assert len(drops) == 1
    assert drops[0].data['objects'] == ['visible']
    assert drops[0].data['statement_index'] == 2


def test_tsql_quoted_separators_do_not_end_routine_boundary():
    source = "CREATE PROC p AS SELECT '; GO'; SELECT '\nGO\n'; DROP TABLE hidden;\nGO\nDROP TABLE visible;"
    result = Analyzer().analyze_sql_report(source, dialect='tsql')
    assert [f.data['objects'] for f in result.findings if f.rule == 'sql-drop-object'] == [['visible']]


def test_tsql_ordinary_statements_still_split_and_quoted_routine_text_is_data():
    result = Analyzer().analyze_sql_report("SELECT 'CREATE PROC p AS DROP TABLE hidden;'; DROP TABLE visible;", dialect='tsql')
    assert rules(result) == {'sql-drop-object'}
    assert result.findings[0].data['objects'] == ['visible']


@pytest.mark.parametrize('argument, expected', [('$true', Level.BLOCK), ('$false', Level.MEDIUM), ('$recursive', Level.MEDIUM)])
def test_dotnet_recursion_distinguishes_true_false_and_unknown(argument, expected):
    result = analyze(f"[IO.Directory]::Delete('D:\\Windows', {argument})", shell='powershell')
    assert result.level == expected
    assert ('delete-protected-root' in rules(result)) == (argument == '$true')
    assert ('delete-recursion-unresolved' in rules(result)) == (argument == '$recursive')
    if argument == '$recursive':
        assert all(f.data['recursive'] is None for f in result.findings if 'recursive' in f.data)


@pytest.mark.parametrize('env, failed_level', [({'USERPROFILE': r'D:\Windows'}, Level.BLOCK), ({}, Level.HIGH)])
def test_dotnet_unknown_recursion_preserves_failed_assignment_flags(env, failed_level):
    result = analyze("$HOME='build'; [IO.Directory]::Delete($HOME, $recursive)", shell='powershell', env=env)
    item = next(f for f in result.findings if f.rule == 'delete-after-failed-assignment')
    assert item.level == failed_level
    assert 'delete-recursion-unresolved' in rules(result)
    assert 'delete-protected-root' not in rules(result)


def test_dotnet_unknown_recursion_does_not_claim_nonrecursive_affected_counts():
    provider = MemoryEvidenceProvider({r'D:\work\tree\child.txt': 'data'})
    result = analyze("[IO.Directory]::Delete('D:\\work\\tree', $recursive)", shell='powershell', provider=provider)
    assert 'delete-recursion-unresolved' in rules(result)
    assert not any(isinstance(q, SummarizeDeletion) for q in provider.queries)


@pytest.mark.parametrize('source', ['rg password .', 'rg password', 'grep -r password .', 'rg -g "*.py" hello', 'rg -n --glob="*.py" hello src', 'grep -r hello src'])
def test_recursive_search_retains_coverage_without_claiming_unread_credentials(source):
    provider = MemoryEvidenceProvider({'/work/secrets': 'password=abcdefghijk', '/work/src/a.py': 'pass'})
    result = analyze(source, provider=provider)
    assert rules(result) == {'ingestion-inspection-incomplete'}
    assert result.level == Level.LOW
    assert result.findings[0].data['reason'] == 'recursive_selection_unavailable'
    assert not any(isinstance(q, ReadFile) for q in provider.queries)


@pytest.mark.parametrize('source', ['rg --files .', 'rg -l password .', 'rg -c password .', 'rg -q password .', 'rg -q password', 'grep -rl password .', 'rg password . | wc -l'])
def test_filename_count_quiet_and_consumed_search_output_does_not_ingest(source):
    provider = MemoryEvidenceProvider({'/work/secrets': 'password=abcdefghijk'})
    assert analyze(source, provider=provider).to_dict() == {}
    assert not any(isinstance(q, ReadFile) for q in provider.queries)


def test_recursive_search_explicit_file_still_checks_credentials():
    result = analyze('rg password secrets', files={'/work/secrets': 'password=abcdefghijk'})
    assert rules(result) == {'credentials-read'}


@pytest.mark.parametrize('query', ['ps', 'container ls', 'images', 'image ls', 'inspect c', 'logs c', 'volume ls', 'network ls', 'compose ps', 'info'])
def test_docker_queries_do_not_silently_accept_unknown_options(query):
    result = analyze('docker ' + query + ' --invented')
    assert rules(result) == {'unknown-option'}


@pytest.mark.parametrize('query', ['ps -aq', 'ps --filter status=running --format "{{.Names}}"', 'ps --last=3', 'container ls -a --no-trunc', 'images --digests', 'inspect --format "{{.Id}}" c', 'logs --tail 10 --since 1h c', 'stats --no-stream', 'volume ls -q', 'info --format json'])
def test_supported_docker_queries_stay_quiet(query):
    assert analyze('docker ' + query).to_dict() == {}


@pytest.mark.parametrize('source', ['docker ps --format', 'docker ps --invented=1', 'docker ps --all=garbage'])
def test_docker_missing_or_unsupported_option_values_keep_coverage(source):
    assert 'unknown-option' in rules(analyze(source))


@pytest.mark.parametrize('source', ['docker ps $missing', 'docker ps --filter "$missing"', 'docker --context "$missing" ps'])
def test_docker_dynamic_query_arguments_keep_coverage(source):
    assert 'unresolved-value' in rules(analyze(source))


@pytest.mark.parametrize('shell', ['powershell', 'cmd'])
def test_docker_query_option_validation_is_shared_by_windows_adapters(shell):
    assert rules(analyze('docker ps --invented', shell=shell)) == {'unknown-option'}


@pytest.mark.parametrize('source', ['docker exec c program --invented', 'docker run image program --help'])
def test_docker_payload_options_are_not_query_options_or_docker_help(source):
    assert rules(analyze(source)) == {'docker-change'}


@pytest.mark.parametrize('command, flag', [('rm', '-f'), ('container rm', '-f'), ('rmi', '-f'), ('volume rm', '-f'), ('rm', '-v')])
@pytest.mark.parametrize('shell', ['bash', 'powershell', 'cmd'])
def test_docker_boolean_short_options_preserve_distinct_targets(command, flag, shell):
    separator = '&' if shell == 'cmd' else ';'
    result = analyze(f'docker {command} {flag} a {separator} docker {command} {flag} b', shell=shell)
    effects = [f for f in result.findings if f.rule == 'docker-change']
    assert [f.data['targets'] for f in effects] == [['a'], ['b']]
    assert all(f.data['targets_resolved'] for f in effects)


@pytest.mark.parametrize('source, target', [
    ('docker run -t image', 'image'),
    ('docker exec -t container program', 'container'),
    ('docker build -f Dockerfile -t image .', '.'),
    ('docker stop -t 10 container', 'container'),
    ('docker kill -s TERM container', 'container'),
    ('docker login -u user -p secret registry.example', 'registry.example'),
])
def test_docker_short_option_arities_depend_on_subcommand(source, target):
    result = analyze(source)
    effect = next(f for f in result.findings if f.rule == 'docker-change')
    assert effect.data['targets'] == [target]


@pytest.mark.parametrize('branch', [
    'if true; then readonly x; fi',
    'if false; then true; else readonly x; fi',
    'case "$key" in a) readonly x;; esac',
    'if true; then if true; then readonly x; fi; fi',
    'for i in one; do readonly x; done',
])
@pytest.mark.parametrize('mutation', ['export x=/work/cache', 'unset x; export x=/work/cache'])
def test_conditional_readonly_does_not_allow_falsely_safe_assignment(branch, mutation):
    result = analyze(f'x=/etc; {branch}; {mutation}; rm -rf "$x"')
    if mutation.startswith('unset'):
        assert 'delete-variable-unresolved' in rules(result)
        assert 'delete-inside-workspace' not in rules(result)
    else:
        assert {'delete-protected-root', 'delete-inside-workspace'} <= rules(result)
        assert 'delete-variable-unresolved' not in rules(result)
    assert 'readonly-assignment-failed' in rules(result)
    failure = next(f for f in result.findings if f.rule == 'readonly-assignment-failed')
    assert failure.data['possible']


def test_conditional_readonly_does_not_terminate_all_paths():
    result = analyze('x=/etc; if true; then readonly x; fi; x=/work/cache; rm -rf "$x"')
    assert {'delete-protected-root', 'delete-inside-workspace'} <= rules(result)
    assert 'delete-variable-unresolved' not in rules(result)


def test_function_readonly_does_not_leak_to_caller():
    result = analyze('x=/etc; function unused() { readonly x; }; export x=/work/cache; rm -rf "$x"')
    assert 'delete-inside-workspace' in rules(result)
    assert 'delete-variable-unresolved' not in rules(result)


@pytest.mark.parametrize('separator', ['GO -- end definition', 'GO 2', 'GO 2 -- repeat', 'GO /* batch */', '/* batch */ GO', 'GO /* count */ 2'])
def test_tsql_commented_and_counted_batch_boundaries(separator):
    result = Analyzer().analyze_sql_report('CREATE PROC p AS SELECT 1;\n' + separator + '\nDROP TABLE visible;', dialect='tsql')
    drops = [f for f in result.findings if f.rule == 'sql-drop-object']
    assert len(drops) == 1
    assert drops[0].data['objects'] == ['visible']
    assert drops[0].data['statement_index'] == 2


@pytest.mark.parametrize('body', ["SELECT 'GO 2';", '-- GO 2', '/* GO */', 'SELECT [GO];', 'GO 2 SELECT 1;', 'GO 0', 'GO -1'])
def test_tsql_non_separators_keep_routine_body_deferred(body):
    result = Analyzer().analyze_sql_report('CREATE PROC p AS SELECT 1;\n' + body + '\nDROP TABLE hidden;', dialect='tsql')
    assert 'sql-drop-object' not in rules(result)


@pytest.mark.parametrize('terminator', [';&', ';;&'])
def test_case_fallthrough_preserves_possible_readonly(terminator):
    result = analyze(f'x=/etc; case "$key" in a) readonly x{terminator} b) export x=/work/cache; rm -rf "$x";; esac')
    assert {'delete-protected-root', 'delete-inside-workspace'} <= rules(result)
    assert 'delete-variable-unresolved' not in rules(result)
