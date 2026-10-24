"""SQL operation policy and bounded, non-executing source inspection."""
import builtins
import json
import pytest
import jsonschema
from command_inspector import Analyzer, AnalyzerConfig, InputError, analyze_sql, analyze_sql_json
from command_inspector.local_evidence import DisabledEvidenceProvider, MemoryEvidenceProvider, ReadFile, StatTarget


def report(sql, dialect=None, **limits):
    return Analyzer(AnalyzerConfig(**limits), evidence=DisabledEvidenceProvider()).analyze_sql_report(sql, dialect=dialect)


def finding(result, rule, level):
    found = [f for f in result.findings if f.rule == rule]
    assert len(found) == 1, result.to_dict()
    assert found[0].level.name == level
    return found[0]


@pytest.mark.parametrize("dialect", [None, "postgres", "mysql", "sqlite", "tsql"])
@pytest.mark.parametrize("sql", ["", "-- DROP TABLE t\n", "SELECT 1", "SELECT 'DROP TABLE users; DELETE FROM t'",
                                 "SELECT * FROM users WHERE id=1", "WITH a AS (SELECT 1) SELECT * FROM a",
                                 "SELECT * FROM a UNION ALL SELECT * FROM b", "BEGIN TRANSACTION; COMMIT; ROLLBACK"])
def test_read_only_is_silent(dialect, sql):
    assert report(sql, dialect).to_dict() == {}


@pytest.mark.parametrize("dialect", [None, "postgres", "mysql", "sqlite", "tsql"])
@pytest.mark.parametrize("sql,rule,level,objects", [
    ("UPDATE users SET active=1 WHERE id=1", "sql-row-change", "LOW", ["users"]),
    ("DELETE FROM users WHERE id=1", "sql-row-change", "LOW", ["users"]),
    ("UPDATE users SET active=1", "sql-row-change", "MEDIUM", ["users"]),
    ("DELETE FROM users", "sql-row-change", "MEDIUM", ["users"]),
    ("INSERT INTO users (id) VALUES (1)", "sql-row-change", "LOW", ["users"]),
    ("CREATE TABLE users (id INT)", "sql-schema-change", "LOW", ["users"]),
    ("CREATE TABLE backup AS SELECT * FROM users", "sql-schema-change", "LOW", ["backup"]),
    ("ALTER TABLE users ADD email VARCHAR(64)", "sql-schema-change", "LOW", ["users"]),
    ("ALTER TABLE users DROP COLUMN email", "sql-remove-schema", "MEDIUM", ["users.email"]),
    ("DROP TABLE users", "sql-drop-object", "HIGH", ["users"]),
    ("DROP TABLE IF EXISTS users", "sql-drop-object", "HIGH", ["users"]),
    ("CREATE DATABASE archive", "sql-create-identity", "MEDIUM", ["archive"]),
    ("DROP DATABASE archive", "sql-drop-object", "HIGH", ["archive"]),
    ("CREATE USER app", "sql-create-identity", "MEDIUM", ["app"]),
    ("DROP USER app", "sql-drop-object", "HIGH", ["app"]),
])
def test_core_operation_levels(dialect, sql, rule, level, objects):
    result = report(sql, dialect)
    found = finding(result, rule, level)
    assert result.num_findings == 1
    assert found.data["objects"] == objects
    assert not found.evidence


@pytest.mark.parametrize("sql,dialect,rule,level", [
    ("TRUNCATE TABLE users", "postgres", "sql-truncate", "MEDIUM"),
    ("TRUNCATE SCHEMA archive", "postgres", "sql-truncate", "MEDIUM"),
    ("DROP SCHEMA archive CASCADE", "postgres", "sql-remove-schema", "MEDIUM"),
    ("CREATE OR REPLACE TABLE users AS SELECT 1 AS id", "postgres", "sql-truncate", "MEDIUM"),
    ("GRANT SELECT ON TABLE users TO app", "postgres", "sql-privilege-change", "MEDIUM"),
    ("REVOKE ALL ON TABLE users FROM app", "postgres", "sql-privilege-change", "MEDIUM"),
    ("GRANT ALL PRIVILEGES ON db.* TO 'app'@'localhost'", "mysql", "sql-privilege-change", "MEDIUM"),
    ("REVOKE SELECT ON db.* FROM app", "mysql", "sql-privilege-change", "MEDIUM"),
    ("CREATE USER app WITH PASSWORD 'private-literal'", "postgres", "sql-create-identity", "MEDIUM"),
    ("CREATE USER 'app'@'localhost' IDENTIFIED BY 'private-literal'", "mysql", "sql-create-identity", "MEDIUM"),
    ("ALTER USER app WITH PASSWORD 'private-literal'", "postgres", "sql-privilege-change", "MEDIUM"),
    ("CREATE LOGIN app WITH PASSWORD='private-literal'", "tsql", "sql-create-identity", "MEDIUM"),
    ("DROP LOGIN app", "tsql", "sql-drop-object", "HIGH"),
    ("ALTER AUTHORIZATION ON OBJECT::dbo.users TO app", "tsql", "sql-privilege-change", "MEDIUM"),
    ("MERGE INTO users USING updates ON users.id=updates.id WHEN MATCHED THEN DELETE", "tsql", "sql-row-change", "MEDIUM"),
    ("INSERT OVERWRITE TABLE users SELECT * FROM updates", "spark", "sql-row-change", "MEDIUM"),
    ("SELECT * INTO backup FROM users", "tsql", "sql-schema-change", "LOW"),
])
def test_dialect_operations(sql, dialect, rule, level, caplog, capsys):
    result = report(sql, dialect)
    finding(result, rule, level)
    assert result.num_findings == 1, result.to_dict()
    assert "private-literal" not in json.dumps(result.to_dict()) + caplog.text + str(capsys.readouterr())


@pytest.mark.parametrize("sql,level", [
    ("DELETE u,v FROM users u JOIN visits v ON u.id=v.id WHERE u.id=1", "MEDIUM"),
    ("DELETE u FROM users u JOIN visits v ON u.id=v.id WHERE u.id=1", "LOW"),
    ("UPDATE users u JOIN visits v ON u.id=v.id SET u.active=0 WHERE u.id=1", "LOW"),
    ("UPDATE users u JOIN visits v ON u.id=v.id SET u.active=0,v.active=0 WHERE u.id=1", "MEDIUM"),
    ("UPDATE users u JOIN visits v ON u.id=v.id SET active=0 WHERE u.id=1", "MEDIUM"),
    ("DELETE FROM users WHERE id IN (SELECT id FROM visits)", "LOW"),
    ("DELETE FROM users WHERE 1=1", "LOW"),
    ("UPDATE users SET active=(SELECT MAX(active) FROM visits WHERE id=1)", "MEDIUM"),
    ("DELETE FROM users LIMIT 1", "MEDIUM"),
])
def test_mutation_targets_and_root_where(sql, level):
    finding(report(sql, "mysql"), "sql-row-change", level)


def test_data_changing_cte_is_not_a_read_only_query():
    result = report("WITH removed AS (DELETE FROM users RETURNING *) SELECT * FROM removed", "postgres")
    assert finding(result, "sql-row-change", "MEDIUM").data["objects"] == ["users"]


@pytest.mark.parametrize("sql", ["EXPLAIN DELETE FROM users", "EXPLAIN SELECT * FROM users",
                                 "EXPLAIN (ANALYZE FALSE) DELETE FROM users", "EXPLAIN (ANALYZE OFF, VERBOSE TRUE) DELETE FROM users"])
def test_nonexecuting_explain_is_silent(sql):
    assert report(sql, "postgres").to_dict() == {}


@pytest.mark.parametrize("sql", ["EXPLAIN ANALYZE DELETE FROM users", "EXPLAIN (ANALYZE TRUE) DELETE FROM users", "EXPLAIN (ANALYZE) DELETE FROM users"])
def test_explain_analyze_executes_its_subject(sql):
    finding(report(sql, "postgres"), "sql-row-change", "MEDIUM")


@pytest.mark.parametrize("sql", ["hello", "DROP", "CREATE USER", "DELETE FROM", "SELECT (", "CALL mysterious()", "DO $$DROP TABLE users$$", "EXEC('DROP TABLE users')"])
def test_unresolved_sql_is_low(sql):
    result = report(sql, "postgres")
    finding(result, "sql-unresolved", "LOW")
    assert result.num_findings == 1


def test_bad_statement_does_not_hide_later_drop():
    result = report("DELETE FROM; DROP TABLE users; SELECT 1", "postgres")
    finding(result, "sql-unresolved", "LOW")
    assert finding(result, "sql-drop-object", "HIGH").data["statement_index"] == 2


def test_strings_comments_and_dollar_quotes_are_not_statements():
    assert report("SELECT $$DROP TABLE t;$$; /* DELETE FROM t; */ SELECT 'CREATE USER x;';", "postgres").to_dict() == {}
    result = report('DROP TABLE "odd;table"; DROP TABLE users', "postgres")
    assert [f.data["objects"] for f in result.findings] == [["odd;table"], ["users"]]


def test_multi_object_drop_and_qualified_columns():
    assert finding(report("DROP TABLE a,b", "mysql"), "sql-drop-object", "HIGH").data["objects"] == ["a", "b"]
    assert finding(report("ALTER TABLE public.users DROP COLUMN email", "postgres"), "sql-remove-schema", "MEDIUM").data["objects"] == ["public.users.email"]


@pytest.mark.parametrize("sql", ["DELETE FROM users WHERE id=?", "UPDATE users SET active=? WHERE id=?"])
def test_scalar_parameters_do_not_make_the_operation_unresolved(sql):
    result = report(sql, "sqlite")
    finding(result, "sql-row-change", "LOW")
    assert result.num_findings == 1


def test_unknown_object_retains_known_operation():
    result = report("DROP TABLE ?", "sqlite")
    finding(result, "sql-unresolved", "LOW")
    finding(result, "sql-drop-object", "HIGH")


def test_sql_objects_never_request_filesystem_evidence():
    provider = MemoryEvidenceProvider()
    result = Analyzer(evidence=provider).analyze_sql_report('DROP TABLE "/etc"', dialect="postgres")
    finding(result, "sql-drop-object", "HIGH")
    assert provider.queries == []


@pytest.mark.parametrize("limits", [{"file_bytes": 5}, {"source_nodes": 2}])
def test_sql_budgets_are_low(limits):
    result = report("DROP TABLE users", "postgres", **limits)
    assert result.level.name == "LOW"
    finding(result, "sql-unresolved", "LOW")


def test_missing_sqlglot_is_low_without_affecting_shell_models(monkeypatch):
    original = builtins.__import__
    def unavailable(name, *args, **kwargs):
        if name == "sqlglot" or name.startswith("sqlglot."):
            raise ImportError
        return original(name, *args, **kwargs)
    monkeypatch.setattr(builtins, "__import__", unavailable)
    assert finding(report("DROP TABLE t"), "sql-unresolved", "LOW").data["reason"] == "missing_parser"
    assert Analyzer().analyze("git push", "/work", shell="bash")["level"] == "MEDIUM"


def test_dialect_and_public_contract():
    assert finding(report("SELECT 1", "unknown-dialect"), "sql-unresolved", "LOW").data["reason"] == "unsupported_dialect"
    result = analyze_sql("DROP TABLE users", dialect="postgres")
    assert json.loads(analyze_sql_json("DROP TABLE users", dialect="postgres")) == result
    jsonschema.validate(result, Analyzer.report_schema())
    assert Analyzer().capabilities()["parser_versions"]["sqlglot"] == "30.21.0"
    assert "sql" in Analyzer().capabilities()["source_languages"]
    rules = Analyzer.rule_catalog()
    assert rules["version"] == "1.13.0"
    assert all(r["introduced_in"] == "1.3.0" for r in rules["rules"] if r["rule"].startswith("sql-"))


@pytest.mark.parametrize("value", [None, 42, b"SELECT 1", "SELECT\x00", "\ud800"])
def test_sql_input_validation(value):
    with pytest.raises(InputError):
        Analyzer().analyze_sql(value)


def test_dialect_input_validation_and_disabled_rule():
    with pytest.raises(InputError):
        Analyzer().analyze_sql("SELECT 1", dialect=123)
    assert report("DROP TABLE users", disabled_rules=frozenset({"sql-drop-object"})).to_dict() == {}


SHELLS = ["bash", "powershell", "cmd"]


def shell_report(command, shell, *, provider=None, **limits):
    return Analyzer(AnalyzerConfig(**limits), evidence=provider or DisabledEvidenceProvider()).analyze_report(
        command, "/work" if shell == "bash" else r"D:\work", shell=shell)


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("command", ['psql -c "DROP TABLE users"', 'psql --command="DROP TABLE users"',
                                     'mysql -e "DROP TABLE users"', 'mariadb --execute="DROP TABLE users"',
                                     'sqlite3 database.db "DROP TABLE users"', 'sqlcmd -Q "DROP TABLE users"'])
def test_sql_clients_share_the_module(shell, command):
    if shell == "powershell":
        command = command.replace('--command=', '--command ').replace('--execute=', '--execute ')
    result = shell_report(command, shell)
    assert result.num_findings == 1, result.to_dict()
    finding(result, "sql-drop-object", "HIGH")


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("command", ['psql -h localhost -U app -d db -c "SELECT 1"',
                                     'mysql -uroot -pprivate-literal -Ddb -e "SELECT 1"',
                                     'sqlite3 database.db "SELECT 1"', 'sqlcmd -S localhost -U app -P private-literal -Q "SELECT 1"',
                                     'psql --help', 'mysql --version', 'sqlite3 -help', 'sqlcmd -?'])
def test_readonly_clients_and_help_are_quiet(shell, command):
    assert shell_report(command, shell).to_dict() == {}


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("command", ['psql', 'mysql', 'sqlite3 database.db', 'sqlcmd', 'psql -c', 'psql --unknown "DROP TABLE t"'])
def test_unknown_client_sources_are_low(shell, command):
    finding(shell_report(command, shell), "sql-unresolved", "LOW")


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("command", ['psql -f script.sql', 'sqlcmd -i script.sql'])
def test_direct_sql_file_uses_bounded_evidence(shell, command):
    path = "/work/script.sql" if shell == "bash" else r"D:\work\script.sql"
    provider = MemoryEvidenceProvider({path: "DROP TABLE users;"})
    result = shell_report(command, shell, provider=provider)
    found = finding(result, "sql-drop-object", "HIGH")
    assert found.data["source"] == path
    assert found.data["context"] == "direct_artifact"
    assert found.evidence[0]["query"] == "ReadFile"
    assert provider.queries == [ReadFile(path, 524288)]


@pytest.mark.parametrize("shell", SHELLS)
def test_missing_sql_file_is_low(shell):
    result = shell_report("psql -f missing.sql", shell)
    finding(result, "sql-unresolved", "LOW")
    assert result.num_findings == 1


@pytest.mark.parametrize("command", ["psql <<'SQL'\nDROP TABLE users;\nSQL", "mysql <<'SQL'\nDROP TABLE users;\nSQL",
                                     "psql -f - <<'SQL'\nDROP TABLE users;\nSQL", "echo 'DROP TABLE users;' | psql",
                                     "printf '%s' 'DROP TABLE users;' | mysql"])
def test_literal_bash_stdin_is_sql(command):
    finding(shell_report(command, "bash"), "sql-drop-object", "HIGH")


def test_powershell_literal_sql_pipeline():
    finding(shell_report("'DROP TABLE users;' | psql", "powershell"), "sql-drop-object", "HIGH")


@pytest.mark.parametrize("shell", ["bash", "cmd"])
def test_sql_stdin_file_redirection(shell):
    path = "/work/script.sql" if shell == "bash" else r"D:\work\script.sql"
    provider = MemoryEvidenceProvider({path: "DROP TABLE users;"})
    finding(shell_report("mysql < script.sql", shell, provider=provider), "sql-drop-object", "HIGH")


def test_inline_sql_does_not_consume_heredoc_as_sql():
    assert shell_report("psql -c 'SELECT 1' <<'SQL'\nDROP TABLE users;\nSQL", "bash").to_dict() == {}


def test_repeated_psql_commands_preserve_every_source():
    result = shell_report('psql -c "DROP TABLE a" -c "DROP TABLE b"', "bash")
    assert [f.data["objects"] for f in result.findings] == [["a"], ["b"]]


def test_sql_script_include_is_unresolved_and_not_followed():
    provider = MemoryEvidenceProvider({"/work/script.sql": "\\i nested.sql\n", "/work/nested.sql": "DROP TABLE users"})
    result = shell_report("psql -f script.sql", "bash", provider=provider)
    assert result.level.name == "LOW"
    assert not any(f.rule == "sql-drop-object" for f in result.findings)
    assert provider.queries == [ReadFile("/work/script.sql", 524288)]


def test_written_sql_has_authoring_context():
    result = shell_report("printf 'DROP TABLE users;' > change.sql", "bash")
    assert finding(result, "sql-drop-object", "HIGH").data["context"] == "written_content"


def test_changed_sql_file_does_not_use_stale_evidence():
    provider = MemoryEvidenceProvider({"/work/script.sql": "SELECT 1"})
    result = shell_report("echo unknown > script.sql; psql -f script.sql", "bash", provider=provider)
    assert any(f.rule == "sql-unresolved" and f.data.get("reason") == "changed_earlier" for f in result.findings)


@pytest.mark.parametrize("sql,dialect,rule,level,objects", [
    ("ALTER TABLE t DROP a, DROP b", "mysql", "sql-remove-schema", "MEDIUM", ["t.a", "t.b"]),
    ("ALTER TABLE public.users OWNER TO app", "postgres", "sql-privilege-change", "MEDIUM", ["public.users"]),
    ("ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO app", "postgres", "sql-privilege-change", "MEDIUM", []),
    ("DENY SELECT ON dbo.users TO app", "tsql", "sql-privilege-change", "MEDIUM", []),
    ("DROP USER IF EXISTS app,bob", "postgres", "sql-drop-object", "HIGH", ["app", "bob"]),
    ("CREATE ROLE app WITH LOGIN", "postgres", "sql-create-identity", "MEDIUM", ["app"]),
    ("DELETE u,v FROM users u JOIN visits v ON u.id=v.id WHERE u.id=1", "mysql", "sql-row-change", "MEDIUM", ["users", "visits"]),
    ("UPDATE users u JOIN visits v ON u.id=v.id SET u.active=0,v.active=0 WHERE u.id=1", "mysql", "sql-row-change", "MEDIUM", ["users", "visits"]),
    ("UPDATE users u JOIN visits v ON u.id=v.id SET v.active=0 WHERE u.id=1", "mysql", "sql-row-change", "LOW", ["visits"]),
    ("INSERT OR REPLACE INTO users VALUES (1)", "sqlite", "sql-row-change", "MEDIUM", ["users"]),
    ("EXPLAIN ANALYZE DELETE FROM users", "mysql", "sql-row-change", "MEDIUM", ["users"]),
])
def test_reviewed_edge_cases(sql, dialect, rule, level, objects):
    result = report(sql, dialect)
    assert finding(result, rule, level).data["objects"] == objects
    assert result.num_findings == 1


@pytest.mark.parametrize("sql,dialect", [
    ("VALUES (1),(2)", "postgres"), ("SHOW TABLES", "mysql"),
    ("DESCRIBE users", "mysql"), ("EXPLAIN FORMAT=JSON DELETE FROM users", "mysql"),
    ("PRAGMA table_info(users)", "sqlite"), ("PRAGMA database_list", "sqlite"),
])
def test_readonly_dialect_metadata(sql, dialect):
    assert report(sql, dialect).to_dict() == {}


@pytest.mark.parametrize("sql,dialect", [
    ("CREATE USER app WITH PASSWORD", "postgres"), ("DROP USER app garbage", "postgres"),
    ("DROP USER app,", "postgres"), ("ALTER USER app WITH", "postgres"),
    ("GRANT nonsense ON db.* TO app", "mysql"), ("PRAGMA journal_mode=WAL", "sqlite"),
    ("REPLACE INTO users VALUES (1)", "sqlite"),
])
def test_opaque_or_invalid_forms_do_not_get_invented_effects(sql, dialect):
    result = report(sql, dialect)
    finding(result, "sql-unresolved", "LOW")
    assert result.num_findings == 1


def test_sql_server_batch_separator_is_not_an_identifier_match():
    result = report("DROP TABLE a\nGO\nDROP TABLE b", "tsql")
    assert [f.data["objects"] for f in result.findings] == [["a"], ["b"]]
    assert [f.data["statement_index"] for f in result.findings] == [1, 2]
    assert report("SELECT 'GO'; SELECT [GO] FROM users;", "tsql").to_dict() == {}


def test_routine_definition_does_not_execute_its_body():
    result = report("CREATE FUNCTION f() RETURNS VOID AS $$BEGIN DROP TABLE users; END;$$ LANGUAGE plpgsql", "postgres")
    finding(result, "sql-schema-change", "LOW")
    finding(result, "sql-unresolved", "LOW")
    assert result.level.name == "LOW"


@pytest.mark.parametrize("shell", ["powershell", "cmd"])
def test_sql_client_executable_suffix(shell):
    finding(shell_report('PSQL.EXE -c "DROP TABLE users"', shell), "sql-drop-object", "HIGH")


@pytest.mark.parametrize("content", [b"DROP TABLE users;", "DROP TABLE users;".encode("utf-16"), b"\xef\xbb\xbfDROP TABLE users;"])
def test_sql_script_encodings(content):
    provider = MemoryEvidenceProvider({"/work/script.sql": content})
    finding(shell_report("psql -f script.sql", "bash", provider=provider), "sql-drop-object", "HIGH")


@pytest.mark.parametrize("content", [b"SELECT\x00 1", b"\xffbad"])
def test_invalid_script_encoding_is_low(content):
    provider = MemoryEvidenceProvider({"/work/script.sql": content})
    finding(shell_report("psql -f script.sql", "bash", provider=provider), "sql-unresolved", "LOW")


def test_partial_sql_script_keeps_uncertainty_and_visible_effect():
    provider = MemoryEvidenceProvider({"/work/script.sql": "DROP TABLE users; " + " " * 400})
    result = shell_report("psql -f script.sql", "bash", provider=provider, file_bytes=30)
    finding(result, "sql-unresolved", "LOW")
    finding(result, "sql-drop-object", "HIGH")


def test_sql_script_read_budget_is_shared():
    provider = MemoryEvidenceProvider({"/work/a.sql": "SELECT 1", "/work/b.sql": "DROP TABLE users"})
    result = shell_report("psql -f a.sql -f b.sql", "bash", provider=provider, file_bytes=30, total_read_bytes=30)
    finding(result, "sql-unresolved", "LOW")
    assert not any(f.rule == "sql-drop-object" for f in result.findings)


def test_named_sql_file_inside_a_script_is_not_followed():
    provider = MemoryEvidenceProvider({"/work/entry.sh": "psql -f nested.sql", "/work/nested.sql": "DROP TABLE users"})
    result = shell_report("bash entry.sh", "bash", provider=provider)
    assert finding(result, "sql-unresolved", "LOW").data["reason"] == "effort_partial"
    assert provider.queries == [ReadFile("/work/entry.sh", 524288), StatTarget("/work/nested.sql")]


@pytest.mark.parametrize("command", ["psql 3<<'SQL'\nDROP TABLE users;\nSQL",
                                     "psql <<SQL\nDROP TABLE $TABLE;\nSQL"])
def test_nonstdin_and_expanding_heredocs_are_unresolved(command):
    result = shell_report(command, "bash")
    finding(result, "sql-unresolved", "LOW")
    assert not any(f.rule == "sql-drop-object" for f in result.findings)


def test_later_stdin_redirect_replaces_sql_heredoc():
    provider = MemoryEvidenceProvider({"/work/input.sql": "SELECT 1"})
    result = shell_report("psql <<'SQL' < input.sql\nDROP TABLE users;\nSQL", "bash", provider=provider)
    assert result.to_dict() == {}


def test_sqlcmd_multiple_input_files():
    provider = MemoryEvidenceProvider({"/work/a.sql": "DROP TABLE a", "/work/b.sql": "DROP TABLE b"})
    result = shell_report("sqlcmd -i a.sql,b.sql", "bash", provider=provider)
    assert [f.data["objects"] for f in result.findings] == [["a"], ["b"]]


def test_standalone_sql_does_not_need_any_shell_parser(monkeypatch):
    analyzer = Analyzer(AnalyzerConfig(shell=None))
    monkeypatch.setattr(analyzer, "frontend", None)
    monkeypatch.setattr(analyzer, "powershell_frontend", None)
    finding(analyzer.analyze_sql_report("DROP TABLE users"), "sql-drop-object", "HIGH")


def test_submitted_sql_and_clients_are_never_executed(monkeypatch):
    import os
    import subprocess
    def forbidden(*args, **kwargs):
        pytest.fail("Analysis attempted execution")
    monkeypatch.setattr(os, "system", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    finding(report("DROP TABLE users", "postgres"), "sql-drop-object", "HIGH")
    for shell in SHELLS:
        finding(shell_report('psql -c "DROP TABLE users"', shell), "sql-drop-object", "HIGH")


@pytest.mark.parametrize("shell,command", [("bash", "cat script.sql | psql"),
                                          ("powershell", "Get-Content script.sql | psql"),
                                          ("powershell", "Get-Content -Raw script.sql | psql"),
                                          ("cmd", "type script.sql | psql")])
def test_single_unfiltered_file_stream_is_sql(shell, command):
    path = "/work/script.sql" if shell == "bash" else r"D:\work\script.sql"
    provider = MemoryEvidenceProvider({path: "DROP TABLE users"})
    result = shell_report(command, shell, provider=provider)
    assert finding(result, "sql-drop-object", "HIGH").data["source"] == path
    assert provider.queries == [ReadFile(path, 524288)]


@pytest.mark.parametrize("shell,command", [("bash", "cat -n script.sql | psql"),
                                          ("bash", "cat a.sql b.sql | psql"),
                                          ("bash", "grep DROP script.sql | psql"),
                                          ("bash", "cat script.sql | wc -l | psql"),
                                          ("powershell", "Get-Content -TotalCount 1 script.sql | psql"),
                                          ("cmd", "type a.sql b.sql | psql")])
def test_selected_or_transformed_streams_are_not_whole_sql_files(shell, command):
    paths = {"/work/script.sql": "DROP TABLE users", "/work/a.sql": "DROP TABLE users", "/work/b.sql": "SELECT 1",
             r"D:\work\script.sql": "DROP TABLE users", r"D:\work\a.sql": "DROP TABLE users", r"D:\work\b.sql": "SELECT 1"}
    result = shell_report(command, shell, provider=MemoryEvidenceProvider(paths))
    assert not any(f.rule == "sql-drop-object" for f in result.findings)
    assert any(f.rule == "sql-unresolved" for f in result.findings)


def test_cmd_literal_sql_pipeline():
    finding(shell_report("echo DROP TABLE users | psql", "cmd"), "sql-drop-object", "HIGH")


def test_redirected_stdin_overrides_file_pipeline():
    provider = MemoryEvidenceProvider({"/work/outer.sql": "DROP TABLE users", "/work/inner.sql": "SELECT 1"})
    result = shell_report("cat outer.sql | psql < inner.sql", "bash", provider=provider)
    assert result.to_dict() == {}


@pytest.mark.parametrize("shell", ["bash", "powershell"])
def test_readonly_file_stream_is_quiet(shell):
    path = "/work/script.sql" if shell == "bash" else r"D:\work\script.sql"
    command = "cat script.sql | psql" if shell == "bash" else "Get-Content script.sql | psql"
    assert shell_report(command, shell, provider=MemoryEvidenceProvider({path: "SELECT 1"})).to_dict() == {}


@pytest.mark.parametrize("sql", ["EXPLAIN (UNSUPPORTED TRUE) DELETE FROM users", "EXPLAIN (ANALYZE FALSE, ANALYZE TRUE) DELETE FROM users", "EXPLAIN (ANALYZE MAYBE) DELETE FROM users", "EXPLAIN DROP TABLE users"])
def test_unsupported_explain_is_low(sql):
    result = report(sql, "postgres")
    finding(result, "sql-unresolved", "LOW")
    assert result.num_findings == 1


def test_explain_analyze_with_other_options():
    finding(report("EXPLAIN (ANALYZE ON, BUFFERS TRUE, FORMAT JSON) DELETE FROM users", "postgres"), "sql-row-change", "MEDIUM")


def test_privilege_report_is_reviewable_without_sql_body():
    found = finding(report("GRANT SELECT, DELETE ON TABLE users TO app", "postgres"), "sql-privilege-change", "MEDIUM")
    assert found.data["action"] == "grant"
    assert found.data["objects"] == ["users"]
    assert found.data["principals"] == ["app"]
    assert found.data["privileges"] == ["DELETE", "SELECT"]


@pytest.mark.parametrize("sql", ["DELETE FROM ? WHERE id=1", "UPDATE ? SET active=1 WHERE id=1"])
def test_single_target_where_does_not_escalate_for_unknown_object_name(sql):
    result = report(sql, "sqlite")
    finding(result, "sql-unresolved", "LOW")
    finding(result, "sql-row-change", "LOW")
    assert result.level.name == "LOW"


@pytest.mark.parametrize("shell", SHELLS)
def test_database_operands_and_sql_identifiers_do_not_read_files(shell):
    provider = MemoryEvidenceProvider({"/outside/database.db": "DROP TABLE wrong"})
    result = shell_report('sqlite3 /outside/database.db "SELECT * FROM users"', shell, provider=provider)
    assert result.to_dict() == {}
    assert provider.queries == []


@pytest.mark.parametrize("sql", ["CREATE USER IF EXISTS app", "DROP USER IF NOT EXISTS app"])
def test_invalid_identity_condition_is_low(sql):
    result = report(sql, "postgres")
    finding(result, "sql-unresolved", "LOW")
    assert result.num_findings == 1


@pytest.mark.parametrize("sql,dialect", [("REVOKE TABLE SET 1 ; DELETE DELETE", "postgres"),
                                        ("DELETE USER ; TO ANALYZE = ;", "mysql"), ("DELETE SELECT", "sqlite")])
def test_sqlglot_incomplete_mutation_nodes_are_low(sql, dialect):
    result = report(sql, dialect)
    assert result.level.name == "LOW"
    assert all(f.rule == "sql-unresolved" for f in result.findings)


def test_sql_pipeline_inputs_belong_to_their_own_invocations():
    provider = MemoryEvidenceProvider({"/work/a.sql": "DROP TABLE a", "/work/b.sql": "DROP TABLE b"})
    result = shell_report("psql < a.sql | psql < b.sql", "bash", provider=provider)
    assert [f.data["objects"] for f in result.findings] == [["a"], ["b"]]


def test_sql_input_does_not_leak_to_earlier_pipeline_stage():
    provider = MemoryEvidenceProvider({"/work/input.sql": "DROP TABLE users"})
    result = shell_report("psql | cat < input.sql", "bash", provider=provider)
    assert not any(f.rule == "sql-drop-object" for f in result.findings)
    finding(result, "sql-unresolved", "LOW")


@pytest.mark.parametrize("command", ["psql $(psql) <<'SQL'\nDROP TABLE users;\nSQL", "echo 'DROP TABLE users' | psql $(psql)"])
def test_sql_input_does_not_leak_into_command_substitutions(command):
    result = shell_report(command, "bash")
    found = finding(result, "sql-drop-object", "HIGH")
    assert "substitution" not in found.detail
    finding(result, "sql-unresolved", "LOW")
