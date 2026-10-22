"""Static SQL client source selection, shared by Bash, PowerShell and CMD."""
from dataclasses import replace
from ..models import Fact, Value

SQL_CLIENTS = {"psql", "mysql", "mariadb", "sqlite3", "sqlcmd"}


def describe_sql(name, args, cwd=None):
    from ..shared.options import CommandSpec, parse_options
    from ..shared.commands import resolve_path
    specs = {
        "psql": CommandSpec("aAbceEfFhHlLnoOpPqRsStTUvVwWxXz0?", ("--command", "--file", "--host", "--port", "--username", "--dbname", "--set", "--output", "--log-file", "--no-psqlrc", "--no-password", "--quiet", "--help", "--version", "--"),
                            ("-c", "-f", "-h", "-p", "-U", "-d", "-v", "-F", "-L", "-o", "-P", "-R", "-T", "--command", "--file", "--host", "--port", "--username", "--dbname", "--set", "--output", "--log-file")),
        "mysql": CommandSpec("ABbceEfhHnNpPqrsStuvVw", ("--execute", "--database", "--host", "--port", "--user", "--password", "--batch", "--silent", "--skip-column-names", "--help", "--version", "--"),
                             ("-e", "-D", "-h", "-P", "-u", "--execute", "--database", "--host", "--port", "--user", "--password")),
        "sqlite3": CommandSpec("", ("-cmd", "-init", "-readonly", "-readwrite", "-batch", "-bail", "-echo", "-header", "-noheader", "-csv", "-json", "-line", "-list", "-column", "-table", "-separator", "-nullvalue", "-help", "--help", "-version", "--version", "--"),
                               ("-cmd", "-init", "-separator", "-nullvalue")),
        "sqlcmd": CommandSpec("abCeEfghiIkKlLmNopPqQrRsStuvVwWxXyYzZ?", ("--help", "--version", "--"),
                              tuple("-" + c for c in "iQqSUdPHswtvVofyYlL")),
    }
    client = "mysql" if name == "mariadb" else name
    # MySQL short -p consumes only an attached password; a separate word is
    # a database operand. Keep passwords away from both parsing and reports.
    if client == "mysql":
        args = tuple(Value("-p") if a.text and a.text.startswith("-p") and not a.text.startswith("--") else a for a in args)
    operands, flags, bound, unknown = parse_options(args, specs[client])
    dialect = {"psql": "postgres", "mysql": "mysql", "sqlite3": "sqlite", "sqlcmd": "tsql"}[client]
    if flags & {"--help", "--version", "-?", "-help", "-version"} or client in {"psql", "mysql"} and flags & {"-V"}:
        return []
    outputs = []
    output_keys = {"psql": {"-o", "--output", "-L", "--log-file"}, "sqlcmd": {"-o"}}.get(client, set())
    last_log = next((index for index in range(len(bound.occurrences) - 1, -1, -1) if bound.occurrences[index][0] in {"-L", "--log-file"}), None)
    for index, (option, value) in enumerate(bound.occurrences):
        if option not in output_keys:
            continue
        if option in {"-L", "--log-file"} and index != last_log:
            continue
        if client == "psql" and option in {"-o", "--output"} and value.text and value.text.startswith("|"):
            outputs.append(Fact("unresolved", "execution-content-unavailable", payload="SQL client output pipe command is not inspected"))
            outputs.append(Fact("invalidate", "unknown_pipe_effect"))
        else:
            path = resolve_path(value, cwd)
            outputs.append(Fact("write", "append" if option in {"-L", "--log-file"} else "overwrite",
                                targets=(path,) if path else (), values=(value,), flags=frozenset({"runtime_output"})))
    for option in output_keys & set(unknown):
        outputs.append(Fact("write", "transform", values=(Value(None, "missing_output_destination"),)))
    if unknown:
        return outputs + [Fact("sql", "sql-unresolved", flags=frozenset({f"dialect:{dialect}", "statement:0", "object:statement"}), payload="unsupported_client_options")]
    sources = []
    def inline(value):
        sources.append(Fact("sql_source", dialect, payload=value.text, flags=frozenset({"inline"})))
    def file(value):
        sources.append(Fact("sql_source", dialect, values=(value,), flags=frozenset({"stdin" if value.text == "-" else "file"})))
    code_keys = {"psql": {"-c", "--command"}, "mysql": {"-e", "--execute"}, "sqlite3": {"-cmd"}, "sqlcmd": {"-q", "-Q"}}[client]
    file_keys = {"psql": {"-f", "--file"}, "mysql": set(), "sqlite3": {"-init"}, "sqlcmd": {"-i"}}[client]
    for option, value in bound.occurrences:
        if option in code_keys:
            inline(value)
        elif option in file_keys:
            if client == "sqlcmd" and value.text:
                for path in value.text.split(","):
                    file(Value(path))
            else:
                file(value)
    if client == "sqlite3" and len(operands) > 1:
        for value in operands[1:]:
            inline(value)
    # sqlite -cmd/-init and sqlcmd -q continue consuming stdin. Other clients'
    # explicit execution options replace stdin as a SQL source.
    if not sources or client == "sqlite3" and len(operands) <= 1 or client == "sqlcmd" and "-q" in flags:
        sources.append(Fact("sql_source", dialect, flags=frozenset({"stdin"})))
    return outputs + sources


def attach_sql_input(facts, *, payload=None, values=None, override=False, guard=None, invocation=None):
    """Route only to the current invocation's SQL stdin source."""
    for index, fact in enumerate(facts):
        if guard is not None and fact.guard != guard or invocation is not None and f"sql_invocation:{invocation}" not in fact.flags:
            continue
        if fact.kind != "sql_source" or not fact.flags & {"stdin", "stdin_origin"} or not override and "stdin_redirected" in fact.flags:
            continue
        flags = (fact.flags - {"stdin", "inline", "file"}) | {"stdin_redirected", "stdin_origin"}
        if values is not None:
            facts[index] = replace(fact, values=tuple(values), payload=None, flags=flags | {"file"})
        else:
            facts[index] = replace(fact, payload=payload, flags=flags | {"inline"})
    return facts


def sql_file_input(facts):
    """A single unfiltered file forwarded by cat/Get-Content/TYPE.

    Callers establish the command identity. Selection/formatting options and
    wildcard/multiple operands must not become a claim about the entire file.
    """
    reads = [f for f in facts if f.kind == "read" and f.operation == "ingest"]
    if len(reads) != 1 or reads[0].flags - {"output_to_pipe"} or len(reads[0].values) != 1:
        return None
    value = reads[0].values[0]
    return (value,) if value.text is not None and not value.pattern else None
