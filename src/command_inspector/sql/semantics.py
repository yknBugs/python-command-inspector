"""SQL AST facts: SQL objects are identifiers, never filesystem paths."""
from collections import deque
from ..models import Fact


class SQLBuilder:
    def __init__(self, dialect=None, *, source="sql", context="invoked_now", guard="", node_limit=65536):
        self.dialect = dialect or "generic"
        self.source, self.context, self.guard = source, context, guard
        self.facts = []
        self.node_limit = node_limit

    def emit(self, operation, index, objects=(), *, kind="statement", flags=(), reason=None):
        self.facts.append(Fact("sql", operation, tuple(objects),
                               flags=frozenset({f"statement:{index}", f"dialect:{self.dialect}",
                                                f"object:{kind}", *flags}),
                               payload=reason, source=self.source, context=self.context, guard=self.guard))

    def unresolved(self, index, reason):
        self.emit("sql-unresolved", index, reason=reason)

    @staticmethod
    def name(node):
        from sqlglot import exp
        if isinstance(node, (exp.Schema, exp.UserDefinedFunction)):
            node = node.this
        if isinstance(node, (exp.Table, exp.Column)):
            parts = node.parts
        elif isinstance(node, exp.Identifier):
            parts = [node]
        else:
            return None
        if not parts or any(not isinstance(p, exp.Identifier) for p in parts):
            return None
        return ".".join(p.name for p in parts)

    def objects(self, nodes, index):
        names = [self.name(n) for n in nodes if n is not None]
        if not names or any(n is None for n in names):
            self.unresolved(index, "unresolved_object")
        return tuple(n for n in names if n is not None)

    def build(self, statements):
        # Missing dependency/dialect and parse errors do not require importing exp.
        for statement in statements:
            if statement.reason:
                self.unresolved(statement.index, statement.reason)
            else:
                self.statement(statement)
        return tuple(self.facts)

    def statement(self, statement):
        from sqlglot import exp
        root, index = statement.expression, statement.index
        # EXPLAIN does not run its subject. Some dialects represent it as a
        # Describe; others use Command, handled by the token fallback below.
        if isinstance(root, exp.Describe):
            if str(root.args.get("style") or "").upper() == "ANALYZE":
                from .syntax import SQLStatement
                self.statement(SQLStatement(index, root.this, statement.tokens, source=statement.source))
            return
        if isinstance(root, exp.Command):
            self.command(statement.tokens, index, statement.source)
            return
        if isinstance(root, exp.Alter) and any(isinstance(a, exp.Command) for a in root.args.get("actions", ())):
            columns = self.column_removals(statement.tokens)
            table = self.name(root.this)
            if columns and table:
                self.emit("sql-remove-schema", index, [table + "." + c for c in columns], kind="column", flags={"action:drop"})
                return
        supported = (exp.Query, exp.Values, exp.Insert, exp.Update, exp.Delete, exp.Merge,
                     exp.Create, exp.Drop, exp.Alter, exp.TruncateTable,
                     exp.Grant, exp.Revoke, exp.Show, exp.Transaction, exp.Commit,
                     exp.Rollback, exp.Pragma, exp.Block)
        if not isinstance(root, supported):
            self.unresolved(index, "unsupported_statement")
            return
        if isinstance(root, exp.Pragma):
            # PRAGMA includes writes as well as metadata queries. Only explicitly
            # modeled metadata queries are silent.
            value = root.this
            key = value.this.name if isinstance(value, exp.EQ) else value.name
            if key.casefold() not in {"table_info", "table_xinfo", "index_info", "index_xinfo",
                                      "index_list", "foreign_key_list", "database_list", "compile_options"}:
                self.unresolved(index, "unsupported_pragma")
            return
        stack = [(root, None)]
        while stack:
            node, parent_table = stack.pop()
            if isinstance(node, exp.Describe):
                if str(node.args.get("style") or "").upper() == "ANALYZE":
                    stack.append((node.this, parent_table))
                continue
            if isinstance(node, exp.Command):
                self.unresolved(index, "unsupported_nested_statement")
                continue
            if isinstance(node, (exp.Execute, exp.ExecuteSql)):
                self.unresolved(index, "dynamic_sql")
                continue
            if isinstance(node, (exp.Grant, exp.Revoke)):
                securable = node.args.get("securable")
                names = (self.name(securable),) if self.name(securable) else ()
                flags = {"action:grant" if isinstance(node, exp.Grant) else "action:revoke"}
                flags.update("principal:" + name for p in node.args.get("principals", ()) if (name := self.name(p.this)))
                flags.update("privilege:" + p.this.name for p in node.args.get("privileges", ()) if p.this.name)
                self.emit("sql-privilege-change", index, names, kind="privilege", flags=flags)
            elif isinstance(node, exp.TruncateTable):
                self.emit("sql-truncate", index, self.objects(node.expressions, index), kind="table", flags={"action:truncate"})
            elif isinstance(node, exp.Drop):
                kind = str(node.args.get("kind") or "object").casefold()
                objects = self.objects(node.args.get("tables") or [node.this], index)
                if kind == "column" and parent_table:
                    objects = tuple(parent_table + "." + name for name in objects)
                rule = "sql-drop-object" if kind in {"table", "database", "user", "login", "role"} else "sql-remove-schema" if kind in {"schema", "column"} else "sql-schema-change"
                self.emit(rule, index, objects, kind=kind, flags={"action:drop"})
            elif isinstance(node, exp.Create):
                kind = str(node.args.get("kind") or "object").casefold()
                rule = "sql-create-identity" if kind in {"database", "user", "login", "role"} else "sql-truncate" if node.args.get("replace") and kind == "table" else "sql-schema-change"
                self.emit(rule, index, self.objects([node.this], index), kind=kind,
                          flags={"action:create", "replacement"} if node.args.get("replace") else {"action:create"})
                if kind in {"function", "procedure", "trigger"}:
                    # Defining a routine does not run its body. Server-side
                    # procedural languages are outside this SQL statement layer.
                    self.unresolved(index, "routine_body_uninspected")
                    continue
            elif isinstance(node, exp.Alter):
                parent_table = self.name(node.this)
                actions = node.args.get("actions") or []
                if not actions or any(not isinstance(a, exp.Drop) for a in actions):
                    self.emit("sql-privilege-change" if str(node.args.get("kind")).upper() in {"USER", "ROLE", "LOGIN"} else "sql-schema-change",
                              index, self.objects([node.this], index), kind=str(node.args.get("kind") or "table").casefold(), flags={"action:alter"})
            elif isinstance(node, (exp.Delete, exp.Update)):
                if not isinstance(node.this, exp.Expr):
                    # SQLGlot can represent malformed DELETE without FROM with
                    # this=False. That is incomplete syntax, not a row mutation.
                    self.unresolved(index, "incomplete_mutation")
                    continue
                targets = node.args.get("tables") or [node.this]
                tables = [node.this]
                pending = deque(node.this.args.get("joins") or ())
                while pending:
                    joined = pending.popleft().this
                    tables.append(joined)
                    pending.extend(joined.args.get("joins") or ())
                aliases = {t.alias_or_name: t for t in tables if isinstance(t, exp.Table)}
                uncertain = False
                if isinstance(node, exp.Delete) and node.args.get("tables"):
                    targets = [aliases.get(t.name, t) for t in targets]
                elif isinstance(node, exp.Update) and len(tables) > 1:
                    # Resolve assignment aliases to real tables, rather than
                    # counting read-only JOIN/subquery tables as changed objects.
                    qualifiers = [e.this.table if isinstance(e.this, exp.Column) else None for e in node.expressions]
                    uncertain = not qualifiers or any(q not in aliases for q in qualifiers)
                    targets = tables if uncertain else [aliases[q] for q in dict.fromkeys(qualifiers)]
                objects = self.objects(targets, index)
                single = len(targets) == 1 and not uncertain
                flags = {"has_where"} if node.args.get("where") is not None else set()
                if single:
                    flags.add("single_target")
                self.emit("sql-row-change", index, objects, kind="table", flags=flags | {"delete" if isinstance(node, exp.Delete) else "update"})
            elif isinstance(node, exp.Insert):
                self.emit("sql-row-change", index, self.objects([node.this], index), kind="table",
                          flags={"insert", "overwrite"} if node.args.get("overwrite") or node.args.get("alternative") == "REPLACE" else {"insert"})
            elif isinstance(node, exp.Merge):
                self.emit("sql-row-change", index, self.objects([node.this], index), kind="table", flags={"merge"})
                # MERGE action nodes are clauses, not independent statements.
                stack.extend((c, parent_table) for c in node.iter_expressions() if not isinstance(c, exp.Whens))
                continue
            elif isinstance(node, exp.Into):
                self.emit("sql-schema-change", index, self.objects([node.this], index), kind="table", flags={"action:select_into"})
            stack.extend((child, parent_table) for child in reversed(list(node.iter_expressions())))

    @staticmethod
    def keyword(token):
        return token.text.upper() if token.token_type.name not in {"STRING", "IDENTIFIER", "HEREDOC_STRING"} else ""

    def command(self, tokens, index, source):
        """Narrow token handling for SQLGlot's opaque administrative commands.

        No regex scan of raw SQL: string/comment contents cannot become verbs.
        Unsupported options remain visible as LOW coverage findings.
        """
        words = [self.keyword(t) for t in tokens]
        if not words:
            return
        if words[0] == "EXPLAIN":
            offset, executes = 1, False
            if len(words) > 1 and words[1] == "ANALYZE":
                offset, executes = 2, True
            elif len(words) > 1 and tokens[1].token_type.name == "L_PAREN":
                end = next((i for i in range(2, len(tokens)) if tokens[i].token_type.name == "R_PAREN"), None)
                if end is None:
                    self.unresolved(index, "unsupported_explain")
                    return
                executes = self.explain_options(tokens[2:end])
                if executes is None:
                    self.unresolved(index, "unsupported_explain_options")
                    return
                offset = end + 1
            if offset >= len(tokens):
                self.unresolved(index, "unsupported_explain")
                return
            from sqlglot import Dialect
            from sqlglot.errors import ParseError
            selected = Dialect.get_or_raise("" if self.dialect == "generic" else self.dialect)
            class QuietParser(selected.parser_class):
                def _warn_unsupported(self):
                    pass
            try:
                from .syntax import SQLStatement
                parsed = QuietParser(dialect=selected).parse(list(tokens[offset:]), source)
                if len(parsed) != 1 or parsed[0] is None:
                    raise ValueError
                if sum(1 for _ in parsed[0].walk()) > self.node_limit:
                    self.unresolved(index, "syntax_budget")
                    return
                from sqlglot import exp
                if not isinstance(parsed[0], (exp.Query, exp.Values, exp.Insert, exp.Update, exp.Delete, exp.Merge, exp.Create)) or isinstance(parsed[0], exp.Create) and parsed[0].args.get("expression") is None:
                    self.unresolved(index, "unsupported_explain_subject")
                    return
                if executes:
                    self.statement(SQLStatement(index, parsed[0], tuple(tokens[offset:]), source=source))
            except (ParseError, ValueError, RecursionError):
                self.unresolved(index, "unsupported_explain")
            return
        if len(words) < 3:
            self.unresolved(index, "unsupported_statement")
            return
        verb, kind = words[:2]
        if verb in {"CREATE", "DROP", "ALTER"} and kind in {"USER", "LOGIN", "ROLE"}:
            pos = 2
            if words[pos:pos + 2] == ["IF", "EXISTS"] and verb in {"DROP", "ALTER"}:
                pos += 2
            elif words[pos:pos + 3] == ["IF", "NOT", "EXISTS"] and verb == "CREATE":
                pos += 3
            elif words[pos] == "IF":
                self.unresolved(index, "unsupported_identity_statement")
                return
            names = []
            while pos < len(tokens):
                token = tokens[pos]
                if token.token_type.name not in {"VAR", "IDENTIFIER", "STRING"}:
                    break
                names.append(token.text)
                pos += 1
                if pos + 1 < len(tokens) and tokens[pos].text == "@" and tokens[pos + 1].token_type.name in {"VAR", "IDENTIFIER", "STRING"}:
                    names[-1] += "@" + tokens[pos + 1].text
                    pos += 2
                if pos < len(tokens) and tokens[pos].token_type.name == "COMMA":
                    pos += 1
                    if pos == len(tokens):
                        self.unresolved(index, "unsupported_identity_statement")
                        return
                else:
                    break
            if not names:
                self.unresolved(index, "unsupported_identity_statement")
                return
            if not self.identity_options(tokens[pos:], verb):
                self.unresolved(index, "unsupported_identity_options")
                return
            rule = "sql-drop-object" if verb == "DROP" else "sql-create-identity" if verb == "CREATE" else "sql-privilege-change"
            self.emit(rule, index, names, kind=kind.casefold(), flags={"action:" + verb.casefold()})
            return
        if verb in {"GRANT", "REVOKE", "DENY"} and (("FROM" if verb == "REVOKE" else "TO") in words[1:]):
            split = words.index("FROM" if verb == "REVOKE" else "TO")
            if split > 1 and split + 1 < len(tokens):
                end = words.index("ON") if "ON" in words else split
                privileges = {"ALL", "PRIVILEGES", "SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER", "CREATE", "DROP", "ALTER", "INDEX", "EXECUTE", "USAGE", "CONNECT", "TEMPORARY", "TEMP", "OPTION", "GRANT", "FOR", "CONTROL", "VIEW", "DEFINITION", "SHOW", "DATABASES", "PROCESS", "FILE", "RELOAD", "SHUTDOWN", "SUPER", "EVENT", "LOCK", "TABLES", "REPLICATION", "CLIENT", "SLAVE"}
                if "ON" in words and any(w and w not in privileges for w in words[1:end]) or end <= 1:
                    self.unresolved(index, "unsupported_privilege_statement")
                    return
                self.emit("sql-privilege-change", index, kind="privilege", flags={"action:" + verb.casefold()})
                return
        if verb == "TRUNCATE" and kind in {"SCHEMA", "DATABASE"} and len(tokens) == 3 and tokens[2].token_type.name in {"VAR", "IDENTIFIER"}:
            self.emit("sql-truncate", index, [tokens[2].text], kind=kind.casefold(), flags={"action:truncate"})
            return
        if verb == "ALTER" and kind == "AUTHORIZATION":
            if "TO" in words and words.index("TO") + 1 < len(tokens):
                self.emit("sql-privilege-change", index, kind="privilege", flags={"action:alter_authorization"})
                return
        if verb == "ALTER" and kind in {"TABLE", "SCHEMA", "DATABASE", "VIEW", "SEQUENCE", "FUNCTION"} and "OWNER" in words:
            owner = words.index("OWNER")
            name, end = self.token_name(tokens, 2)
            if name and end == owner and words[owner:owner + 2] == ["OWNER", "TO"] and owner + 3 == len(tokens) and tokens[-1].token_type.name in {"VAR", "IDENTIFIER"}:
                self.emit("sql-privilege-change", index, [name], kind=kind.casefold(), flags={"action:alter_owner"})
                return
        if words[:3] == ["ALTER", "DEFAULT", "PRIVILEGES"]:
            offset = next((i for i, w in enumerate(words[3:], 3) if w in {"GRANT", "REVOKE"}), None)
            if offset is not None:
                self.command(tokens[offset:], index, source)
                return
        self.unresolved(index, "unsupported_statement")

    def explain_options(self, tokens):
        booleans = {"ANALYZE", "VERBOSE", "COSTS", "SETTINGS", "BUFFERS", "WAL", "TIMING", "SUMMARY", "GENERIC_PLAN", "MEMORY"}
        options, seen, pos, executes = {"FORMAT": {"TEXT", "XML", "JSON", "YAML"}, "SERIALIZE": {"TEXT", "BINARY", "NONE"}}, set(), 0, False
        while pos < len(tokens):
            key = self.keyword(tokens[pos])
            if key in seen or key not in booleans | options.keys():
                return None
            seen.add(key)
            pos += 1
            value = True
            if key in options:
                if pos == len(tokens) or self.keyword(tokens[pos]) not in options[key]:
                    return None
                pos += 1
            elif pos < len(tokens) and self.keyword(tokens[pos]) in {"TRUE", "FALSE", "ON", "OFF", "0", "1"}:
                value = self.keyword(tokens[pos]) not in {"FALSE", "OFF", "0"}
                pos += 1
            if key == "ANALYZE":
                executes = value
            if pos < len(tokens):
                if tokens[pos].token_type.name != "COMMA" or pos + 1 == len(tokens):
                    return None
                pos += 1
        return executes if seen else None

    def identity_options(self, tokens, verb):
        if verb == "DROP":
            return not tokens or len(tokens) == 1 and self.keyword(tokens[0]) in {"CASCADE", "RESTRICT"}
        if not tokens:
            return verb == "CREATE"
        pos = 0
        if self.keyword(tokens[0]) == "WITH":
            pos += 1
        start = pos
        switches = {"LOGIN", "NOLOGIN", "SUPERUSER", "NOSUPERUSER", "CREATEDB", "NOCREATEDB", "CREATEROLE", "NOCREATEROLE", "INHERIT", "NOINHERIT", "REPLICATION", "NOREPLICATION", "BYPASSRLS", "NOBYPASSRLS"}
        while pos < len(tokens):
            word = self.keyword(tokens[pos])
            if word in switches:
                pos += 1
            elif word == "PASSWORD":
                pos += 1
                if pos < len(tokens) and tokens[pos].token_type.name == "EQ":
                    pos += 1
                if pos == len(tokens) or tokens[pos].token_type.name not in {"STRING", "NULL"}:
                    return False
                pos += 1
            elif word == "IDENTIFIED" and pos + 2 < len(tokens) and self.keyword(tokens[pos + 1]) in {"BY", "AS"} and tokens[pos + 2].token_type.name == "STRING":
                pos += 3
            elif word in {"DEFAULT_DATABASE", "CHECK_POLICY", "CHECK_EXPIRATION"} and pos + 2 < len(tokens) and tokens[pos + 1].token_type.name == "EQ" and tokens[pos + 2].token_type.name in {"VAR", "IDENTIFIER", "ON", "OFF"}:
                pos += 3
            else:
                return False
            if pos < len(tokens) and tokens[pos].token_type.name == "COMMA":
                pos += 1
                if pos == len(tokens):
                    return False
        return pos > start

    @staticmethod
    def token_name(tokens, pos):
        parts = []
        while pos < len(tokens) and tokens[pos].token_type.name in {"VAR", "IDENTIFIER"}:
            parts.append(tokens[pos].text)
            pos += 1
            if pos + 1 < len(tokens) and tokens[pos].token_type.name == "DOT" and tokens[pos + 1].token_type.name in {"VAR", "IDENTIFIER"}:
                pos += 1
            else:
                break
        return ".".join(parts), pos

    def column_removals(self, tokens):
        words = [self.keyword(t) for t in tokens]
        if words[:2] != ["ALTER", "TABLE"]:
            return None
        table, pos = self.token_name(tokens, 2)
        columns = []
        while table and pos < len(tokens) and words[pos] == "DROP":
            pos += 1
            if pos < len(tokens) and words[pos] == "COLUMN":
                pos += 1
            if words[pos:pos + 2] == ["IF", "EXISTS"]:
                pos += 2
            name, pos = self.token_name(tokens, pos)
            if not name:
                return None
            columns.append(name)
            if pos < len(tokens) and words[pos] in {"CASCADE", "RESTRICT"}:
                pos += 1
            if pos == len(tokens):
                return columns
            if tokens[pos].token_type.name != "COMMA":
                return None
            pos += 1
        return None
