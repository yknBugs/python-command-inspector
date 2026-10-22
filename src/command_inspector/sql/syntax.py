"""Bounded, non-executing SQLGlot frontend. SQLGlot is an optional dependency."""
from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class SQLStatement:
    index: int
    expression: object | None = field(default=None, repr=False)
    tokens: tuple = field(default=(), repr=False)
    reason: str | None = None
    source: str = field(default="", repr=False)


class SQLFrontend:
    def parse(self, text: str, dialect: str | None, node_limit: int) -> tuple[SQLStatement, ...]:
        try:
            from sqlglot import Dialect
            from sqlglot import exp
            from sqlglot.errors import ParseError, TokenError
        except ImportError:
            return (SQLStatement(1, reason="missing_parser"),)
        try:
            selected = Dialect.get_or_raise(dialect or "")
        except ValueError:
            return (SQLStatement(1, reason="unsupported_dialect"),)

        # SQLGlot 30.21.0's fallback warning includes raw SQL (possibly passwords).
        # Suppress it locally, without changing process-wide logging configuration.
        class QuietParser(selected.parser_class):
            def _warn_unsupported(self):
                pass

        class StatementTokenizer(selected.tokenizer_class):
            # Keep opaque-command tails tokenized too, for bounded, dialect-aware
            # EXPLAIN/admin handling and reliable statement separation.
            COMMANDS = set()

        try:
            tokens = StatementTokenizer(dialect=selected).tokenize(text)
        except (TokenError, RecursionError):
            return (SQLStatement(1, reason="tokenization_failed"),)
        if len(tokens) > node_limit:
            return (SQLStatement(1, reason="syntax_budget"),)
        chunks, chunk, routine = [], [], False
        def is_routine_prefix(items):
            kinds = [t.token_type.name for t in items[:4]]
            if kinds[:3] == ["CREATE", "OR", "ALTER"]:
                kinds = kinds[2:]
            return len(kinds) >= 2 and kinds[0] in {"CREATE", "ALTER"} and kinds[1] in {"PROCEDURE", "FUNCTION", "TRIGGER"}
        skip_count = -1
        for token_index, token in enumerate(tokens):
            if token_index == skip_count:
                continue
            # Tokenization distinguishes separators from strings, identifiers,
            # comments and PostgreSQL dollar-quoted literals.
            # Comments are absent from the token stream. A batch delimiter may
            # contain GO, an optional positive repeat count, and comments only.
            go = False
            if dialect == "tsql" and token.token_type.name == "COMMAND" and token.text.upper() == "GO":
                line_start = text.rfind("\n", 0, token.start) + 1
                line_end = text.find("\n", token.end + 1)
                if line_end < 0:
                    line_end = len(text)
                next_index = token_index + 1
                count_index = None
                if next_index < len(tokens) and tokens[next_index].start < line_end:
                    count = tokens[next_index]
                    if count.token_type.name == "NUMBER" and count.text.isascii() and count.text.isdecimal() and count.text.strip("0"):
                        count_index = next_index
                        next_index += 1
                go = (token_index == 0 or tokens[token_index - 1].end < line_start) and (
                    next_index == len(tokens) or tokens[next_index].start >= line_end)
                if go and count_index is not None:
                    skip_count = count_index
            if go or token.token_type.name == "SEMICOLON" and not routine:
                if chunk:
                    chunks.append((chunk, routine))
                    chunk = []
                routine = False
            else:
                chunk.append(token)
                if dialect == "tsql" and is_routine_prefix(chunk):
                    # A routine definition owns the rest of its client batch,
                    # including semicolons and optional BEGIN/END. Do not expose
                    # its deferred body as immediate operations.
                    routine = True
        if chunk:
            chunks.append((chunk, routine))
        result, nodes = [], 0
        for index, (chunk, routine) in enumerate(chunks, 1):
            if routine:
                result.append(SQLStatement(index, reason="routine_body_uninspected"))
                continue
            try:
                opaque = chunk[0].token_type.name == "COMMAND" or chunk[0].text.upper() == "DENY" and chunk[0].token_type.name == "VAR"
                expressions = [exp.Command(this=chunk[0].text.upper())] if opaque else QuietParser(dialect=selected).parse(chunk, text)
                if len(expressions) != 1 or expressions[0] is None:
                    result.append(SQLStatement(index, reason="unsupported_statement"))
                    continue
                expression = expressions[0]
                for _ in expression.walk():
                    nodes += 1
                    if nodes > node_limit:
                        return (*result, SQLStatement(index, reason="syntax_budget"))
                result.append(SQLStatement(index, expression, tuple(chunk), source=text))
            except (ParseError, RecursionError):
                # Parse independently: a malformed statement must not conceal a
                # subsequent, valid DROP. Never export parser exception strings.
                result.append(SQLStatement(index, reason="parse_failed"))
        return tuple(result)
