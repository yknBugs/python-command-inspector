"""In-process CMD lexer; never invokes a shell."""
from ..models import ParsedSource, Span, SyntaxNode
from ..bash.syntax import ParseBudgetExceeded


class CmdFrontend:
    """Small CMD lexer with raw tails retained for builtin operand models."""
    def parse(self, text, max_nodes=65536):
        tokens, diagnostics = [], []
        i = 0
        while i < len(text):
            if text[i] in " \t\r":
                i += 1
                continue
            start = i
            if text[i] in "&|<>()\n":
                operator = text[i:i + 2]
                if operator not in {"&&", "||", ">>", ">&", "<&"}:
                    operator = text[i]
                i += len(operator)
                tokens.append(SyntaxNode("operator", Span(start, i), text=operator))
                continue
            quoted = False
            while i < len(text):
                char = text[i]
                if char == "^" and not quoted and i + 1 < len(text):
                    i += 2
                    continue
                if char == '"':
                    quoted = not quoted
                elif not quoted and char in " \t\r\n&|<>()":
                    break
                i += 1
            if quoted:
                diagnostics.append(Span(start, i))
            tokens.append(SyntaxNode("word", Span(start, i), text=text[start:i]))
            if len(tokens) > max_nodes:
                raise ParseBudgetExceeded
        # Redirections belong to the command even when placed before/between
        # operands. A descriptor is special only when adjacent to its operator.
        children, parts, cursor = [], [], 0
        def flush():
            if parts:
                span = Span(parts[0].span.start, parts[-1].span.end)
                children.append(SyntaxNode("command", span, tuple(parts), text[span.start:span.end]))
                parts.clear()
        while cursor < len(tokens):
            token = tokens[cursor]
            if token.kind == "operator" and token.text in {">", ">>", "<", ">&", "<&"}:
                redirect = []
                if parts and parts[-1].kind == "word" and parts[-1].text.isdigit() and parts[-1].span.end == token.span.start:
                    fd = parts.pop()
                    redirect.append(SyntaxNode("file_descriptor", fd.span, text=fd.text))
                redirect.append(token)
                if cursor + 1 < len(tokens) and tokens[cursor + 1].kind == "word":
                    cursor += 1
                    redirect.append(tokens[cursor])
                else:
                    diagnostics.append(token.span)
                span = Span(redirect[0].span.start, redirect[-1].span.end)
                parts.append(SyntaxNode("redirection", span, tuple(redirect), text[span.start:span.end]))
            elif token.kind == "operator":
                flush()
                children.append(token)
            else:
                parts.append(token)
            cursor += 1
        flush()
        # Count actual public nodes, including synthetic command/redirection nodes.
        pending, count = list(children), 1
        while pending:
            item = pending.pop()
            count += 1
            if count > max_nodes:
                raise ParseBudgetExceeded
            pending.extend(item.children)
        return ParsedSource(SyntaxNode("program", Span(0, len(text)), tuple(children), text), tuple(diagnostics), "cmd-python-subset")
