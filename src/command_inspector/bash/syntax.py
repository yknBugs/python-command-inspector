"""Tree-sitter adapter. Vendor nodes and byte offsets do not leave this module."""
import re
from ..models import ParsedSource, Span, SyntaxNode, AnalysisError


class FrontendUnavailable(Exception):
    pass


class ParseBudgetExceeded(Exception):
    pass


class BashFrontend:
    def __init__(self):
        try:
            from tree_sitter import Language, Parser
            import tree_sitter_bash
        except ImportError:
            raise FrontendUnavailable from None
        self.parser = Parser(Language(tree_sitter_bash.language()))

    def parse(self, text: str, max_nodes: int = 65536) -> ParsedSource:
        raw = text.encode("utf-8")
        offsets = [0] * (len(raw) + 1)
        byte = 0
        for char, value in enumerate(text):
            for _ in value.encode("utf-8"):
                offsets[byte] = char
                byte += 1
        offsets[byte] = len(text)
        tree = self.parser.parse(raw)
        inspected = 0
        if text and not text.endswith("\n") and tree.root_node.has_error:
            # At EOF, the pinned grammar can treat an unterminated heredoc's
            # last line as shell commands. A virtual newline recovers its body
            # only when the sole remaining error is the missing EOF delimiter.
            candidate = self.parser.parse(raw + b"\n")
            pending, valid, missing_end = [candidate.root_node], True, False
            while pending:
                part = pending.pop()
                inspected += 1
                if inspected > max_nodes:
                    raise ParseBudgetExceeded
                if part.type == "ERROR":
                    valid = False
                    break
                if part.is_missing:
                    eof_end = part.type == "heredoc_end" and part.start_byte == len(raw) + 1
                    valid &= eof_end
                    missing_end |= eof_end
                pending.extend(part.children)
            if valid and missing_end:
                tree = candidate
                offsets.append(len(text))
        diagnostics = []
        # Iterative postorder conversion handles deeply nested vendor trees.
        pending = [(tree.root_node, False)]
        converted = {}
        count = inspected
        while pending:
            node, ready = pending.pop()
            if not ready:
                count += 1
                if count > max_nodes:
                    raise ParseBudgetExceeded
                pending.append((node, True))
                pending.extend((child, False) for child in reversed(node.children))
                continue
            span = Span(offsets[node.start_byte], offsets[node.end_byte])
            if node.type == "ERROR" or node.is_missing:
                diagnostics.append(span)
            converted[node.id] = SyntaxNode(node.type, span, tuple(converted[c.id] for c in node.children),
                                            text[span.start:span.end])
            if node.type == "command":
                repaired, added = self.repair_assignment_boundary(converted[node.id], max_nodes - count)
                count += added
                if count > max_nodes:
                    raise ParseBudgetExceeded
                converted[node.id] = repaired
            if node.type == "redirected_statement":
                # tree-sitter-bash 0.25 can omit a standalone '-' immediately
                # before a heredoc (e.g. psql -f - <<EOF). Recover only this exact
                # literal gap, never tokenize arbitrary unparsed shell text.
                current = converted[node.id]
                children = list(current.children)
                for index in range(len(children) - 1):
                    command, redirect = children[index:index + 2]
                    gap = text[command.span.end:redirect.span.start]
                    if command.kind == "command" and redirect.kind == "heredoc_redirect" and gap.strip() == "-":
                        start = command.span.end + gap.index("-")
                        word = SyntaxNode("word", Span(start, start + 1), text="-")
                        children[index] = SyntaxNode(command.kind, Span(command.span.start, start + 1),
                                                     (*command.children, word), text[command.span.start:start + 1])
                converted[node.id] = SyntaxNode(current.kind, current.span, tuple(children), current.text)
            if node.type == "heredoc_body":
                # tree-sitter-bash 0.25 exposes $(...) here but can leave legacy
                # backticks as plain text. Recover only uncovered, unescaped
                # pairs through the same parser; never evaluate their contents.
                current = converted[node.id]
                children = list(current.children)
                cursor = span.start
                while cursor < span.end:
                    covering = next((c for c in current.children
                                     if c.span.start <= cursor < c.span.end), None)
                    if covering and covering.kind != "heredoc_content":
                        cursor = covering.span.end
                        continue
                    if text[cursor] == "\\":
                        cursor += 2
                        continue
                    if text[cursor] != "`":
                        cursor += 1
                        continue
                    end = cursor + 1
                    while end < span.end:
                        if text[end] == "\\":
                            end += 2
                        elif text[end] == "`":
                            break
                        else:
                            end += 1
                    if end >= span.end:
                        break
                    recovered = self.parse(text[cursor:end + 1], max_nodes - count)
                    search = [recovered.root]
                    while search:
                        part = search.pop()
                        if part.kind == "command_substitution":
                            def shifted(item):
                                nonlocal count
                                count += 1
                                if count > max_nodes:
                                    raise ParseBudgetExceeded
                                return SyntaxNode(item.kind, Span(item.span.start + cursor, item.span.end + cursor),
                                                  tuple(shifted(c) for c in item.children), item.text)
                            children.append(shifted(part))
                            break
                        search.extend(part.children)
                    cursor = end + 1
                converted[node.id] = SyntaxNode(current.kind, span,
                                                tuple(sorted(children, key=lambda c: c.span.start)), current.text)
        return ParsedSource(converted[tree.root_node.id], tuple(diagnostics))

    def repair_assignment_boundary(self, command, remaining_nodes):
        """Recover the pinned grammar's split in `X=$W/a:$W/b command`.

        An assignment and command name cannot meet with no lexical separator.
        Reparse only this recognized, simple assignment spelling with equivalent
        braced references; preserve the original source and character offsets.
        The actual command/arguments still come from the parser, not token guesses.
        """
        children = command.children
        pair = next(((left, right) for left, right in zip(children, children[1:])
                     if left.kind == "variable_assignment" and right.kind == "command_name"
                     and left.span.end == right.span.start and left.text.endswith("$")), None)
        if pair is None:
            return command, 0
        left, right = pair
        start, end = left.span.start - command.span.start, right.span.end - command.span.start
        spelling = command.text[start:end]
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=(?:\$[A-Za-z_][A-Za-z0-9_]*|\$\{[A-Za-z_][A-Za-z0-9_]*\}|[\w./:,+%=@-])+", spelling):
            return command, 0
        references = list(re.finditer(r"\$([A-Za-z_][A-Za-z0-9_]*)", command.text[start:end]))
        if not references:
            return command, 0
        insertions = {}
        for match in references:
            insertions[start + match.start() + 1] = "{"
            insertions[start + match.end()] = "}"
        rewritten, boundaries = [], [0]
        for index in range(len(command.text) + 1):
            if index in insertions:
                rewritten.append(insertions[index])
                boundaries.append(index)
            if index < len(command.text):
                rewritten.append(command.text[index])
                boundaries.append(index + 1)
        parsed = self.parse("".join(rewritten), remaining_nodes)
        if parsed.diagnostics or len(parsed.root.children) != 1:
            return command, 0
        converted, pending, count = {}, [(parsed.root.children[0], False)], 0
        while pending:
            part, ready = pending.pop()
            if not ready:
                count += 1
                if count > remaining_nodes:
                    raise ParseBudgetExceeded
                pending.append((part, True))
                pending.extend((child, False) for child in reversed(part.children))
                continue
            span = Span(command.span.start + boundaries[part.span.start], command.span.start + boundaries[part.span.end])
            original = command.text[span.start - command.span.start:span.end - command.span.start]
            kind = "simple_expansion" if part.kind == "expansion" and re.fullmatch(r"\$[A-Za-z_][A-Za-z0-9_]*", original) else part.kind
            converted[id(part)] = SyntaxNode(kind, span,
                tuple(converted[id(child)] for child in part.children if child.span.start != child.span.end
                      and converted[id(child)].span.start != converted[id(child)].span.end), original)
        return converted[id(parsed.root.children[0])], count
