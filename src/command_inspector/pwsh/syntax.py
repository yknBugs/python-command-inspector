"""In-process Windows syntax adapters; no shell subprocesses or Wine."""
from dataclasses import replace
import hashlib
import re
from ..models import ParsedSource, Span, SyntaxNode
from ..bash.syntax import FrontendUnavailable, ParseBudgetExceeded


_FOREACH_OBJECT_NAME = re.compile(r"foreach-object(?=$|[\s;|&>(){])", re.I)
_NATIVE_EQUALS_ARG = re.compile(r'--[A-Za-z][A-Za-z0-9_-]*=[A-Za-z0-9_./:\\\\-]+(?=$|[\s|;>])')
_QUOTED_EQUALS_ARG = re.compile(r'''--[A-Za-z][A-Za-z0-9_-]*=(?:'(?:[^']|'')*'|"(?:[^"`$]|`.)*")(?=$|[\s|;>])''')

def _ascii_fold(raw):
    """Fold each non-ASCII character to equal-length text from its digest.

    The vendored grammar accepts only ASCII identifiers, while PowerShell allows
    Unicode letters in names, properties and hashtable keys. Keeping the byte
    length lets the folded copy share every span with the original input. Each
    character uses its own digest so the replacement cannot collide with
    ordinary source text. Digest nibbles map onto 'a'-'p': letters only, so a
    fold can never read as a number or carry a quote or separator the way raw
    digest bytes could. 'z' pads a digest that is somehow too short.
    """
    folded = []
    for char in raw.decode("utf-8"):
        if char < "\x80":
            folded.append(char)
            continue
        encoded = char.encode("utf-8")
        width = len(encoded)
        digest = hashlib.sha256(encoded).digest()
        letters = "".join(chr(97 + nibble) for byte in digest for nibble in (byte >> 4, byte & 15))
        folded.append(letters[:width].ljust(width, "z"))
    return "".join(folded).encode("utf-8")


def _error_nodes(node):
    count, pending = 0, [node]
    while pending:
        current = pending.pop()
        if current.type == "ERROR" or current.is_missing:
            count += 1
        pending.extend(current.children)
    return count


class PowerShellFrontend:
    def __init__(self):
        try:
            from tree_sitter import Language, Parser
            import tree_sitter_powershell
        except ImportError:
            raise FrontendUnavailable from None
        self.parser = Parser(Language(tree_sitter_powershell.language()))

    def parse(self, text, max_nodes=65536, *, _repairs=0):
        original = self._parse(text, max_nodes)
        if not original.diagnostics:
            return original
        # At statement boundaries the vendor grammar can tokenize ForEach-Object
        # as the foreach keyword followed by subtraction. Mask only keyword
        # tokens that actually spell this command, never occurrences in strings
        # or comments. Same-width replacement preserves all character spans.
        parse_text = list(text)
        pending, count, command_names = [original.root], 0, False
        quoted_arguments = {}
        while pending:
            node = pending.pop()
            count += 1
            if node.kind == "foreach" and _FOREACH_OBJECT_NAME.match(text, node.span.start):
                parse_text[node.span.start] = "X"
                command_names = True
            if node.kind == 'command_elements':
                for argument in node.children:
                    if argument.kind == 'generic_token':
                        # Calculated-property hashes are argument-mode array
                        # elements. The vendor grammar loses their opening @{.
                        match = re.match(r'\s*,\s*(?=@\{)', text[argument.span.end:])
                        if match:
                            comma = text.index(',', argument.span.end, argument.span.end + match.end())
                            parse_text[comma] = ' '
                            command_names = True
                        if argument.text.startswith(',@{'):
                            parse_text[argument.span.start] = ' '
                            command_names = True
                for parameter in node.children:
                    quoted = (_QUOTED_EQUALS_ARG.match(text, parameter.span.start)
                              if parameter.kind == 'command_parameter' else None)
                    if quoted and text[parameter.span.end:parameter.span.end + 1] == '=':
                        # Parse the quoted value as its own expression, then
                        # reunite the attached native option without losing its
                        # quoting or allowing pipes inside it to become commands.
                        parse_text[parameter.span.end] = ' '
                        quoted_arguments[parameter.span.start] = quoted.end()
                        command_names = True
                    if (parameter.kind == 'command_parameter' and parameter.span.end < len(text)
                            and text[parameter.span.end] == '='
                            and _NATIVE_EQUALS_ARG.match(text, parameter.span.start)):
                        # Native argument-mode --name=value is valid. The
                        # grammar rejects its '=' suffix; repair only contiguous
                        # literal arguments and restore their original text.
                        # At EOF the rejected suffix can be outside the command
                        # subtree; use the proven parameter boundary, not the
                        # recovery ERROR node's parent or shape.
                        parse_text[parameter.span.end] = '_'
                        command_names = True
            if node.kind == "ERROR":
                if any(c.kind == 'command_name' for c in node.children):
                    for index, child in enumerate(node.children):
                        if child.kind == ',' and index and index + 1 < len(node.children):
                            previous, following = node.children[index - 1:index + 2:2]
                            if previous.text.startswith('@{') and following.kind == 'simple_name':
                                parse_text[child.span.start] = ' '
                                command_names = True
                # Unit suffixes are valid numeric literals in expressions. Mask
                # only recovery suffixes attached to a proven preceding digit.
                if (re.fullmatch(r'(?i)[kmgtp]b', node.text) and node.span.start > 0
                        and text[node.span.start - 1].isdigit()):
                    parse_text[node.span.start:node.span.end] = '0' * (node.span.end - node.span.start)
                    command_names = True
                # A literal standalone '-' in command argument mode is rejected
                # by the grammar (python -, pwsh -Command -). Same-width masking
                # recovers the command, without changing expression subtraction.
                for index, child in enumerate(node.children):
                    if (child.kind == "-" and child.text == "-" and index > 0
                            and node.children[index - 1].kind == "command_argument_sep"
                            and any(c.kind == "command_name" for c in node.children[:index])):
                        parse_text[child.span.start] = "_"
                        command_names = True
            pending.extend(node.children)
        remaining = max_nodes - count
        parse_text = ''.join(parse_text)
        if command_names:
            # Recovery from one malformed argument can hide the next option.
            # Revisit newly exposed command tokens, with bounded repair depth.
            original = (self.parse(parse_text, remaining, _repairs=_repairs + 1)
                        if _repairs < 3 else self._parse(parse_text, remaining))
            restored, pending, count = {}, [(original.root, False)], 0
            while pending:
                node, ready = pending.pop()
                if not ready:
                    count += 1
                    pending.append((node, True))
                    pending.extend((child, False) for child in reversed(node.children))
                    continue
                children = tuple(restored[id(c)] for c in node.children)
                if node.kind == 'command_elements' and quoted_arguments:
                    rebuilt, index = [], 0
                    while index < len(children):
                        child = children[index]
                        end = quoted_arguments.get(child.span.start)
                        if end is not None and child.kind == 'command_parameter':
                            parts = []
                            while index < len(children) and children[index].span.end <= end:
                                if children[index].kind != 'command_argument_sep':
                                    parts.append(children[index])
                                index += 1
                            rebuilt.append(SyntaxNode('native_equals_argument', Span(child.span.start, end),
                                                      tuple(parts), text[child.span.start:end]))
                        else:
                            rebuilt.append(child)
                            index += 1
                    children = tuple(rebuilt)
                if node.kind == 'command_elements':
                    # Restore masked argument-mode commas as array structure,
                    # including hash/scriptblock elements, not extra argv items.
                    rebuilt, index = [], 0
                    while index < len(children):
                        child = children[index]
                        if (child.kind == 'command_argument_sep' and child.text.strip() == ','
                                and rebuilt and index + 1 < len(children)):
                            previous = rebuilt.pop()
                            following = children[index + 1]
                            comma = text.index(',', child.span.start, child.span.end)
                            rebuilt.append(SyntaxNode('array_literal_expression', Span(previous.span.start, following.span.end),
                                (previous, SyntaxNode(',', Span(comma, comma + 1), text=','), following),
                                text[previous.span.start:following.span.end]))
                            index += 2
                        else:
                            rebuilt.append(child)
                            index += 1
                    children = tuple(rebuilt)
                restored[id(node)] = replace(node, children=children,
                                            text=text[node.span.start:node.span.end])
            original = replace(original, root=restored[id(original.root)])
            remaining -= count
            if not original.diagnostics:
                return original
        # The vendor grammar rejects bare comma arrays in argument mode. Repair
        # only finite literal arrays within an already parsed command argument
        # region. Expression/method/foreach commas are left to the grammar.
        atom = r'''(?:[A-Za-z0-9_$./:\\\\*?][A-Za-z0-9_$./:\\\\*?\[\]-]*|'(?:[^']|'')*'|"(?:[^"`$]|`.)*")'''
        array = re.compile(r'(?<!\S)' + atom + r'(?:[ \t]*,[ \t]*' + atom + r')+(?=$|[\s|;>])')
        regions, pending = [], [original.root]
        while pending:
            node = pending.pop()
            if node.kind == "command_elements":
                regions.append(node.span)
            elif node.kind == "ERROR":
                candidates = [c for c in node.children if c.kind in {"pipeline", "pipeline_chain", "command"}]
                if candidates and candidates[0].span.start == node.span.start:
                    commands, stack = [], [candidates[0]]
                    while stack:
                        child = stack.pop()
                        if child.kind == 'command':
                            commands.append(child)
                        else:
                            stack.extend(child.children)
                    commands.sort(key=lambda c: c.span.end, reverse=True)
                    if commands:
                        elements = next((c for c in commands[0].children if c.kind == "command_elements"), None)
                        if elements:
                            regions.append(Span(elements.span.start, node.span.end))
            pending.extend(node.children)
        groups = set()
        for region in regions:
            for match in array.finditer(text[region.start:region.end]):
                groups.add((region.start + match.start(), region.start + match.end()))
        if not groups:
            return original
        masked = list(parse_text)
        for start, end in groups:
            quoted, escaped = None, False
            for index in range(start, end):
                char = text[index]
                if escaped:
                    escaped = False
                elif quoted and char == '`':
                    escaped = True
                elif char in "'\"":
                    quoted = None if quoted == char else char if quoted is None else quoted
                elif char == ',' and quoted is None:
                    masked[index] = ' '
        # Charge every repair pass to the same node budget.
        repaired = self._parse(''.join(masked), remaining)
        group_starts = {a: (a, b) for a, b in groups}
        restored, pending = {}, [(repaired.root, False)]
        while pending:
            node, ready = pending.pop()
            if not ready:
                pending.append((node, True))
                pending.extend((child, False) for child in reversed(node.children))
                continue
            children = tuple(restored[id(c)] for c in node.children)
            if node.kind == 'command_elements':
                rebuilt, index = [], 0
                while index < len(children):
                    child = children[index]
                    group = group_starts.get(child.span.start) if child.kind != 'command_argument_sep' else None
                    if group:
                        parts = []
                        while index < len(children) and children[index].span.end <= group[1]:
                            part = children[index]
                            if part.kind != 'command_argument_sep':
                                if parts:
                                    comma = text.index(',', parts[-1].span.end, part.span.start)
                                    parts.append(SyntaxNode(',', Span(comma, comma + 1), text=','))
                                parts.append(part)
                            index += 1
                        rebuilt.append(SyntaxNode('array_literal_expression', Span(*group), tuple(parts), text[group[0]:group[1]]))
                    else:
                        rebuilt.append(child); index += 1
                children = tuple(rebuilt)
            restored[id(node)] = replace(node, children=children, text=text[node.span.start:node.span.end])
        return replace(repaired, root=restored[id(repaired.root)])

    def _parse(self, text, max_nodes):
        raw = text.encode()
        offsets = []
        for index, char in enumerate(text):
            offsets.extend([index] * len(char.encode()))
        offsets.append(len(text))
        tree = self.parser.parse(raw)
        if tree.root_node.has_error:
            folded = self.parser.parse(_ascii_fold(raw))
            if _error_nodes(folded.root_node) < _error_nodes(tree.root_node):
                tree = folded
        pending, converted, diagnostics, count = [(tree.root_node, False)], {}, [], 0
        while pending:
            node, ready = pending.pop()
            if not ready:
                count += 1
                if count > max_nodes:
                    raise ParseBudgetExceeded
                pending.append((node, True))
                pending.extend((c, False) for c in reversed(node.children))
                continue
            span = Span(offsets[node.start_byte], offsets[node.end_byte])
            # The vendor grammar inserts a missing ';' for an empty literal
            # scriptblock. Matched real braces and an empty body prove this is
            # valid syntax; do not suppress other missing tokens or errors.
            empty_block = False
            if node.is_missing and node.type == ";" and node.parent is not None and node.parent.type == "empty_statement":
                ancestor = node.parent
                for _ in range(4):
                    ancestor = ancestor.parent if ancestor is not None else None
                if ancestor is not None and ancestor.type == "script_block_expression":
                    braces = [c for c in ancestor.children if c.type in {"{", "}"}]
                    bodies = [c for c in ancestor.children if c.type == "script_block"]
                    empty_block = (len(braces) == 2 and all(not c.is_missing for c in braces)
                                   and len(bodies) == 1 and bodies[0].start_byte == bodies[0].end_byte)
            if node.type == "ERROR" or (node.is_missing and not empty_block):
                diagnostics.append(span)
            converted[node.id] = SyntaxNode(node.type, span, tuple(converted[c.id] for c in node.children), text[span.start:span.end])
        return ParsedSource(converted[tree.root_node.id], tuple(diagnostics), "tree-sitter-powershell")
