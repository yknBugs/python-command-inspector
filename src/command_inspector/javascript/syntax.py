"""Tree-sitter JavaScript syntax, without Node or submitted-code evaluation."""
from dataclasses import dataclass, field
from ..models import Span
from ..bash.syntax import FrontendUnavailable, ParseBudgetExceeded


@dataclass(frozen=True, eq=False, slots=True)
class Node:
    kind: str
    text: str = field(repr=False)
    span: Span
    children: tuple = ()
    fields: tuple = ()

    def get(self, name):
        return next((child for key, child in self.fields if key == name), None)


@dataclass(frozen=True)
class ParsedJavaScript:
    root: Node | None
    diagnostics: tuple = ()
    backend: str = 'tree-sitter-javascript'


FUNCTIONS = {'function_declaration', 'function_expression', 'arrow_function', 'generator_function', 'generator_function_declaration', 'method_definition'}


class JavaScriptFrontend:
    def __init__(self):
        try:
            from tree_sitter import Language, Parser
            import tree_sitter_javascript
        except ImportError:
            raise FrontendUnavailable from None
        self.parser = Parser(Language(tree_sitter_javascript.language()))

    def parse(self, text, max_nodes=65536, *, allow_top_level_return=False):
        tree = self.parser.parse(text.encode('utf-8'))
        offsets, byte = {}, 0
        for index, char in enumerate(text):
            offsets[byte] = index
            byte += len(char.encode('utf-8'))
        offsets[byte] = len(text)
        nodes, diagnostics, count = {}, [], 0
        pending = [(tree.root_node, False)]
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
            if node.is_error or node.is_missing:
                diagnostics.append(span)
            nodes[node.id] = Node(node.type, text[span.start:span.end], span,
                                  tuple(nodes[c.id] for c in node.named_children if c.type != 'comment'),
                                  tuple((node.field_name_for_child(i), nodes[c.id]) for i, c in enumerate(node.children) if node.field_name_for_child(i)))
        root = nodes[tree.root_node.id]
        # Grammar recovery is not a complete ECMAScript early-error checker.
        # Validate the common context errors our source subset can establish.
        pending = [(root, allow_top_level_return, False, False, (), None)]
        while pending:
            node, function, loop, switch, labels, parent = pending.pop()
            if node.kind in FUNCTIONS:
                function, loop, switch, labels = True, False, False, ()
            if node.kind in {'for_statement', 'for_in_statement', 'while_statement', 'do_statement'}:
                loop = True
            if node.kind == 'switch_statement':
                switch = True
            if node.kind == 'labeled_statement' and node.get('label'):
                labels += (node.get('label').text,)
            invalid = node.kind == 'return_statement' and not function
            if node.kind in {'break_statement', 'continue_statement'}:
                label = node.get('label')
                invalid |= label.text not in labels if label else not (loop or node.kind == 'break_statement' and switch)
            if node.kind == 'lexical_declaration' and node.get('kind') and node.get('kind').text == 'const':
                invalid |= any(c.kind == 'variable_declarator' and c.get('value') is None for c in node.children)
            if node.kind in {'program', 'statement_block'}:
                seen = set()
                for declaration in node.children:
                    if declaration.kind == 'lexical_declaration':
                        for variable in declaration.children:
                            name = variable.get('name')
                            if name and name.kind == 'identifier':
                                if name.text in seen:
                                    diagnostics.append(name.span)
                                seen.add(name.text)
            if invalid or node.kind.startswith('jsx_'):
                diagnostics.append(node.span)
            pending.extend((child, function, loop, switch, labels, node) for child in node.children)
        return ParsedJavaScript(None if diagnostics else root, tuple(diagnostics))
