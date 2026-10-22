"""Literal credential fields and signatures from the parsed JavaScript tree."""
from bisect import bisect_right

from ..shared.source_secrets import SourceSecrets
from .values import decode


def secret_facts(root, source, context, cwd, value_bytes):
    found = SourceSecrets(source, context, cwd, 'javascript')
    nodes, pending, literals = [], [root], {}
    fold_bytes = value_bytes
    while pending:
        node = pending.pop()
        nodes.append(node)
        pending.extend(node.children)
    for node in reversed(nodes):
        text = None
        if node.kind == 'string':
            text = decode(node.text[1:-1])
        elif node.kind == 'template_string' and not any(c.kind == 'template_substitution' for c in node.children):
            text = decode(node.text[1:-1])
        elif node.kind == 'parenthesized_expression' and node.children:
            text = literals.get(node.children[-1])
        elif node.kind == 'binary_expression' and node.get('operator').text == '+':
            left, right = literals.get(node.get('left')), literals.get(node.get('right'))
            if left is not None and right is not None and len(left) + len(right) <= fold_bytes:
                text = left + right
        if text is not None:
            size = len(text.encode('utf-8'))
            folded = node.kind == 'binary_expression'
            if size <= value_bytes and (not folded or size <= fold_bytes):
                literals[node] = text
                if folded:
                    fold_bytes -= size
    starts = [0, *(index + 1 for index, char in enumerate(root.text) if char == '\n')]

    def label(node):
        if node is None:
            return ''
        if node.kind in {'identifier', 'property_identifier'}:
            return node.text
        if node.kind == 'member_expression':
            return label(node.get('property'))
        if node.kind == 'subscript_expression':
            return literals.get(node.get('index'), '')
        return literals.get(node, '')

    def add(node, name=''):
        if node in literals:
            offset = node.span.start - root.span.start
            line = bisect_right(starts, offset)
            found.add(literals[node], line, offset - starts[line - 1], name)

    for node in nodes:
        add(node)
        if node.kind == 'variable_declarator':
            add(node.get('value'), label(node.get('name')))
        elif node.kind in {'assignment_expression', 'assignment_pattern'}:
            add(node.get('right'), label(node.get('left')))
        elif node.kind in {'pair', 'field_definition'}:
            add(node.get('value'), label(node.get('key') or node.get('property')))
    return found.facts()
