"""Bounded inspection of literal credentials, independent of Python execution."""
import ast

from ..shared.source_secrets import SourceSecrets


def secret_facts(root, source, context, cwd, value_bytes):
    found = SourceSecrets(source, context, cwd, 'python')
    literals = {}
    fold_bytes = value_bytes
    nodes = list(ast.walk(root))
    # AST parents precede children. Fold only literal strings/concatenations;
    # runtime expressions and variable references are not evaluated here.
    for node in reversed(nodes):
        text = None
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                text = node.value
            elif isinstance(node.value, bytes):
                try:
                    text = node.value.decode('utf-8')
                except UnicodeError:
                    pass
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, right = literals.get(node.left), literals.get(node.right)
            if left is not None and right is not None and len(left) + len(right) <= fold_bytes:
                text = left + right
        elif isinstance(node, ast.JoinedStr) and all(value in literals for value in node.values):
            if sum(len(literals[value]) for value in node.values) <= fold_bytes:
                text = ''.join(literals[value] for value in node.values)
        if text is not None:
            try:
                size = len(text.encode('utf-8'))
                folded = isinstance(node, (ast.BinOp, ast.JoinedStr))
                if size <= value_bytes and (not folded or size <= fold_bytes):
                    literals[node] = text
                    if folded:
                        fold_bytes -= size
            except UnicodeError:
                pass  # Let the existing authored-content check report this.

    def name(target):
        if isinstance(target, ast.Name):
            return target.id
        if isinstance(target, ast.Attribute):
            return target.attr
        if isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant) and isinstance(target.slice.value, str):
            return target.slice.value
        return ''

    def assign(target, value):
        if isinstance(target, (ast.Tuple, ast.List)) and isinstance(value, (ast.Tuple, ast.List)) and len(target.elts) == len(value.elts):
            for child, item in zip(target.elts, value.elts):
                assign(child, item)
        elif value in literals and (label := name(target)):
            found.add(literals[value], value.lineno, value.col_offset, label)

    for node in nodes:
        if node in literals:
            found.add(literals[node], node.lineno, node.col_offset)
        if isinstance(node, ast.Assign):
            for target in node.targets:
                assign(target, node.value)
        elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)):
            assign(node.target, node.value)
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if key in literals and value in literals:
                    found.add(literals[value], value.lineno, value.col_offset, literals[key])
        elif isinstance(node, ast.keyword) and node.arg and node.value in literals:
            found.add(literals[node.value], node.value.lineno, node.value.col_offset, node.arg)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            args = node.args
            positional = [*args.posonlyargs, *args.args]
            defaults = list(zip(positional[-len(args.defaults):], args.defaults)) if args.defaults else []
            defaults.extend(zip(args.kwonlyargs, args.kw_defaults))
            for argument, value in defaults:
                if value in literals:
                    found.add(literals[value], value.lineno, value.col_offset, argument.arg)
    return found.facts()
