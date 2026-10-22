"""Bounded Python assignment/call events, without executing submitted code.

Each lexical scope joins all visible assignments. Source order and branch
conditions do not select an assignment. Only explicitly modeled values can
flow into effects; arbitrary objects and calls remain unknown.
"""
import ast
from dataclasses import dataclass, field, replace

from ..models import Value
from ..shared.value_flow import ValueLimits, bounded, candidates, choices, compose, join


@dataclass(frozen=True, slots=True)
class PythonValue:
    kind: str = "unknown"
    scalar: Value = Value(None, "unsupported_python_value")
    items: tuple["PythonValue", ...] = ()
    mode: Value | None = None
    origin: int | None = None


@dataclass(frozen=True, slots=True)
class _Unpack:
    expression: object = field(repr=False)
    index: int
    iteration: bool = False


def unknown(reason="unsupported_python_value", variables=()):
    return PythonValue(scalar=Value(None, reason, tuple(sorted(set(variables)))))


@dataclass(eq=False)
class Scope:
    number: int
    parent: "Scope | None"
    function: ast.AST | None = None
    assignments: dict = field(default_factory=dict)
    symbols: dict = field(default_factory=dict)
    parameters: tuple[str, ...] = ()
    defaults: dict = field(default_factory=dict)
    returns: list = field(default_factory=list)
    globals: set = field(default_factory=set)
    nonlocals: set = field(default_factory=set)

    def owner(self, name):
        if name in self.globals:
            scope = self
            while scope.parent:
                scope = scope.parent
            return scope
        if name in self.nonlocals:
            scope = self.parent
            while scope and scope.parent:
                if name in scope.assignments or name in scope.parameters:
                    return scope
                scope = scope.parent
        return self

    def lookup(self, name):
        owner = self.owner(name)
        if owner is not self:
            return owner.lookup(name)
        if name in self.assignments or name in self.parameters:
            return self.symbols.get(name, unknown("missing_variable", (name,)))
        return self.parent.lookup(name) if self.parent else unknown("missing_variable", (name,))

    def declared(self, name):
        return name in self.assignments or name in self.parameters or bool(self.parent and self.parent.declared(name))


class PythonValues:
    def __init__(self, root, cwd, env, paths, *, possible_values=16, control_flow_steps=256, value_bytes=524288, python_bindings=()):
        self.cwd, self.env, self.paths = cwd, {k.casefold() if paths.windows else k: v for k, v in env.items()}, paths
        self.limit = ValueLimits(possible_values, value_bytes)
        self.steps = control_flow_steps
        self.scopes = [Scope(0, None)]
        self.functions, self.calls, self.iterations = {}, [], []
        self.cache = {}
        self.mutations = []
        for name, value in dict(python_bindings).items():
            self.scopes[0].assignments[name] = [(value, self.scopes[0], "value")]
        self.collect(root)
        for scope in self.scopes:
            for name in scope.nonlocals:
                owner = scope.owner(name)
                if owner is not scope and name in scope.assignments:
                    owner.assignments.setdefault(name, []).extend(scope.assignments.pop(name))
        self.invalidate_mutated_containers()
        self.solve()

    def assign(self, target, expression, scope, category="value", expression_scope=None):
        if isinstance(target, ast.Name):
            scope.owner(target.id).assignments.setdefault(target.id, []).append((expression, expression_scope or scope, category))
        elif isinstance(target, ast.Subscript):
            owner = target.value
            while isinstance(owner, ast.Subscript):
                owner = owner.value
            if isinstance(owner, ast.Name):
                self.mutations.append((scope, owner.id))
        elif isinstance(target, (ast.Tuple, ast.List)):
            for index, child in enumerate(target.elts):
                if isinstance(child, ast.Starred):
                    self.assign(child.value, None, scope)
                else:
                    # Select the outer component before descending into a
                    # nested target. Only the outer loop projection joins inputs.
                    self.assign(child, _Unpack(expression, index, category == 'iteration'), scope, expression_scope=expression_scope)

    def invalidate_mutated_containers(self):
        def binding(scope, name):
            owner = scope.owner(name)
            while owner.parent and name not in owner.assignments and name not in owner.parameters:
                owner = owner.parent
            return owner, name
        edges = {}
        for scope in self.scopes:
            for name, events in scope.assignments.items():
                for expression, source, category in events:
                    if category == 'value' and isinstance(expression, ast.Name):
                        left, right = binding(scope, name), binding(source, expression.id)
                        edges.setdefault(left, set()).add(right)
                        edges.setdefault(right, set()).add(left)
        containers = {binding(scope, name) for scope in self.scopes for name, events in scope.assignments.items()
                      if any(isinstance(expression, (ast.List, ast.Tuple, ast.Dict, ast.Set)) for expression, _, _ in events)}
        reachable = set(containers)
        pending_aliases = list(containers)
        while pending_aliases:
            for alias in edges.get(pending_aliases.pop(), ()):
                if alias not in reachable:
                    reachable.add(alias)
                    pending_aliases.append(alias)
        pending = [binding(scope, name) for scope, name in self.mutations if binding(scope, name) in reachable]
        affected = set()
        while pending:
            item = pending.pop()
            if item in affected:
                continue
            affected.add(item)
            pending.extend(edges.get(item, ()))
        for scope, name in affected:
            scope.assignments.setdefault(name, []).append((unknown('mutated_python_container', (name,)), scope, 'value'))

    def child_scope(self, node, parent):
        lexical_parent = parent.parent if isinstance(parent.function, ast.ClassDef) and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)) else parent
        scope = Scope(len(self.scopes), lexical_parent, node)
        self.scopes.append(scope)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            args = node.args
            parameters = [*args.posonlyargs, *args.args, *args.kwonlyargs]
            scope.parameters = tuple(a.arg for a in parameters)
            positional = [*args.posonlyargs, *args.args]
            scope.defaults.update((a.arg, (v, parent)) for a, v in zip(positional[-len(args.defaults):], args.defaults) if args.defaults)
            scope.defaults.update((a.arg, (v, parent)) for a, v in zip(args.kwonlyargs, args.kw_defaults) if v is not None)
            for extra in (args.vararg, args.kwarg):
                if extra:
                    scope.assignments[extra.arg] = [(None, scope, "value")]
            pending = list(node.body) if not isinstance(node, ast.Lambda) else [node.body]
            while pending:
                child = pending.pop()
                if isinstance(child, ast.Global):
                    scope.globals.update(child.names)
                elif isinstance(child, ast.Nonlocal):
                    scope.nonlocals.update(child.names)
                elif not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
                    pending.extend(ast.iter_child_nodes(child))
        return scope

    def collect(self, root):
        pending = [(root, self.scopes[0], False)]
        while pending:
            node, scope, defined = pending.pop()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                child = self.child_scope(node, scope)
                self.functions[id(node)] = child
                if not isinstance(node, ast.Lambda):
                    value = PythonValue("function", Value(str(child.number)))
                    scope.assignments.setdefault(node.name, []).append((value, scope, "value"))
                    pending.extend((c, child, True) for c in reversed(node.body))
                    pending.extend((c, scope, defined) for c in reversed(node.decorator_list))
                else:
                    child.returns.append(node.body)
                    pending.append((node.body, child, True))
                pending.extend((c, scope, defined) for c in (*node.args.defaults, *[v for v in node.args.kw_defaults if v]))
                arguments = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs, *([node.args.vararg] if node.args.vararg else []), *([node.args.kwarg] if node.args.kwarg else [])]
                pending.extend((a.annotation, scope, defined) for a in arguments if a.annotation is not None)
                if getattr(node, "returns", None) is not None:
                    pending.append((node.returns, scope, defined))
                continue
            if isinstance(node, ast.ClassDef):
                self.assign(ast.Name(id=node.name), None, scope)
                child = self.child_scope(node, scope)
                pending.extend((c, child, defined) for c in reversed(node.body))
                pending.extend((c, scope, defined) for c in (*node.bases, *node.decorator_list))
                pending.extend((k.value, scope, defined) for k in node.keywords)
                continue
            if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                child = self.child_scope(node, scope)
                for index, generator in enumerate(node.generators):
                    expression_scope = scope if index == 0 else child
                    self.assign(generator.target, generator.iter, child, "iteration", expression_scope)
                    self.iterations.append((generator.iter, expression_scope, defined))
                    pending.append((generator.iter, expression_scope, defined))
                    pending.extend((c, child, defined) for c in generator.ifs)
                elements = [node.key, node.value] if isinstance(node, ast.DictComp) else [node.elt]
                pending.extend((c, child, defined) for c in elements)
                continue
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname or alias.name.split(".")[0]
                    namespace = alias.name if alias.asname else alias.name.split(".")[0]
                    scope.assignments.setdefault(name, []).append((PythonValue("namespace", Value(namespace)), scope, "value"))
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name != "*":
                        canonical = (node.module + "." if node.module else "") + alias.name
                        scope.assignments.setdefault(alias.asname or alias.name, []).append((PythonValue("callable", Value(canonical)), scope, "value"))
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    self.assign(target, node.value, scope)
            elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)):
                self.assign(node.target, node.value, scope)
            elif isinstance(node, ast.AugAssign):
                self.assign(node.target, ast.BinOp(left=node.target, op=node.op, right=node.value), scope)
            elif isinstance(node, (ast.For, ast.AsyncFor)):
                self.assign(node.target, node.iter, scope, "iteration")
                self.iterations.append((node.iter, scope, defined))
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    if item.optional_vars:
                        self.assign(item.optional_vars, item.context_expr, scope)
            elif isinstance(node, ast.ExceptHandler) and node.name:
                self.assign(ast.Name(id=node.name), None, scope)
            elif isinstance(node, ast.Delete):
                for target in node.targets:
                    self.assign(target, None, scope)
            elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
                self.assign(ast.Name(id=node.name), None, scope)
            elif isinstance(node, ast.Return) and scope.function:
                scope.returns.append(node.value)
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and node.func.attr in {'append', 'extend', 'insert', 'clear', 'pop', 'remove', 'reverse', 'sort', 'update', 'setdefault', 'popitem'}:
                    receiver = node.func.value
                    while isinstance(receiver, ast.Subscript):
                        receiver = receiver.value
                    if isinstance(receiver, ast.Name):
                        self.mutations.append((scope, receiver.id))
                self.calls.append((node, scope, defined))
            pending.extend((c, scope, defined) for c in reversed(tuple(ast.iter_child_nodes(node))))

    def merge(self, items, name=""):
        items = tuple(items)
        variables = {n for v in items for n in v.scalar.variables} | ({name} if name else set())
        kinds = {v.kind for v in items}
        if kinds == {"str", "path"}:
            items = tuple(replace(v, kind="path") for v in items)
            kinds = {"path"}
        if not items or any(v.kind == "unknown" for v in items) or len(kinds) != 1:
            return unknown(next((v.scalar.reason for v in items if v.kind == "unknown"), "unsupported_python_value"), variables)
        kind = items[0].kind
        if kind == "python_executable":
            return replace(items[0], scalar=replace(items[0].scalar, variables=tuple(sorted(variables))))
        if kind == "file_content":
            return PythonValue(kind, Value(None, "file_content_unresolved", tuple(sorted(variables))), items=(self.merge(v.items[0] for v in items),))
        if kind == "sequence":
            if any(len(v.items) != len(items[0].items) for v in items):
                return unknown("changed_sequence_shape", variables)
            return PythonValue(kind, Value(None, variables=tuple(sorted(variables))),
                               tuple(self.merge(v.items[i] for v in items) for i in range(len(items[0].items))))
        identity = kind in {"namespace", "callable", "function", "bound"}
        limit = ValueLimits(self.limit.count, max([self.limit.bytes, *(len(c.text.encode()) for v in items for c in candidates(v.scalar) if c.text is not None)])) if identity else self.limit
        scalar = join((v.scalar for v in items), limit, name)
        if scalar.text is None and not scalar.alternatives:
            return unknown(scalar.reason, scalar.variables)
        mode = join((v.mode for v in items), self.limit) if kind in {"file", "code"} else None
        origin = items[0].origin if all(v.origin == items[0].origin for v in items) else None
        bound_items = (self.merge(v.items[0] for v in items),) if kind == "bound" else ()
        return PythonValue(kind, scalar, items=bound_items, mode=mode, origin=origin)

    def parameter_events(self):
        events = {}
        for call, caller, _ in self.calls:
            target = self.evaluate(call.func, caller)
            if target.kind != "function":
                continue
            for candidate in candidates(target.scalar):
                function = self.scopes[int(candidate.text)]
                positional = [*function.function.args.posonlyargs, *function.function.args.args]
                supplied = {arg.arg: value for arg, value in zip(positional, call.args)}
                supplied.update((k.arg, k.value) for k in call.keywords if k.arg is not None)
                dynamic = any(isinstance(v, ast.Starred) for v in call.args) or any(k.arg is None for k in call.keywords)
                for name in function.parameters:
                    item = (None, caller) if dynamic else (supplied[name], caller) if name in supplied else function.defaults.get(name, (None, caller))
                    events.setdefault((function.number, name), []).append(item)
        return events

    def solve(self):
        for _ in range(self.steps):
            previous_symbols = [dict(scope.symbols) for scope in self.scopes]
            self.cache = {}
            parameter_events = self.parameter_events()
            next_symbols = []
            for scope in self.scopes:
                symbols = {}
                for name, events in scope.assignments.items():
                    values = []
                    for expression, source_scope, category in events:
                        value = self.evaluate(expression, source_scope)
                        values.append(self.iteration(value) if category == "iteration" else value)
                    symbols[name] = self.merge(values, name)
                for name in scope.parameters:
                    values = [self.evaluate(e, s) for e, s in parameter_events.get((scope.number, name), [(None, scope)])]
                    symbols[name] = self.merge([*values, *([symbols[name]] if name in symbols else [])], name)
                next_symbols.append(symbols)
            if all(scope.symbols == symbols for scope, symbols in zip(self.scopes, next_symbols)):
                break
            for scope, symbols in zip(self.scopes, next_symbols):
                scope.symbols = symbols
        else:
            for scope, symbols in zip(self.scopes, next_symbols):
                for name, value in symbols.items():
                    events = scope.assignments.get(name, ())
                    literal = bool(events) and name not in scope.parameters and all(category == "value" and self.literal(expression) for expression, _, category in events)
                    if value.kind not in {"namespace", "callable", "function", "bound"} and not literal and previous_symbols[scope.number].get(name) != value:
                        scope.symbols[name] = unknown("control_flow_limit", (name,))
        self.cache = {}

    @staticmethod
    def literal(expression):
        if isinstance(expression, PythonValue):
            return True
        pending = [expression]
        while pending:
            node = pending.pop()
            if isinstance(node, (ast.List, ast.Tuple)):
                pending.extend(node.elts)
            elif not isinstance(node, ast.Constant):
                return False
        return True

    def iteration(self, value):
        if value.kind == "sequence":
            return self.merge(value.items)
        if value.kind == "selection":
            return PythonValue("path", value.scalar)
        return unknown("unresolved_iteration", value.scalar.variables)

    def scalar_map(self, kind, values, function):
        variables = tuple(sorted({n for v in values for n in v.scalar.variables}))
        if any(v.kind == "unknown" for v in values):
            return unknown(next(v.scalar.reason for v in values if v.kind == "unknown"), variables)
        bindings = {str(i): v.scalar for i, v in enumerate(values)}
        rows, _ = choices(bindings, bindings, self.limit)
        results = []
        for row in rows or (bindings,):
            scalars = [row.get(str(i), v.scalar) for i, v in enumerate(values)]
            if any(v.text is None for v in scalars):
                return unknown(next((v.reason for v in scalars if v.reason), "unresolved_composition"), variables)
            if any(v.pattern for v in scalars):
                # A transformed glob result is not a literal wildcard filename,
                # nor generally the same selection as transforming its pattern.
                return unknown("python_selection_transformation_unresolved", variables)
            if kind != "callable" and sum(len(v.text.encode("utf-8", errors="surrogatepass")) for v in scalars) > self.limit.bytes:
                return unknown("value_bytes_limit", variables)
            try:
                rendered = function(*(v.text for v in scalars))
                result = replace(rendered, variables=tuple(sorted(set(rendered.variables) | set(variables)))) if isinstance(rendered, Value) else Value(rendered, variables=variables)
                if kind != "callable":
                    result = bounded(result, self.limit)
            except (ValueError, TypeError, IndexError):
                return unknown("unsupported_python_expression", variables)
            results.append(PythonValue(kind, result) if result.text is not None or result.alternatives else unknown(result.reason, variables))
        return self.merge(results)

    def evaluate(self, node, scope):
        if isinstance(node, PythonValue):
            return node
        if node is None:
            return unknown("missing_python_value")
        key = (node, scope.number)
        if key not in self.cache:
            self.cache[key] = unknown("recursive_python_value")
            self.cache[key] = self.expression(node, scope)
        return self.cache[key]

    def expression(self, node, scope):
        if isinstance(node, _Unpack):
            value = self.evaluate(node.expression, scope)
            if node.iteration:
                value = self.iteration(value)
            if value.kind == 'sequence' and node.index < len(value.items):
                return value.items[node.index]
            return unknown('unresolved_unpack', value.scalar.variables)
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                try:
                    node.value.encode("utf-8")
                except UnicodeError:
                    return unknown("unsupported_python_string")
            kind = "str" if isinstance(node.value, str) else "bool" if isinstance(node.value, bool) else "int" if isinstance(node.value, int) else "unknown"
            value = bounded(Value(str(node.value)), self.limit)
            return PythonValue(kind, value) if kind != "unknown" and value.text is not None else unknown(value.reason or "unsupported_python_type")
        if isinstance(node, ast.Name):
            result = scope.lookup(node.id)
            if result.kind == "unknown" and result.scalar.reason == "missing_variable" and not scope.declared(node.id):
                if node.id in {"open", "exec", "eval", "compile", "str", "print", "len", "range", "list", "tuple", "next", "iter"}:
                    return PythonValue("callable", Value(node.id))
                if node.id in {"os", "shutil", "subprocess", "pathlib", "runpy", "glob"}:
                    return PythonValue("namespace", Value(node.id))
            return replace(result, scalar=replace(result.scalar, variables=tuple(sorted(set(result.scalar.variables) | {node.id}))))
        if isinstance(node, (ast.List, ast.Tuple)):
            return PythonValue("sequence", items=tuple(self.evaluate(c, scope) for c in node.elts))
        if isinstance(node, ast.Lambda):
            return PythonValue("function", Value(str(self.functions[id(node)].number)))
        if isinstance(node, ast.IfExp):
            return self.merge((self.evaluate(node.body, scope), self.evaluate(node.orelse, scope)))
        if isinstance(node, ast.JoinedStr):
            values = []
            for part in node.values:
                if isinstance(part, ast.FormattedValue):
                    if part.format_spec is not None or part.conversion not in {-1, 115}:
                        return unknown("unsupported_python_format", self.variables(node))
                    part = part.value
                value = self.evaluate(part, scope)
                if value.kind not in {"str", "path", "int", "bool"}:
                    return unknown("unsupported_python_format", self.variables(node))
                values.append(value)
            return self.scalar_map("str", values, lambda *parts: compose((Value(p) for p in parts), limit=self.limit))
        if isinstance(node, ast.BinOp):
            left, right = self.evaluate(node.left, scope), self.evaluate(node.right, scope)
            if isinstance(node.op, ast.Add) and left.kind == right.kind == "str":
                return self.scalar_map("str", (left, right), lambda a, b: compose((Value(a), Value(b)), limit=self.limit))
            if isinstance(node.op, ast.Div) and left.kind == "path" and right.kind in {"path", "str"}:
                return self.scalar_map("path", (left, right), self.paths.module.join)
        if isinstance(node, ast.Attribute):
            owner = self.evaluate(node.value, scope)
            if owner.kind in {"namespace", "callable"}:
                if owner.scalar.text == "sys" and node.attr == "executable":
                    return PythonValue("python_executable", Value(None, "current_python_executable"))
                return self.scalar_map("callable", (owner,), lambda text: text + "." + node.attr)
            if owner.kind == "path" and node.attr in {"parent", "name", "suffix", "stem"}:
                functions = {"parent": self.paths.module.dirname, "name": self.paths.module.basename,
                             "suffix": lambda text: self.paths.module.splitext(text)[1],
                             "stem": lambda text: self.paths.module.splitext(self.paths.module.basename(text))[0]}
                return self.scalar_map("path" if node.attr == "parent" else "str", (owner,), functions[node.attr])
            if owner.kind in {"file", "path"}:
                return PythonValue("bound", Value(node.attr), items=(owner,))
        if isinstance(node, ast.Subscript):
            owner = self.evaluate(node.value, scope)
            if owner.kind == "sequence" and isinstance(node.slice, ast.Constant) and type(node.slice.value) is int:
                try:
                    return owner.items[node.slice.value]
                except IndexError:
                    return unknown("invalid_python_index")
            if self.call_name(node.value, scope) == "os.environ":
                key = self.evaluate(node.slice, scope)
                return self.scalar_map("str", (key,), lambda name: self.env.get(name.casefold() if self.paths.windows else name))
        if isinstance(node, ast.Call):
            return self.call_value(node, scope)
        return unknown("unsupported_python_expression", self.variables(node))

    @staticmethod
    def variables(node):
        return tuple(sorted({c.id for c in ast.walk(node) if isinstance(c, ast.Name) and isinstance(c.ctx, ast.Load)}))

    def call_name(self, node, scope):
        value = self.evaluate(node, scope)
        return value.scalar.text if value.kind in {"namespace", "callable"} else None

    def call_value(self, node, scope):
        target = self.evaluate(node.func, scope)
        name = target.scalar.text if target.kind == "callable" else None
        args = [self.evaluate(c, scope) for c in node.args]
        if target.kind == "function":
            returns = [self.evaluate(expression, self.scopes[int(c.text)]) for c in candidates(target.scalar)
                       for expression in self.scopes[int(c.text)].returns]
            return self.merge(returns)
        if name in {"pathlib.Path", "pathlib.PosixPath", "pathlib.WindowsPath", "os.path.join", "posixpath.join", "ntpath.join"}:
            if not args:
                args = [PythonValue("str", Value("."))]
            if all(v.kind in {"path", "str"} for v in args):
                if name.startswith("pathlib.") and len(args) == 1:
                    return replace(args[0], kind="path")
                return self.scalar_map("path" if name.startswith("pathlib.") else "str", args, self.paths.module.join)
            if name.startswith("pathlib."):
                return PythonValue("path", Value(None, "unsupported_path_type", self.variables(node)))
        if name in {"open", "builtins.open", "io.open"}:
            path_node = node.args[0] if node.args else next((k.value for k in node.keywords if k.arg == "file"), None)
            mode_node = node.args[1] if len(node.args) > 1 else next((k.value for k in node.keywords if k.arg == "mode"), ast.Constant("r"))
            path, mode = self.evaluate(path_node, scope), self.evaluate(mode_node, scope)
            scalar = path.scalar if path.kind in {"path", "str", "unknown"} else Value(None, "file_descriptor_or_path_type_unresolved", path.scalar.variables)
            return PythonValue("file", scalar, mode=mode.scalar if mode.kind == "str" else Value(None, "unsupported_open_mode", mode.scalar.variables), origin=id(node))
        if name == "str" and len(args) == 1 and args[0].kind in {"str", "path", "int", "bool"}:
            return replace(args[0], kind="str")
        if name in {"compile", "builtins.compile"}:
            source = args[0] if args else self.evaluate(next((k.value for k in node.keywords if k.arg == 'source'), None), scope)
            mode = args[2] if len(args) > 2 else self.evaluate(next((k.value for k in node.keywords if k.arg == 'mode'), None), scope)
            if source.kind == 'str' and mode.kind == 'str':
                return replace(source, kind="code", mode=mode.scalar)
            return unknown('compile_source_or_mode_unresolved', self.variables(node))
        if name in {"os.getenv", "os.environ.get"} and args:
            default = args[1].scalar.text if len(args) > 1 else None
            return self.scalar_map("str", (args[0],), lambda key: self.env.get(key.casefold() if self.paths.windows else key, default))
        if name in {"glob.glob", "glob.iglob"} and args and args[0].kind in {"str", "path"}:
            if node.keywords or len(args) != 1:
                return unknown("unsupported_glob_arguments", self.variables(node))
            return PythonValue("selection", replace(args[0].scalar, pattern=True, reason="python_glob"))
        if isinstance(node.func, ast.Attribute) or target.kind == "bound":
            owner = target.items[0] if target.kind == "bound" else self.evaluate(node.func.value, scope)
            method = target.scalar.text if target.kind == "bound" else node.func.attr
            if owner.kind == "file" and method == "read" or owner.kind == "path" and method == "read_text":
                if not node.args and not node.keywords:
                    return PythonValue("file_content", Value(None, "file_content_unresolved", owner.scalar.variables), items=(owner,))
            if owner.kind == "path":
                if method in {"joinpath", "with_name"} and args and all(v.kind in {"str", "path"} for v in args):
                    base = self.scalar_map("path", (owner,), self.paths.module.dirname) if method == "with_name" else owner
                    return self.scalar_map("path", [base, *args], self.paths.module.join)
                if method == "open":
                    mode_node = node.args[0] if node.args else next((k.value for k in node.keywords if k.arg == "mode"), ast.Constant("r"))
                    mode_value = self.evaluate(mode_node, scope)
                    mode = mode_value.scalar if mode_value.kind == "str" else Value(None, "unsupported_open_mode", mode_value.scalar.variables)
                    return PythonValue("file", owner.scalar, mode=mode, origin=id(node))
                if method in {"glob", "rglob"} and args:
                    if node.keywords or len(args) != 1:
                        return unknown("unsupported_glob_arguments", self.variables(node))
                    selection = self.scalar_map("path", (owner, args[0]), lambda a, b: self.paths.module.join(a, "**" if method == "rglob" else "", b))
                    return PythonValue("selection", replace(selection.scalar, pattern=True, reason="python_pathlib_glob"))
                if method in {"resolve", "absolute", "expanduser"}:
                    return PythonValue("path", Value(None, "python_path_transformation_unresolved", owner.scalar.variables))
        return unknown("unmodeled_python_call", self.variables(node))

    @staticmethod
    def snapshot(scope):
        bindings = {}
        scopes = []
        while scope:
            scopes.append(scope)
            scope = scope.parent
        for scope in reversed(scopes):
            for name, value in scope.symbols.items():
                # User-function IDs are local to this AST, never follow them
                # into a separate evaluated source or inspect a call graph.
                if value.kind in {"str", "path", "int", "bool", "namespace", "callable", "file", "file_content", "python_executable", "unknown", "code"}:
                    bindings[name] = value
        return tuple(bindings.items())
