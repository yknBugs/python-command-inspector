"""Bounded lexical assignment events; no evaluation of JavaScript programs."""
from dataclasses import dataclass, field, replace
import re
from ..models import Value
from ..shared.value_flow import ValueLimits, candidates, choices, join, bounded, compose
from .syntax import FUNCTIONS


@dataclass(frozen=True)
class JSValue:
    kind: str = 'unknown'
    scalar: Value = Value(None, 'unsupported_javascript_value')
    items: tuple = ()


def unknown(reason='unsupported_javascript_value', variables=()):
    return JSValue(scalar=Value(None, reason, tuple(variables)))


def scalar(text, kind='str'):
    return JSValue(kind, Value(text))


def decode(text):
    """Decode literal escapes only, never a JavaScript expression."""
    result, i = [], 0
    escapes = {'n':'\n', 'r':'\r', 't':'\t', 'b':'\b', 'f':'\f', 'v':'\v', '0':'\0'}
    try:
        while i < len(text):
            c = text[i]; i += 1
            if c != '\\':
                result.append(c); continue
            c = text[i]; i += 1
            if c in '\r\n':
                if c == '\r' and i < len(text) and text[i] == '\n': i += 1
                continue
            if c == 'x':
                result.append(chr(int(text[i:i+2],16))); i += 2
            elif c == 'u':
                if text[i] == '{':
                    end = text.index('}', i)
                    result.append(chr(int(text[i+1:end],16))); i = end+1
                else:
                    result.append(chr(int(text[i:i+4],16))); i += 4
            elif c.isdigit() and (c != '0' or i < len(text) and text[i].isdigit()):
                return None  # Legacy octal is deliberately not interpreted.
            else: result.append(escapes.get(c,c))
        return ''.join(result).encode('utf-16', 'surrogatepass').decode('utf-16')
    except (ValueError, IndexError, UnicodeError):
        return None


@dataclass(eq=False)
class Scope:
    number: int
    parent: object = None
    function: object = None
    assignments: dict = field(default_factory=dict)
    symbols: dict = field(default_factory=dict)
    params: list = field(default_factory=list)
    returns: list = field(default_factory=list)

    def owner(self, name):
        if name in self.assignments or any(n == name for n, _ in self.params) or self.parent is None:
            return self
        return self.parent.owner(name)

    def lookup(self, name):
        return self.owner(name).symbols.get(name, unknown('missing_variable', (name,)))


BUILTINS = {'fs', 'fs/promises', 'path', 'path/posix', 'path/win32', 'child_process', 'vm', 'process', 'http', 'https'}


class JavaScriptValues:
    def __init__(self, root, cwd, env, paths, *, source='command', possible_values=16, control_flow_steps=256, value_bytes=524288, javascript_bindings=()):
        self.cwd, self.env, self.paths, self.source = cwd, dict(env), paths, source
        self.limit, self.steps = ValueLimits(possible_values,value_bytes), control_flow_steps
        self.scopes = [Scope(0)]
        self.calls, self.functions, self.locations, self.mutations = [], {}, {}, []
        self.env_mutated = False
        self.reassignments = []
        self.parents = {}
        for name, value in javascript_bindings:
            self.scopes[0].assignments[name] = [(value,self.scopes[0],'value')]
        self.collect(root,self.scopes[0])
        # Resolve assignment owners after all declarations have been collected.
        for target, expression, origin in self.reassignments:
            self.bind(target, expression, origin, declaration=False)
        self.invalidate_mutations()
        self.cache = {}
        self.solve()

    def bind(self, target, value, scope, category='value', declaration=True):
        if target is None: return
        if target.kind in {'identifier','shorthand_property_identifier_pattern'}:
            owner = scope if declaration else scope.owner(target.text)
            owner.assignments.setdefault(target.text,[]).append((value,scope,category))
        elif target.kind == 'object_pattern':
            for child in target.children:
                if child.kind == 'pair_pattern':
                    self.bind(child.get('value'), (value,child.get('key').text),scope,'property',declaration)
                elif child.kind == 'shorthand_property_identifier_pattern':
                    self.bind(child,(value,child.text),scope,'property',declaration)
                else:
                    self.bind(child,None,scope,declaration=declaration)
        elif target.kind == 'array_pattern':
            for i, child in enumerate(target.children): self.bind(child,(value,i),scope,'index',declaration)
        elif target.kind in {'member_expression','subscript_expression'}:
            node = target
            while node.kind in {'member_expression','subscript_expression'}: node = node.get('object')
            if node and node.kind == 'identifier': self.mutations.append((scope,node.text))
            if target.text.startswith('process.env'): self.env_mutated = True

    def collect(self, node, scope):
        self.locations[node] = scope
        if node.kind in FUNCTIONS:
            child = Scope(len(self.scopes),scope,node); self.scopes.append(child); self.functions[node] = child
            name = node.get('name')
            if name and node.kind.endswith('declaration'):
                self.bind(name,scalar(str(child.number),'function'),scope)
            parameters = node.get('parameters')
            params = parameters.children if parameters else (node.get('parameter'),) if node.get('parameter') else ()
            for param in params:
                target = param.get('left') if param.kind == 'assignment_pattern' else param
                default = param.get('right') if param.kind == 'assignment_pattern' else None
                if target.kind == 'identifier': child.params.append((target.text,default))
                else: self.bind(target,None,child)
                if default: self.collect(default,scope)
            body = node.get('body')
            if body:
                if body.kind != 'statement_block': child.returns.append(body)
                self.collect(body,child)
            return
        if node.kind in {'statement_block','for_in_statement','for_statement','catch_clause'}:
            scope = Scope(len(self.scopes),scope); self.scopes.append(scope); self.locations[node] = scope
        if node.kind == 'import_statement':
            source = node.get('source'); module = decode(source.text[1:-1]) if source else None
            module = (module or '').removeprefix('node:')
            namespace = scalar(module,'namespace') if module in BUILTINS else unknown('uninspected_module')
            clause = next((c for c in node.children if c.kind == 'import_clause'),None)
            if clause:
                for c in clause.children:
                    if c.kind == 'identifier': self.bind(c,namespace,scope)
                    elif c.kind == 'namespace_import': self.bind(c.children[-1],namespace,scope)
                    elif c.kind == 'named_imports':
                        for spec in c.children:
                            target = spec.get('alias') or spec.get('name')
                            self.bind(target,self.property(namespace,spec.get('name').text),scope)
            return
        if node.kind == 'variable_declarator':
            # var declarations are function-scoped; let/const remain lexical.
            parent = self.parents.get(node) if hasattr(self,'parents') else None
            owner = scope
            if parent and parent.kind == 'variable_declaration':
                while owner.parent and owner.function is None: owner = owner.parent
            self.bind(node.get('name'),node.get('value'),owner)
        elif node.kind in {'assignment_expression','augmented_assignment_expression'}:
            self.reassignments.append((node.get('left'), node.get('right') if node.kind == 'assignment_expression' else None, scope))
        elif node.kind == 'update_expression': self.reassignments.append((node.get('argument'), None, scope))
        elif node.kind == 'for_in_statement':
            self.bind(node.get('left'),node.get('right'),scope,'iteration' if node.get('operator').text == 'of' else 'unknown')
        elif node.kind == 'return_statement':
            owner = scope
            while owner.parent and owner.function is None: owner = owner.parent
            if owner.function: owner.returns.append(node.children[0] if node.children else None)
        elif node.kind in {'call_expression','new_expression'}:
            self.calls.append((node,scope))
            function = node.get('function') or node.get('constructor')
            if function and function.kind == 'member_expression' and function.get('property').text in {'push','pop','shift','unshift','splice','sort','reverse','fill','copyWithin'}:
                obj = function.get('object')
                if obj.kind == 'identifier': self.mutations.append((scope,obj.text))
        if not hasattr(self,'parents'): self.parents = {}
        for child in node.children:
            self.parents[child] = node
            self.collect(child,scope)

    def invalidate_mutations(self):
        edges = {}
        for scope in self.scopes:
            for name, events in scope.assignments.items():
                for expression, origin, kind in events:
                    if kind == 'value' and getattr(expression,'kind',None) == 'identifier':
                        a,b = (scope,name),(origin.owner(expression.text),expression.text)
                        edges.setdefault(a,set()).add(b); edges.setdefault(b,set()).add(a)
        pending = [(s.owner(n),n) for s,n in self.mutations]; seen=set()
        while pending:
            item=pending.pop()
            if item in seen: continue
            seen.add(item); pending.extend(edges.get(item,()))
            scope,name=item
            scope.assignments.setdefault(name,[]).append((unknown('mutated_javascript_object',(name,)),scope,'value'))

    def merge(self, values, name=''):
        values=tuple(values); variables=tuple(sorted({n for v in values for n in v.scalar.variables} | ({name} if name else set())))
        if not values or any(v.kind=='unknown' for v in values) or len({v.kind for v in values}) != 1:
            return unknown(next((v.scalar.reason for v in values if v.kind=='unknown'),'mixed_javascript_types'),variables)
        kind=values[0].kind
        if kind == 'file_content':
            return JSValue(kind, items=(self.merge(v.items[0] for v in values),))
        if kind in {'array','object'}:
            if any(len(v.items)!=len(values[0].items) for v in values): return unknown('changed_object_shape',variables)
            if kind=='object':
                if any(tuple(k for k,_ in v.items)!=tuple(k for k,_ in values[0].items) for v in values): return unknown('changed_object_shape',variables)
                items=tuple((k,self.merge(v.items[i][1] for v in values)) for i,(k,_) in enumerate(values[0].items))
            else: items=tuple(self.merge(v.items[i] for v in values) for i in range(len(values[0].items)))
            return JSValue(kind,Value(None,variables=variables),items)
        budget = self.limit
        if kind in {'callable', 'namespace', 'function'}:
            budget = ValueLimits(self.limit.count, max(self.limit.bytes, sum(len(c.text.encode('utf-8')) for v in values for c in candidates(v.scalar) if c.text is not None)))
        result=join((v.scalar for v in values),budget,name)
        if result.text is None and not result.alternatives: return unknown(result.reason,variables)
        return JSValue(kind,result)

    def compose(self, values, function, kind='str'):
        if any(v.kind not in {'str','number','bool','namespace','callable'} for v in values): return unknown('unsupported_composition')
        bindings={str(i):v.scalar for i,v in enumerate(values)}
        rows,_=choices(bindings,bindings,self.limit); results=[]
        for row in rows or (bindings,):
            parts=[row.get(str(i),v.scalar) for i,v in enumerate(values)]
            if any(v.text is None for v in parts): return unknown('possible_values_limit', {n for p in parts for n in p.variables})
            if sum(len(v.text.encode('utf-8')) for v in parts)>self.limit.bytes: return unknown('value_bytes_limit')
            rendered=function(*(v.text for v in parts))
            value=rendered if isinstance(rendered,Value) else Value(rendered)
            value=bounded(replace(value,variables=tuple(sorted({n for p in parts for n in p.variables}))),self.limit)
            results.append(JSValue(kind,value))
        return self.merge(results)

    def property(self, owner, key):
        if owner.kind in {'namespace','callable'}:
            if owner.scalar.text=='process.env':
                value=None if self.env_mutated else self.env.get(key)
                if self.paths.windows and not self.env_mutated: value=next((v for k,v in self.env.items() if k.casefold()==key.casefold()),None)
                return JSValue('str',value if isinstance(value,Value) else Value(value,'missing_variable' if value is None else None,(key,)))
            # Built-in identities are source syntax, not expanded user values.
            # A tiny value budget must not hide a known effect method.
            names = [Value(v.text + '.' + key, variables=v.variables) for v in candidates(owner.scalar) if v.text is not None]
            if not names:
                return unknown('unresolved_builtin_member')
            identity_limit = ValueLimits(self.limit.count, max(self.limit.bytes, sum(len(v.text.encode('utf-8')) for v in names)))
            return JSValue('callable', join(names, identity_limit))
        if owner.kind=='object': return dict(owner.items).get(key,unknown('missing_property'))
        if owner.kind=='array' and str(key).isdigit():
            i=int(key); return owner.items[i] if i<len(owner.items) else unknown('invalid_index')
        return unknown('unsupported_member',owner.scalar.variables)

    def evaluate(self,node,scope):
        if isinstance(node,JSValue): return node
        if node is None: return unknown('missing_javascript_value')
        key=(node,scope.number)
        if key not in self.cache:
            self.cache[key]=unknown('recursive_value')
            self.cache[key]=self.expression(node,scope)
        return self.cache[key]

    def expression(self,node,scope):
        kind=node.kind
        if kind in {'string','string_fragment','escape_sequence'}:
            text=decode(node.text[1:-1] if kind=='string' else node.text)
            return JSValue('str',bounded(Value(text,'unsupported_string' if text is None else None),self.limit))
        if kind in {'true','false'}: return scalar(node.text,'bool')
        if kind=='number':
            try:
                number = node.text.replace('_', '')
                return scalar(str(int(number, 0) if number.lower().startswith(('0x', '0o', '0b')) else int(number)), 'number')
            except ValueError:
                return unknown('unsupported_numeric_value')
        if kind in {'identifier','shorthand_property_identifier'}:
            owner=scope.owner(node.text)
            if node.text not in owner.assignments and not any(n==node.text for n,_ in owner.params):
                if node.text in {'require','eval','Function','setTimeout','setInterval','setImmediate','fetch'}: return scalar(node.text,'callable')
                if node.text=='process': return scalar('process','namespace')
                if node.text in {'__dirname','__filename'} and self.paths.absolute(self.source) and self.source.endswith(('.js', '.cjs')):
                    return scalar(self.paths.module.dirname(self.source) if node.text=='__dirname' else self.source)
            value=scope.lookup(node.text)
            return replace(value,scalar=replace(value.scalar,variables=tuple(sorted(set(value.scalar.variables)|{node.text}))))
        if kind in FUNCTIONS: return scalar(str(self.functions[node].number),'function')
        if kind in {'parenthesized_expression','await_expression'}: return self.evaluate(node.children[-1],scope)
        if kind=='array':
            # Named children omit holes. Do not shift a sparse argv/path array.
            if any(c.kind == 'spread_element' for c in node.children) or re.search(r'(?:\[|,)\s*,', node.text):
                return unknown('sparse_or_spread_array')
            return JSValue('array',items=tuple(self.evaluate(c,scope) for c in node.children if c.kind != 'comment'))
        if kind=='object':
            properties=[]
            for c in node.children:
                if c.kind=='pair':
                    key=c.get('key'); name=decode(key.text[1:-1]) if key.kind=='string' else key.text if key.kind in {'property_identifier','number'} else None
                    if name is None: return unknown('computed_object_key')
                    properties.append((name,self.evaluate(c.get('value'),scope)))
                elif c.kind=='shorthand_property_identifier': properties.append((c.text,self.evaluate(c,scope)))
                else: return unknown('unsupported_object')
            return JSValue('object',items=tuple(properties))
        if kind in {'member_expression','subscript_expression'}:
            owner=self.evaluate(node.get('object'),scope)
            key=node.get('property') or node.get('index')
            if kind=='member_expression': return self.property(owner,key.text)
            value=self.evaluate(key,scope)
            if value.scalar.text is not None: return self.property(owner,value.scalar.text)
            return unknown('dynamic_property',value.scalar.variables)
        if kind=='ternary_expression': return self.merge((self.evaluate(node.get('consequence'),scope),self.evaluate(node.get('alternative'),scope)))
        if kind=='template_string':
            parts=[self.evaluate(c.children[0],scope) if c.kind=='template_substitution' else self.evaluate(c,scope) for c in node.children]
            return self.compose(parts,lambda *parts:compose((Value(p) for p in parts),limit=self.limit))
        if kind=='binary_expression' and node.get('operator').text=='+':
            a,b=self.evaluate(node.get('left'),scope),self.evaluate(node.get('right'),scope)
            if a.kind==b.kind=='str': return self.compose((a,b),lambda a,b:compose((Value(a),Value(b)),limit=self.limit))
        if kind in {'call_expression','new_expression'}:
            target=self.evaluate(node.get('function') or node.get('constructor'),scope)
            argsnode=node.get('arguments'); args=[self.evaluate(c,scope) for c in argsnode.children] if argsnode else []
            name=target.scalar.text
            if target.kind=='function':
                return self.merge(self.evaluate(r,self.locations.get(r,self.scopes[int(c.text)])) for c in candidates(target.scalar) for r in self.scopes[int(c.text)].returns)
            if name == 'Function' and args:
                if any(arg.kind != 'str' for arg in args):
                    return unknown('dynamic_function_source')
                return self.compose(args, lambda *parts: 'function __dynamic__(' + ','.join(parts[:-1]) + '){\n' + parts[-1] + '\n}', 'dynamic_function')
            if name=='require' and args and args[0].scalar.text is not None:
                module=args[0].scalar.text.removeprefix('node:')
                return scalar(module,'namespace') if module in BUILTINS else unknown('uninspected_module')
            if name=='process.cwd': return scalar(self.cwd) if self.cwd is not None else unknown('cwd_unresolved')
            if name in {'path.join','path.resolve','path/posix.join','path/posix.resolve','path/win32.join','path/win32.resolve','path.posix.join','path.posix.resolve','path.win32.join','path.win32.resolve'}:
                import posixpath, ntpath
                module=ntpath if 'win32' in name else posixpath if 'posix' in name else self.paths.module
                if any(a.kind!='str' for a in args): return unknown('unsupported_path_type')
                if name.endswith('.resolve'):
                    if self.cwd is None: return unknown('cwd_unresolved')
                    args=[scalar(self.cwd),*args]
                def path_operation(*parts):
                    if name.endswith('.resolve'):
                        result = module.normpath(module.join(*parts)) if parts else '.'
                        if module is ntpath and not self.paths.absolute(result):
                            return Value(None, 'unknown_drive_cwd')
                        return result
                    # Node join concatenates segments before normalization; a
                    # rooted later segment does not discard preceding segments.
                    separator = '\\' if module is ntpath else '/'
                    if module is ntpath and any(ntpath.splitdrive(p)[0] for p in parts[1:]):
                        return Value(None, 'unsupported_join_drive_segment')
                    return module.normpath(separator.join(p for p in parts if p)) if any(parts) else '.'
                return self.compose(args, path_operation)
            if name and name.startswith('path.') and name.split('.')[-1] in {'dirname','basename','extname'} and args:
                op=name.split('.')[-1]; fn=self.paths.module.dirname if op=='dirname' else self.paths.module.basename if op=='basename' else lambda p:self.paths.module.splitext(p)[1]
                return self.compose((args[0],),fn)
            if name and name.startswith(('fs.','fs/promises.')) and name.split('.')[-1] in {'readFile','readFileSync'} and args:
                options = args[1] if len(args) > 1 else unknown('buffer_content')
                encoding = dict(options.items).get('encoding', unknown('buffer_content')) if options.kind == 'object' else options
                parent = self.parents.get(node)
                awaited = parent is not None and parent.kind == 'await_expression'
                promise = name.startswith(('fs.promises.', 'fs/promises.'))
                if encoding.scalar.text in {'utf8', 'utf-8'} and (name.endswith('Sync') or promise and awaited):
                    return JSValue('file_content', items=(args[0],))
                return unknown('asynchronous_or_buffer_content')
        return unknown('unsupported_javascript_expression')

    def solve(self):
        for _ in range(self.steps):
            self.cache={}; parameters={}
            for call,scope in self.calls:
                function=self.evaluate(call.get('function') or call.get('constructor'),scope)
                if function.kind!='function': continue
                argnode=call.get('arguments'); args=argnode.children if argnode else ()
                for choice in candidates(function.scalar):
                    target=self.scopes[int(choice.text)]
                    for i,(name,default) in enumerate(target.params):
                        expression=args[i] if i<len(args) else default
                        parameters.setdefault((target.number,name),[]).append(self.evaluate(expression,scope if i<len(args) else target.parent))
            updates=[]
            for scope in self.scopes:
                symbols={}
                for name,events in scope.assignments.items():
                    values=[]
                    for expression,origin,kind in events:
                        if kind in {'property','index'}:
                            expression,key=expression; value=self.property(self.evaluate(expression,origin),str(key))
                        else:
                            value=self.evaluate(expression,origin)
                            if kind=='iteration': value=self.merge(value.items) if value.kind=='array' else unknown('runtime_iteration')
                            if kind=='unknown': value=unknown('runtime_iteration')
                        values.append(value)
                    symbols[name]=self.merge(values,name)
                for name,default in scope.params:
                    values=parameters.get((scope.number,name),[unknown('unbound_parameter',(name,))])
                    symbols[name]=self.merge([*values,*([symbols[name]] if name in symbols else [])],name)
                updates.append(symbols)
            if all(s.symbols==v for s,v in zip(self.scopes,updates)): break
            for scope,symbols in zip(self.scopes,updates): scope.symbols=symbols
        else:
            for scope in self.scopes:
                scope.symbols={k:v if v.kind in {'namespace','callable','function'} else unknown('control_flow_limit',(k,)) for k,v in scope.symbols.items()}
        self.cache={}

    def snapshot(self,scope):
        result={}; chain=[]
        while scope: chain.append(scope); scope=scope.parent
        for scope in reversed(chain): result.update({k:v for k,v in scope.symbols.items() if v.kind!='function'})
        return tuple(result.items())
