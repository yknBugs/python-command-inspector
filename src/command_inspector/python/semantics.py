"""Python effect events lowered into shared filesystem/execution checks.

Submitted modules are never loaded. Assignment candidates and call events do
not establish runtime reachability or execution order. Unsupported return values
remain unresolved at modeled operations.
"""
import ast
from collections import Counter
from dataclasses import replace

from ..models import Fact, Value
from ..paths import PathStyle
from ..shared.value_flow import bounded_arguments, candidates, compose, mark
from .values import PythonValue, PythonValues, unknown

SUBPROCESS_CALLS = frozenset({'subprocess.run', 'subprocess.call', 'subprocess.check_call',
                              'subprocess.check_output', 'subprocess.Popen'})
DELETE_CALLS = frozenset({'shutil.rmtree', 'os.removedirs', 'os.rmdir', 'os.remove', 'os.unlink'})
COPY_CALLS = frozenset({'shutil.copy', 'shutil.copy2', 'shutil.copyfile', 'shutil.copytree'})
MOVE_CALLS = frozenset({'shutil.move', 'os.rename', 'os.replace'})
READ_CALLS = frozenset({'os.listdir', 'os.scandir', 'os.stat', 'os.lstat', 'os.access',
                       'os.path.exists', 'os.path.isfile', 'os.path.isdir', 'os.path.getsize'})


class PythonBuilder:
    def __init__(self, cwd, env, *, source='command', context='invoked_now', paths=None,
                 possible_values=16, control_flow_steps=256, value_bytes=524288, python_bindings=()):
        self.cwd, self.env = cwd, dict(env)
        self.source, self.context = source, context
        self.paths = paths if paths is not None else PathStyle()
        self.budgets = dict(possible_values=possible_values, control_flow_steps=control_flow_steps, value_bytes=value_bytes)
        self.python_bindings = python_bindings

    def build(self, root: ast.Module) -> tuple[Fact, ...]:
        self.values = PythonValues(root, self.cwd, self.env, self.paths, python_bindings=self.python_bindings, **self.budgets)
        self.limit = self.values.limit
        self.called_scopes = set()
        # Activate calls only from module/class execution or already called
        # function bodies; calls in dormant definitions stay definition-only.
        for _ in range(len(self.values.scopes)):
            activated = {int(candidate.text) for call, scope, defined in self.values.calls
                         if (not defined or self.called_body(scope))
                         and (target := self.values.evaluate(call.func, scope)).kind == 'function'
                         for candidate in candidates(target.scalar)}
            if activated <= self.called_scopes:
                break
            self.called_scopes.update(activated)
        self.effect_cwd = self.cwd
        if any((not defined or self.called_body(scope)) and self.values.call_name(call.func, scope) == 'os.chdir' for call, scope, defined in self.values.calls):
            self.effect_cwd = None  # Enumeration does not establish the cwd before a call.
        self.writes = Counter()
        self.stream_reads = Counter()
        self.stream_seeks = set()
        for call, scope, _ in self.values.calls:
            target = self.values.evaluate(call.func, scope)
            if target.kind == 'bound' and target.items[0].kind == 'file':
                origin = target.items[0].origin
                if target.scalar.text in {'read', 'readline', 'readlines'}:
                    self.stream_reads[origin] += 1
                if target.scalar.text == 'seek':
                    self.stream_seeks.add(origin)
            if target.kind == 'callable' and target.scalar.text in {'list', 'tuple', 'next'} and call.args:
                stream = self.values.evaluate(call.args[0], scope)
                if stream.kind == 'file':
                    self.stream_seeks.add(stream.origin)
            if target.kind == 'bound' and target.scalar.text in {'write', 'writelines', 'seek', 'truncate'}:
                handle = target.items[0]
                if handle.kind == 'file':
                    self.writes[handle.origin] += 1
        for expression, scope, _ in self.values.iterations:
            stream = self.values.evaluate(expression, scope)
            if stream.kind == 'file':
                self.stream_seeks.add(stream.origin)
        from .secrets import secret_facts
        facts = secret_facts(root, self.source, self.context, self.cwd, self.budgets['value_bytes'])
        self.choice_serial = len(self.values.calls)
        # Nested argument calls precede surrounding calls in this event stream;
        # this does not assert runtime reachability or execution order.
        events = sorted(self.values.calls, key=lambda e: (getattr(e[0], 'end_lineno', 0), getattr(e[0], 'end_col_offset', 0)))
        for group, (call, scope, defined) in enumerate(events, 1):
            context = self.event_context(scope, defined)
            placeholder = Fact('content', 'inspect', flags=frozenset({'possible', 'python_events'}),
                               source=self.source, context=context, cwd=self.effect_cwd,
                               bindings=tuple(self.env.items()), shell='python', python_event=(self.source, group))
            target = self.values.evaluate(call.func, scope)
            names = candidates(target.scalar) if target.kind in {'callable', 'bound'} else (Value(None),)
            metadata = []
            for name in self.values.variables(call):
                binding = scope.lookup(name).scalar
                if binding.alternatives:
                    metadata.append((name, tuple(v.text for v in binding.alternatives)))
            for case, name in enumerate(names):
                effects = self.effects(call, name.text, scope, placeholder)
                facts.extend(mark(effects, tuple(metadata), group if len(names) > 1 else None, case))
        for expression, scope, defined in self.values.iterations:
            value = self.values.evaluate(expression, scope)
            if value.kind == 'file':
                context = self.event_context(scope, defined)
                fact = Fact('read', 'ingest', flags=frozenset({'possible', 'python_events'}), source=self.source, context=context, cwd=self.effect_cwd, shell='python')
                facts.append(self.filesystem(fact, 'read', 'ingest', value))
        return tuple(facts)

    def stream_position_unknown(self, stream, *, reading=True):
        if stream.kind == 'path':
            return False  # read_text opens a fresh stream for each call.
        return (stream.origin is None or stream.origin in self.stream_seeks
                or self.stream_reads[stream.origin] > (1 if reading else 0))

    def called_body(self, scope):
        while scope:
            if isinstance(scope.function, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                return scope.number in self.called_scopes
            scope = scope.parent
        return False

    def event_context(self, scope, defined):
        return 'defined_body' if defined and not self.called_body(scope) and self.context != 'written_content' else self.context

    @staticmethod
    def call_name(node):
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        return '.'.join([node.id, *reversed(parts)]) if isinstance(node, ast.Name) else None

    @staticmethod
    def argument(node, position, names, default=None):
        return node.args[position] if position is not None and len(node.args) > position else next(
            (k.value for k in node.keywords if k.arg in names), default)

    def value(self, node, position, names, scope, default=None):
        return self.values.evaluate(self.argument(node, position, names, default), scope)

    @staticmethod
    def unresolved(fact, rule, title, *values):
        return replace(fact, kind='unresolved', operation=rule, payload=title,
                       values=tuple(v.scalar if isinstance(v, PythonValue) else v for v in values))

    def filesystem(self, fact, kind, operation, value, *, payload=None, payload_value=None, flags=()):
        scalar = value.scalar if value.kind in {'str', 'path', 'file', 'unknown'} else Value(None, 'unsupported_path_type', value.scalar.variables)
        resolved = self.paths.resolve(scalar, fact.cwd)
        return replace(fact, kind=kind, operation=operation, targets=(resolved,) if resolved is not None else (),
                       values=(scalar,), payload=payload, payload_value=payload_value,
                       flags=fact.flags | frozenset(flags))

    def effects(self, node, name, scope, fact):
        descriptor_keywords = {'dir_fd', 'src_dir_fd', 'dst_dir_fd'}
        descriptors = [k.value for k in node.keywords if k.arg in descriptor_keywords
                       and not (isinstance(k.value, ast.Constant) and k.value.value is None)]
        if descriptors:
            # Without a descriptor model, no relative operand has a confirmed
            # cwd base. Absolute operands remain resolvable independently.
            fact = replace(fact, cwd=None)
        effects = self._effects(node, name, scope, fact)
        if descriptors and effects:
            effects.append(self.unresolved(fact, 'file-operation-unresolved',
                'Directory-descriptor path bases are unresolved',
                *(self.values.evaluate(v, scope) for v in descriptors)))
        return effects

    def evaluation_bindings(self, node, scope):
        namespaces = [self.argument(node, i, {key}) for i, key in ((1, 'globals'), (2, 'locals'))]
        explicit = [v for v in namespaces if v is not None and not (isinstance(v, ast.Constant) and v.value is None)]
        if not explicit:
            return self.values.snapshot(scope), False
        globals_node = namespaces[0]
        if globals_node is None or isinstance(globals_node, ast.Constant) and globals_node.value is None:
            global_scope = scope
            while global_scope.parent:
                global_scope = global_scope.parent
            bindings = dict(self.values.snapshot(global_scope))
        else:
            bindings = {}
        for mapping in explicit:
            if not isinstance(mapping, ast.Dict) or any(not isinstance(k, ast.Constant) or not isinstance(k.value, str) for k in mapping.keys):
                return (), True
            bindings.update((k.value, self.values.evaluate(v, scope)) for k, v in zip(mapping.keys, mapping.values))
        return tuple(bindings.items()), False

    def _effects(self, node, name, scope, fact):
        receiver = self.values.evaluate(node.func.value, scope) if isinstance(node.func, ast.Attribute) else unknown()
        method = node.func.attr if isinstance(node.func, ast.Attribute) else None
        target = self.values.evaluate(node.func, scope)
        if target.kind == 'bound':
            receiver, method = target.items[0], name
        path = self.value(node, 0, {'path', 'name', 'file', 'filename'}, scope)
        if name == 'os.system' or name in SUBPROCESS_CALLS:
            return self.subprocess(node, name, scope, fact)
        if name in {'exec', 'eval', 'builtins.exec', 'builtins.eval'}:
            source = self.value(node, 0, {'source', 'object'}, scope)
            bindings, uncertain_namespace = self.evaluation_bindings(node, scope)
            notices = [self.unresolved(fact, 'execution-content-unavailable', 'Explicit Python evaluation namespace is unresolved')] if uncertain_namespace else []
            if source.kind in {'str', 'code'}:
                mode = source.mode.text if source.kind == 'code' and source.mode is not None else 'eval' if name in {'eval', 'builtins.eval'} else 'exec'
                if mode not in {'exec', 'eval', 'single'}:
                    return [self.unresolved(fact, 'execution-content-unavailable', 'Compiled Python parsing mode is unresolved or invalid', source)]
                return [*notices, replace(fact, kind='inline', operation='python', payload=source.scalar.text,
                                payload_value=source.scalar, source=self.source + ':eval', python_bindings=bindings,
                                flags=fact.flags | {'python_mode:' + mode})]
            if source.kind == 'file_content':
                if self.stream_position_unknown(source.items[0]):
                    return [*notices, self.unresolved(fact, 'execution-content-unavailable', 'Evaluated stream position is unresolved', source)]
                mode = 'eval' if name in {'eval', 'builtins.eval'} else 'exec'
                return [*notices, replace(fact, kind='execute', operation='python', flags=fact.flags | {'stdin_source', 'python_mode:' + mode},
                                stdin_sources=(source.items[0].scalar,), python_bindings=bindings)]
            return [self.unresolved(fact, 'execution-content-unavailable', 'Dynamically evaluated Python content is unresolved', source)]
        if name == 'runpy.run_path':
            return [replace(fact, kind='execute', operation='python', values=(path.scalar,))]
        if name == 'runpy.run_module':
            return [self.unresolved(fact, 'execution-content-unavailable', 'Python module execution content is not inspected', path)]
        if name in {'list', 'tuple', 'next'} and path.kind == 'file':
            return [self.filesystem(fact, 'read', 'ingest', path, flags={'selection_uncertain'})]
        if name in DELETE_CALLS or receiver.kind == 'path' and method in {'unlink', 'rmdir'}:
            target = receiver if receiver.kind == 'path' else path
            flags = {'-r', '-R', 'unconditional'} if name == 'shutil.rmtree' else {'unconditional'}
            effect = self.filesystem(fact, 'delete', 'delete', target, flags=flags)
            if target.kind == 'unknown':
                return [self.unresolved(fact, 'unresolved-value', 'Deletion target is dynamically constructed', target), effect]
            return [effect]
        if name == 'os.truncate' or receiver.kind == 'file' and method == 'truncate':
            target = receiver if receiver.kind == 'file' else path
            length = self.value(node, 0 if receiver.kind == 'file' else 1, {'size', 'length'}, scope)
            payload = '' if length.kind == 'int' and length.scalar.text == '0' else None
            return [self.filesystem(fact, 'write', 'overwrite', target, payload=payload, flags={'runtime_output'} if payload is None else ())]
        if name in {'open', 'builtins.open', 'io.open', 'os.open'} or receiver.kind == 'path' and method == 'open':
            handle = self.values.evaluate(node, scope)
            if name == 'os.open':
                flag_node = self.argument(node, 1, {'flags'})
                flag = self.values.evaluate(flag_node, scope)
                if flag.kind == 'int' and flag.scalar.text in {'0', '1', '2'}:
                    effects = [self.filesystem(fact, 'read', 'list', path)] if flag.scalar.text in {'0', '2'} else []
                    if flag.scalar.text in {'1', '2'}:
                        effects.append(self.filesystem(fact, 'write', 'transform', path))
                    return effects
                return [self.filesystem(fact, 'read', 'list', path), self.filesystem(fact, 'invalidate', 'unknown_open_mode', path),
                        self.unresolved(fact, 'file-operation-unresolved', 'Low-level Python open flags are unresolved', path, flag)]
            return self.open_effects(handle, fact)
        if receiver.kind == 'file' and method in {'read', 'readline', 'readlines'}:
            uncertain_position = self.stream_position_unknown(receiver)
            flags = {'selection_uncertain'} if uncertain_position else {'head_lines:1'} if method == 'readline' else set()
            size_node = self.argument(node, 0, {'size', 'n'})
            if size_node is not None:
                size = self.values.evaluate(size_node, scope)
                if size.kind == 'int' and size.scalar.text is not None and int(size.scalar.text) == 0 and method != 'readlines':
                    return [self.filesystem(fact, 'read', 'list', receiver)]
                if size.kind == 'int' and size.scalar.text is not None and int(size.scalar.text) > 0 and method != 'readlines':
                    flags.add('selection_uncertain' if uncertain_position else 'head_chars:' + size.scalar.text)
                else:
                    flags.add('selection_uncertain')
            return [self.filesystem(fact, 'read', 'ingest', receiver, flags=flags)]
        if receiver.kind == 'file' and method in {'write', 'writelines'}:
            payload = self.value(node, 0, {'s', 'data', 'lines'}, scope)
            if method == 'writelines' and payload.kind == 'sequence':
                payload = self.values.scalar_map('str', payload.items, lambda *parts: compose((Value(v) for v in parts), limit=self.limit))
            effects = []
            for mode in candidates(receiver.mode or Value(None)):
                if mode.text is None:
                    effects.extend([self.filesystem(fact, 'invalidate', 'unknown_write_mode', receiver),
                                    self.unresolved(fact, 'file-operation-unresolved', 'File handle write mode is unresolved', receiver, mode)])
                    continue
                if not self.valid_mode(mode.text) or not any(c in mode.text for c in 'wax+'):
                    effects.append(self.unresolved(fact, 'unresolved-value', 'File handle mode does not permit writing', receiver))
                    continue
                if 'r' in mode.text and '+' in mode.text:
                    # Updating a stream leaves a suffix/offset dependent on
                    # existing contents. The payload alone is not a new script.
                    effects.extend([self.filesystem(fact, 'write', 'transform', receiver),
                                    self.unresolved(fact, 'unresolved-value', 'Final updated stream content is unresolved', receiver)])
                    continue
                overwrite = mode.text is not None and any(c in mode.text for c in 'wx') and self.writes[receiver.origin] == 1
                content = payload.scalar if payload.kind == 'str' else None
                operation = 'create' if overwrite and 'x' in mode.text else 'overwrite' if overwrite else 'append'
                effects.append(self.filesystem(fact, 'write', operation, receiver,
                                               payload=content.text if content else None, payload_value=content,
                                               flags={'create_if_missing'} if operation == 'create' else ()))
            return effects
        if receiver.kind == 'path' and method in {'read_text', 'read_bytes'}:
            return [self.filesystem(fact, 'read', 'ingest', receiver)]
        if receiver.kind == 'path' and method in {'write_text', 'write_bytes'}:
            content = self.value(node, 0, {'data'}, scope)
            payload = content.scalar if content.kind == 'str' and method == 'write_text' else None
            return [self.filesystem(fact, 'write', 'overwrite', receiver, payload=payload.text if payload else None, payload_value=payload,
                                    flags={'runtime_output'} if method == 'write_bytes' else ())]
        if name in {'os.mkdir', 'os.makedirs'} or receiver.kind == 'path' and method == 'mkdir':
            return [self.filesystem(fact, 'write', 'create_directory', receiver if receiver.kind == 'path' else path)]
        if name == 'os.chdir':
            return [self.filesystem(replace(fact, cwd=self.cwd), 'read', 'list', path)]
        if name in READ_CALLS or receiver.kind == 'path' and method in {'exists', 'is_file', 'is_dir', 'stat', 'lstat', 'iterdir'}:
            target = receiver if receiver.kind == 'path' else path
            if self.argument(node, 0, {'path'}) is None and name in {'os.listdir', 'os.scandir'}:
                target = PythonValue('str', Value('.'))
            return [self.filesystem(fact, 'read', 'list', target)]
        if name in COPY_CALLS | MOVE_CALLS or receiver.kind == 'path' and method in {'rename', 'replace'}:
            source = receiver if receiver.kind == 'path' else self.value(node, 0, {'src'}, scope)
            destination = self.value(node, 0 if receiver.kind == 'path' else 1, {'dst', 'target'}, scope)
            operation = 'copy' if name in COPY_CALLS else 'move'
            strict = name in {'shutil.copyfile', 'os.rename', 'os.replace'} or receiver.kind == 'path'
            transfer = self.filesystem(fact, 'transfer', operation, destination, flags={'-T'} if strict else ())
            if name == 'shutil.copytree':
                return [self.filesystem(fact, 'read', 'list', source), self.filesystem(fact, 'write', 'transform', destination),
                        self.unresolved(fact, 'unresolved-value', 'Recursive Python copy contents are not enumerated', source, destination)]
            return [self.filesystem(fact, 'read', 'list', source), replace(transfer, transfer_sources=(source.scalar,))]
        if name == 'os.chmod' or receiver.kind == 'path' and method == 'chmod':
            mode = self.value(node, 0 if receiver.kind == 'path' else 1, {'mode'}, scope)
            target = receiver if receiver.kind == 'path' else path
            effects = [self.filesystem(fact, 'write', 'transform', target)]
            if mode.kind == 'int' and mode.scalar.text == '511':
                effects.append(replace(effects[0], kind='permissions', operation='777'))
            return effects
        if receiver.kind == 'unknown' and method in {'unlink', 'rmdir', 'read_text', 'write_text', 'read', 'write', 'truncate'}:
            effects = [self.unresolved(fact, 'unresolved-value', 'Python method receiver or target is unresolved', receiver)]
            if method in {'unlink', 'rmdir'}:
                effects.append(self.filesystem(fact, 'delete', 'delete', receiver, flags={'unconditional'}))
            elif method in {'write_text', 'write', 'truncate'}:
                effects.append(self.filesystem(fact, 'write', 'transform', receiver))
            else:
                effects.append(self.filesystem(fact, 'read', 'ingest', receiver))
            return effects
        return []

    def open_effects(self, handle, fact):
        effects = []
        for mode in candidates(handle.mode or Value(None)):
            if mode.text is None:
                effects.extend([self.filesystem(fact, 'read', 'list', handle), self.filesystem(fact, 'invalidate', 'unknown_open_mode', handle),
                                self.unresolved(fact, 'file-operation-unresolved', 'Python file open mode is unresolved', mode)])
            elif not self.valid_mode(mode.text):
                effects.append(self.unresolved(fact, 'unresolved-value', 'Python file open mode is invalid', mode))
                continue
            elif 'r' in mode.text or '+' in mode.text:
                effects.append(self.filesystem(fact, 'read', 'list', handle))
            if mode.text and 'w' in mode.text:
                effects.append(self.filesystem(fact, 'write', 'overwrite', handle, payload=''))
            elif mode.text and ('a' in mode.text or 'x' in mode.text):
                # Opening an append handle creates a missing file but does not
                # append authored content or inspect an existing script.
                effects.append(self.filesystem(fact, 'write', 'create', handle, flags={'runtime_output', 'create_if_missing'}))
        return effects

    @staticmethod
    def valid_mode(mode):
        return bool(mode) and all(c in 'rwaxbt+' for c in mode) and sum(mode.count(c) for c in 'rwax') == 1 and mode.count('+') <= 1 and mode.count('b') + mode.count('t') <= 1

    def subprocess(self, node, function, scope, fact, *, shell_override=None):
        arguments = self.value(node, 0, {'args', 'command'}, scope)
        shell = shell_override or self.value(node, None, {'shell'}, scope, ast.Constant(False))
        if function != 'os.system' and shell.kind == 'bool' and shell.scalar.alternatives:
            self.choice_serial += 1
            group = self.choice_serial
            return [effect for index, choice in enumerate(shell.scalar.alternatives)
                    for effect in mark(self.subprocess(node, function, scope, fact, shell_override=replace(shell, scalar=choice)), (), group, index)]
        if arguments.kind == 'file_content' and self.stream_position_unknown(arguments.items[0]):
            return [self.unresolved(fact, 'execution-content-unavailable', 'Subprocess source stream position is unresolved', arguments)]
        if arguments.kind == 'file_content' and (function == 'os.system' or shell.kind == 'bool' and shell.scalar.text == 'True'):
            return [replace(fact, kind='execute', operation='cmd' if self.paths.windows else 'sh',
                            flags=fact.flags | {'stdin_source', 'stdin_program'}, stdin_sources=(arguments.items[0].scalar,))]
        if self.paths.windows and function != 'os.system' and arguments.kind == 'str' and not (shell.kind == 'bool' and shell.scalar.text == 'True'):
            return [self.unresolved(fact, 'execution-content-unavailable', 'Windows subprocess command-line string binding is not modeled', arguments)]
        words = (arguments,) if arguments.kind in {'str', 'path'} else arguments.items if arguments.kind == 'sequence' else None
        if words is None:
            return [self.unresolved(fact, 'unresolved-value', 'Subprocess arguments are dynamically constructed', arguments)]
        if not words:
            return []
        if words[0].kind == 'python_executable':
            words = (PythonValue('str', Value('python')), *words[1:])
        cwd_node = self.argument(node, None, {'cwd'})
        if isinstance(cwd_node, ast.Constant) and cwd_node.value is None:
            cwd_node = None
        cwd_value = self.values.evaluate(cwd_node, scope) if cwd_node is not None else None
        cwd = self.paths.resolve(cwd_value.scalar, self.effect_cwd) if cwd_value is not None else self.effect_cwd
        fact = replace(fact, cwd=cwd, source=self.source + ':subprocess')
        warnings = []
        env_node = self.argument(node, None, {'env'})
        if env_node is not None and not (isinstance(env_node, ast.Constant) and env_node.value is None):
            fact = replace(fact, bindings=())
            warnings.append(self.unresolved(fact, 'unresolved-value', 'Subprocess environment mapping is unresolved'))
        input_node = self.argument(node, None, {'input', 'stdin'})
        if input_node is not None and not (isinstance(input_node, ast.Constant) and input_node.value is None):
            stream = self.values.evaluate(input_node, scope)
            fact = replace(fact, flags=fact.flags | {'stdin_source'})
            if stream.kind == 'str' and any(k.arg == 'input' for k in node.keywords):
                fact = replace(fact, stdin_payload=stream.scalar.text, stdin_payload_value=stream.scalar)
            elif stream.kind in {'file', 'file_content'}:
                owner = stream.items[0] if stream.kind == 'file_content' else stream
                if self.stream_position_unknown(owner, reading=stream.kind == 'file_content'):
                    warnings.append(self.unresolved(fact, 'execution-content-unavailable', 'Subprocess input stream position is unresolved', stream))
                else:
                    fact = replace(fact, stdin_sources=(owner.scalar,))
            else:
                warnings.append(self.unresolved(fact, 'unresolved-value', 'Subprocess input stream is unresolved', stream))
        executable_node = self.argument(node, None, {'executable'})
        if executable_node is not None and not (isinstance(executable_node, ast.Constant) and executable_node.value is None):
            executable = self.values.evaluate(executable_node, scope)
            if shell.kind == 'bool' and shell.scalar.text == 'False':
                words = (executable, *words[1:])
                if executable.kind == 'python_executable':
                    words = (PythonValue('str', Value('python')), *words[1:])
            else:
                # A replacement shell's command-line convention cannot be
                # inferred from the ordinary shell=True profile.
                return [*warnings, self.unresolved(fact, 'execution-content-unavailable', 'Replacement subprocess shell behavior is unresolved', executable)]
        language = 'cmd' if self.paths.windows else 'shell'
        if function == 'os.system' or shell.kind == 'bool' and shell.scalar.text == 'True':
            if words[0].kind not in {'str', 'path'}:
                return [self.unresolved(fact, 'unresolved-value', 'Subprocess shell command is unresolved', words[0])]
            if 'stdin_source' in fact.flags:
                warnings.append(self.unresolved(fact, 'execution-content-unavailable', 'Shell subprocess stdin routing is not modeled'))
            return [*warnings, replace(fact, kind='inline', operation=language,
                                       payload=words[0].scalar.text, payload_value=words[0].scalar)]
        if shell.kind != 'bool' or shell.scalar.text != 'False':
            return [self.unresolved(fact, 'unresolved-value', 'Subprocess shell selection is dynamically constructed', shell)]
        argv = tuple(v.scalar if v.kind in {'str', 'path', 'unknown'} else Value(None, 'unsupported_argv_type', v.scalar.variables) for v in words)
        bounded_argv = bounded_arguments(argv, self.limit)
        if argv != bounded_argv:
            warnings.append(self.unresolved(fact, 'unresolved-value', 'Expanded subprocess arguments exceed the byte budget', *bounded_argv))
        effects = []
        for command in candidates(argv[0]):
            if command.text is None:
                effects.append(self.unresolved(fact, 'execution-content-unavailable', 'Subprocess executable is unresolved', words[0]))
            else:
                from ..shared.path_commands import command_basename
                name = command_basename(command.text, 'cmd' if self.paths.windows else 'bash').casefold().removesuffix('.exe')
                if name in {'cmd', 'powershell', 'pwsh'}:
                    from ..shared.windows import WindowsBuilder
                    from ..shared.path_commands import is_command_path
                    command_shell = 'cmd' if self.paths.windows else 'bash'
                    if is_command_path(command.text, command_shell):
                        effects.append(replace(fact, kind='path_invocation', operation='execute', shell=command_shell, values=(command,)))
                    builder = WindowsBuilder(cwd, dict(fact.bindings), shell='cmd' if name == 'cmd' else 'powershell', **self.budgets)
                    builder.interpreter_values(name, list(bounded_argv[1:]), '')
                    effects.extend(replace(child, flags=child.flags | fact.flags, source=fact.source, context=fact.context,
                                           stdin_payload=fact.stdin_payload, stdin_payload_value=fact.stdin_payload_value,
                                           stdin_sources=fact.stdin_sources, python_event=fact.python_event) for child in builder.facts)
                else:
                    effects.append(replace(fact, kind='invoke', operation=command.text,
                                           values=bounded_argv[1:], shell='cmd' if self.paths.windows else 'bash'))
        return [*warnings, *effects]
