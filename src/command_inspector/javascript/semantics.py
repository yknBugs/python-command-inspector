"""Node built-in call events lowered to the shared effect contract.

No modules are imported and no submitted program is executed. Definitions are
inspected separately from visibly called bodies, without ordering their effects.
"""
from dataclasses import replace

from ..models import Fact, Value
from ..paths import PathStyle
from ..shared.value_flow import bounded_arguments, candidates, mark
from .values import JavaScriptValues, JSValue, scalar, unknown


class JavaScriptBuilder:
    def __init__(self, cwd, env, *, source='command', context='invoked_now', paths=None,
                 possible_values=16, control_flow_steps=256, value_bytes=524288, javascript_bindings=()):
        self.cwd, self.env, self.source, self.context = cwd, dict(env), source, context
        self.paths = paths if paths is not None else PathStyle()
        self.budgets = dict(possible_values=possible_values, control_flow_steps=control_flow_steps, value_bytes=value_bytes)
        self.javascript_bindings = javascript_bindings

    def active(self, scope):
        while scope:
            if scope.function is not None:
                return scope.number in self.called
            scope = scope.parent
        return True

    def build(self, root):
        self.values = JavaScriptValues(root, self.cwd, self.env, self.paths, source=self.source,
                                      javascript_bindings=self.javascript_bindings, **self.budgets)
        self.called = set()
        for _ in range(min(len(self.values.scopes), self.budgets["control_flow_steps"])):
            activated = set()
            for call, scope in self.values.calls:
                if not self.active(scope):
                    continue
                target = self.values.evaluate(call.get('function') or call.get('constructor'), scope)
                if target.kind == 'function':
                    activated.update(int(c.text) for c in candidates(target.scalar))
                # Supported asynchronous built-ins may invoke function callbacks.
                name = target.scalar.text or ''
                if name.startswith(('fs.', 'fs/promises.', 'child_process.')) or name in {'setTimeout', 'setInterval', 'setImmediate'} or ((call.get('function') is not None) and call.get('function').kind == 'member_expression' and call.get('function').get('property').text in {'then', 'catch', 'finally'}):
                    args = call.get('arguments')
                    for arg in args.children if args else ():
                        value = self.values.evaluate(arg, scope)
                        if value.kind == 'function':
                            activated.update(int(c.text) for c in candidates(value.scalar))
            if activated <= self.called:
                break
            self.called.update(activated)
        else:
            # If activation cannot converge within the pass budget, no dormant
            # body can be used to certify an unchanged source read.
            self.called.update(scope.number for scope in self.values.scopes if scope.function is not None)
        self.effect_cwd = self.cwd
        if any(self.active(scope) and self.values.evaluate(call.get('function'), scope).scalar.text == 'process.chdir'
               for call, scope in self.values.calls):
            self.effect_cwd = None
            self.values.cwd = None
            self.values.solve()
        from .secrets import secret_facts
        facts = secret_facts(root, self.source, self.context, self.cwd, self.budgets['value_bytes'])
        for group, (call, scope) in enumerate(self.values.calls, 1):
            context = self.context if self.active(scope) or self.context == 'written_content' else 'defined_body'
            fact = Fact('content', 'inspect', flags=frozenset({'possible', 'python_events'}),
                        source=self.source, context=context, cwd=self.effect_cwd,
                        bindings=tuple(self.env.items()), shell='javascript', python_event=(self.source, group))
            target = self.values.evaluate(call.get('function') or call.get('constructor'), scope)
            if target.kind == 'dynamic_function':
                source = self.values.compose((replace(target, kind='str'),), lambda text: text + '\n__dynamic__();')
                facts.append(replace(fact, kind='inline', operation='javascript', payload=source.scalar.text,
                                     payload_value=source.scalar, source=self.source + ':function'))
                continue
            if target.kind == 'unknown':
                function = call.get('function') or call.get('constructor')
                method = function.get('property') if function and function.kind == 'member_expression' else None
                if method and method.text in {'runInThisContext', 'runInContext', 'runInNewContext'}:
                    facts.append(self.unresolved(fact, 'execution-content-unavailable', 'Compiled JavaScript receiver is unresolved', target))
                    facts.append(replace(fact, kind='invalidate', values=(Value(None, 'unknown_compiled_source'),)))
                if method and method.text.removesuffix('Sync') in {'rm', 'unlink', 'rmdir', 'writeFile', 'appendFile', 'rename', 'copyFile', 'readFile', 'open', 'write', 'read', 'truncate'}:
                    facts.append(self.unresolved(fact, 'file-operation-unresolved', 'Filesystem-like method receiver is unresolved', target))
                    if method.text.removesuffix('Sync') not in {'readFile', 'read'}:
                        facts.append(replace(fact, kind='invalidate', values=(Value(None, 'unknown_receiver'),)))
            names = candidates(target.scalar) if target.kind == 'callable' else ()
            for case, name in enumerate(names):
                facts.extend(mark(self.effects(call, name.text, scope, fact), (), group if len(names) > 1 else None, case))
        return tuple(facts)

    @staticmethod
    def unresolved(fact, rule, title, *values):
        return replace(fact, kind='unresolved', operation=rule, payload=title,
                       values=tuple(v.scalar if isinstance(v, JSValue) else v for v in values))

    def filesystem(self, fact, kind, operation, value, *, payload=None, payload_value=None, flags=()):
        path = value.scalar if value.kind in {'str', 'unknown'} else Value(None, 'unsupported_path_type', value.scalar.variables)
        resolved = self.paths.resolve(path, fact.cwd)
        return replace(fact, kind=kind, operation=operation, targets=(resolved,) if resolved is not None else (),
                       values=(path,), payload=payload, payload_value=payload_value, flags=fact.flags | frozenset(flags))

    @staticmethod
    def option(options, name, default):
        if options.kind == 'object':
            return dict(options.items).get(name, default)
        return unknown('unresolved_options')

    def effects(self, node, name, scope, fact):
        argsnode = node.get('arguments')
        args = [self.values.evaluate(c, scope) for c in argsnode.children] if argsnode else []
        path = args[0] if args else unknown('missing_argument')
        if name is None:
            return [self.unresolved(fact, 'execution-content-unavailable', 'Call target is unresolved')]
        if name.startswith('child_process.'):
            return self.subprocess(name.split('.')[-1], args, fact)
        if name == 'process.kill':
            signal = args[1] if len(args) > 1 else scalar('SIGTERM')
            if signal.scalar.text in {'0', 'SIGSTOP', 'SIGCONT', 'SIGTSTP', 'SIGTTIN', 'SIGTTOU'}:
                return []
            return [replace(fact, kind='system', operation='force-process-termination',
                            targets=(path.scalar.text or 'unresolved',),
                            payload='force' if signal.scalar.text in {'9', 'SIGKILL'} else 'terminate')]
        if name in {'fetch', 'http.request', 'https.request', 'http.get', 'https.get'}:
            options = args[1] if len(args) > 1 else JSValue('object')
            if path.kind == 'object':
                options, path = path, unknown('url_options_unresolved')
            flags = set()
            body = self.option(options, 'body', unknown('no_body'))
            headers = self.option(options, 'headers', JSValue('object'))
            if headers.kind == 'object' and any(key.casefold() in {'authorization', 'proxy-authorization', 'cookie', 'x-api-key'} for key, _ in headers.items):
                flags.add('credential_payload')
            values = (path.scalar,)
            if body.kind == 'file_content':
                flags.update({'local_file_payload', 'file_sources'})
                values = (body.items[0].scalar,)
            effects = [replace(fact, kind='network', operation='request', targets=tuple(c.text for c in candidates(path.scalar) if c.text is not None),
                               values=values, payload=path.scalar.text, flags=fact.flags | flags)]
            if path.kind != 'str' or path.scalar.text is None and not path.scalar.alternatives:
                effects.append(self.unresolved(fact, 'unresolved-value', 'Node network destination is unresolved', path))
            return effects
        if name == 'process.chdir':
            return [self.unresolved(fact, 'unresolved-value', 'Possible process.chdir makes relative operation paths unresolved', path)]
        if name in {'eval', 'Function', 'vm.runInThisContext', 'vm.runInNewContext', 'vm.runInContext', 'vm.compileFunction', 'vm.Script'}:
            source = args[-1] if name == 'Function' and args else path
            if name in {'Function', 'vm.Script', 'vm.compileFunction'} and self.context != 'written_content':
                fact = replace(fact, context='defined_body')
            bindings = self.values.snapshot(scope) if name == 'eval' else ()
            if source.kind == 'file_content':
                return [replace(fact, kind='execute', operation='node', flags=fact.flags | {'stdin_source'},
                                stdin_sources=(source.items[0].scalar,), javascript_bindings=bindings)]
            if source.kind == 'str':
                if name == 'Function':
                    source = replace(self.values.evaluate(node, scope), kind='str')
                    parent = self.values.parents.get(node)
                    if parent and parent.kind == 'call_expression' and parent.get('function') is node:
                        return []  # The visible invocation inspects the body once.
                elif name == 'vm.compileFunction':
                    source = self.values.compose((source,), lambda s: 'function __dynamic__(){\n' + s + '\n}')
                return [replace(fact, kind='inline', operation='javascript', payload=source.scalar.text,
                                payload_value=source.scalar, source=self.source + ':eval', javascript_bindings=bindings)]
            return [self.unresolved(fact, 'execution-content-unavailable', 'Dynamically evaluated JavaScript content is unresolved', source)]
        if not name.startswith(('fs.', 'fs/promises.')):
            return []
        operation = name.split('.')[-1].removesuffix('Sync')
        if operation in {'readFile', 'readdir', 'stat', 'lstat', 'access', 'exists', 'realpath', 'readlink'}:
            return [self.filesystem(fact, 'read', 'ingest' if operation == 'readFile' else 'list', path)]
        if operation in {'unlink', 'rm', 'rmdir'}:
            options = args[1] if len(args) > 1 and args[1].kind != 'function' else JSValue('object')
            recursive = self.option(options, 'recursive', scalar('false', 'bool')) if operation != 'unlink' else scalar('false', 'bool')
            force = self.option(options, 'force', scalar('false', 'bool')) if operation == 'rm' else scalar('false', 'bool')
            flags = {'-r'} if recursive.kind == 'bool' and recursive.scalar.text == 'true' else set()
            if force.kind == 'bool' and force.scalar.text == 'true':
                flags.add('-f')
            if recursive.kind != 'bool' or recursive.scalar.text not in {'true', 'false'}:
                flags.add('recursion_unresolved')
            return [self.filesystem(fact, 'delete', 'remove', path, flags=flags)]
        if operation == 'mkdir':
            return [self.filesystem(fact, 'write', 'create_directory', path)]
        if operation in {'rename', 'copyFile'}:
            destination = args[1] if len(args) > 1 else unknown('missing_argument')
            return [self.filesystem(fact, 'read', 'list', path),
                    replace(self.filesystem(fact, 'transfer', 'move' if operation == 'rename' else 'copy', destination, flags={'-T'}), transfer_sources=(path.scalar,))]
        if operation in {'writeFile', 'appendFile'}:
            data = args[1] if len(args) > 1 else unknown('missing_argument')
            options = args[2] if len(args) > 2 and args[2].kind != 'function' else JSValue('object')
            encoding = options if options.kind == 'str' else self.option(options, 'encoding', scalar('utf8'))
            mode = scalar('a' if operation == 'appendFile' else 'w') if options.kind == 'str' else self.option(options, 'flag', scalar('a' if operation == 'appendFile' else 'w'))
            if mode.scalar.text not in {'w', 'w+', 'wx', 'wx+', 'a', 'a+', 'ax', 'ax+', 'r+'}:
                return [self.filesystem(fact, 'invalidate', 'unknown_write_mode', path),
                        self.unresolved(fact, 'file-operation-unresolved', 'Node file write flags are unresolved', path, mode)]
            effect = 'append' if mode.scalar.text.startswith('a') else 'transform' if mode.scalar.text == 'r+' else 'overwrite'
            flags = {'create_if_missing'} if 'x' in mode.scalar.text else set()
            literal = data.kind == 'str' and encoding.scalar.text in {'utf8', 'utf-8'} and effect != 'transform'
            return [self.filesystem(fact, 'write', effect, path, payload=data.scalar.text if literal else None,
                                    payload_value=data.scalar if literal else None, flags=flags)]
        if operation == 'truncate':
            empty = len(args) < 2 or args[1].scalar.text == '0'
            return [self.filesystem(fact, 'write', 'overwrite' if empty else 'transform', path, payload='' if empty else None)]
        if operation == 'chmod':
            effects = [self.filesystem(fact, 'write', 'transform', path)]
            mode = args[1] if len(args) > 1 else unknown('missing_argument')
            if mode.kind == 'number' and mode.scalar.text == '511' or mode.kind == 'str' and mode.scalar.text == '777':
                effects.append(replace(effects[0], kind='permissions', operation='777'))
            elif mode.kind not in {'str', 'number'} or mode.scalar.text is None:
                effects.append(self.unresolved(fact, 'file-operation-unresolved', 'Node permission mode is unresolved', mode))
            return effects
        if operation == 'cp':
            destination = args[1] if len(args) > 1 else unknown('missing_argument')
            return [self.filesystem(fact, 'read', 'list', path), self.filesystem(fact, 'write', 'transform', destination),
                    self.unresolved(fact, 'file-operation-unresolved', 'Node recursive copy contents and filters are not enumerated', path, destination)]
        if operation in {'chown', 'utimes', 'link', 'symlink', 'cp', 'open', 'createWriteStream', 'createReadStream', 'write', 'writev', 'read', 'readv', 'ftruncate', 'fchmod', 'fchown'}:
            # Handles, copy trees, links and metadata mutations need their own
            # operand/mode models. Never borrow unchanged source evidence.
            return [self.filesystem(fact, 'invalidate', 'unmodeled_node_file_operation', path),
                    self.unresolved(fact, 'file-operation-unresolved', 'Node filesystem operation is not fully modeled', path)]
        return [self.unresolved(fact, 'file-operation-unresolved', 'Node filesystem method is not modeled', path)]

    def subprocess(self, name, args, fact):
        if name not in {'exec', 'execSync', 'execFile', 'execFileSync', 'spawn', 'spawnSync', 'fork'}:
            return [self.unresolved(fact, 'execution-content-unavailable', 'Node subprocess method is not modeled')]
        command = args[0] if args else unknown('missing_argument')
        shell_command = name in {'exec', 'execSync'}
        argv = JSValue('array')
        remaining = args[1:]
        if not shell_command and remaining and remaining[0].kind == 'array':
            argv, remaining = remaining[0], remaining[1:]
        elif not shell_command and remaining and remaining[0].kind not in {'object', 'function'}:
            return [self.unresolved(fact, 'execution-content-unavailable', 'Node subprocess argv is unresolved', remaining[0])]
        options = remaining[0] if remaining and remaining[0].kind != 'function' else JSValue('object')
        if options.kind != 'object':
            return [self.unresolved(fact, 'execution-content-unavailable', 'Node subprocess options are unresolved', options)]
        opts = dict(options.items)
        cwd = self.paths.resolve(opts['cwd'].scalar, self.effect_cwd) if 'cwd' in opts else self.effect_cwd
        fact = replace(fact, cwd=cwd, source=self.source + ':subprocess')
        notices = []
        if 'env' in opts:
            env = opts['env']
            if env.kind == 'object' and all(v.kind == 'str' for _, v in env.items):
                fact = replace(fact, bindings=tuple((k, v.scalar) for k, v in env.items))
            else:
                fact = replace(fact, bindings=())
                notices.append(self.unresolved(fact, 'unresolved-value', 'Node subprocess environment is unresolved'))
        if 'input' in opts:
            source = opts['input']
            fact = replace(fact, flags=fact.flags | {'stdin_source'})
            if source.kind == 'str':
                fact = replace(fact, stdin_payload=source.scalar.text, stdin_payload_value=source.scalar)
            elif source.kind == 'file_content':
                fact = replace(fact, stdin_sources=(source.items[0].scalar,))
            else:
                notices.append(self.unresolved(fact, 'execution-content-unavailable', 'Node subprocess stdin is unresolved'))
        shell = opts.get('shell', scalar('true' if shell_command else 'false', 'bool'))
        if shell.scalar.text not in {'true', 'false'} or shell.kind != 'bool':
            return [*notices, self.unresolved(fact, 'execution-content-unavailable', 'Custom or dynamic subprocess shell is unresolved', shell)]
        if shell_command or shell.scalar.text == 'true':
            source = self.values.compose((command, *argv.items), lambda *parts: ' '.join(parts))
            return [*notices, replace(fact, kind='inline', operation='cmd' if self.paths.windows else 'shell',
                                      payload=source.scalar.text, payload_value=source.scalar)]
        if name == 'fork':
            if 'execPath' in opts or 'execArgv' in opts:
                return [*notices, self.unresolved(fact, 'execution-content-unavailable', 'Custom Node fork launcher options are unresolved')]
            return [*notices, replace(fact, kind='execute', operation='node', values=(command.scalar,))]
        values = bounded_arguments(tuple(v.scalar if v.kind in {'str', 'unknown'} else Value(None, 'unsupported_argv_type') for v in argv.items), self.values.limit)
        for candidate in candidates(command.scalar):
            if command.kind != 'str' or candidate.text is None:
                notices.append(self.unresolved(fact, 'execution-content-unavailable', 'Node subprocess executable is unresolved', command))
            else:
                from ..shared.path_commands import command_basename, is_command_path
                shell_profile = 'cmd' if self.paths.windows else 'bash'
                executable = command_basename(candidate.text, shell_profile).casefold().removesuffix('.exe')
                if executable in {'cmd', 'powershell', 'pwsh'}:
                    from ..shared.windows import WindowsBuilder
                    if is_command_path(candidate.text, shell_profile):
                        notices.append(replace(fact, kind='path_invocation', operation='execute', shell=shell_profile, values=(candidate,)))
                    builder = WindowsBuilder(cwd, dict(fact.bindings), shell='cmd' if executable == 'cmd' else 'powershell', **self.budgets)
                    builder.interpreter_values(executable, list(values), '')
                    notices.extend(replace(child, flags=child.flags | fact.flags, source=fact.source, context=fact.context,
                                           stdin_payload=fact.stdin_payload, stdin_payload_value=fact.stdin_payload_value,
                                           stdin_sources=fact.stdin_sources, python_event=fact.python_event) for child in builder.facts)
                else:
                    notices.append(replace(fact, kind='invoke', operation=candidate.text, values=values, shell=shell_profile))
        return notices
