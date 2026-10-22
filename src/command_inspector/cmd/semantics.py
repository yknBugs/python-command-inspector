"""CMD command tails and builtin operand models; backslash is never an escape."""
import re
from dataclasses import replace
from ..shared.builtins import supports_native_command
from ..shared.commands import describe, route_file_payload
from ..shared.streams import attach_execution_input, file_stream_sources, execution_consumer
from ..models import Value, SyntaxNode
from ..admin.windows import describe_admin
from ..sql.clients import SQL_CLIENTS, attach_sql_input, sql_file_input
from ..shared.windows import WindowsBuilder
from ..shared.value_flow import value as abstract_value, join, join_maps, choices, evaluate, mark, bounded, compose, bounded_arguments
from ..shared.path_commands import is_command_path, is_source_path, command_basename

CMD_MODELED_COMMANDS = {"set", "setlocal", "endlocal", "if", "for", "do", "call", "goto", "cd", "chdir",
    "rd", "rmdir", "del", "erase", "type", "dir", "mkdir", "md", "exit", "echo", "ver", "cls", "title", "pause",
    "copy", "move", "ren", "rename", "taskkill", "shutdown", "sc", "schtasks", "setx", "cmd", "powershell", "pwsh"}


class CmdBuilder(WindowsBuilder):
    def __init__(self, cwd, env, **kwargs):
        super().__init__(cwd, env, shell="cmd", **kwargs)
        self.percent_env = dict(self.env)
        self.percent_env["cd"] = cwd
        self.local_scopes = []
        self.scopes_unresolved = False
        self.delayed = None  # Unknown caller profile until explicitly selected.
        self.halted = False
        self.for_pending = False
        self.loop_variables = {}

    def profile(self):
        return (self.delayed, [(dict(env), delayed) for env, delayed in self.local_scopes],
                self.scopes_unresolved, self.halted)

    def restore_profile(self, profile):
        self.delayed, frames, self.scopes_unresolved, self.halted = profile
        self.local_scopes = [(dict(env), delayed) for env, delayed in frames]

    def merge_profiles(self, profiles, guard=""):
        self.delayed = profiles[0][0] if all(p[0] == profiles[0][0] for p in profiles) else None
        self.halted = all(p[3] for p in profiles)
        self.scopes_unresolved = any(p[2] for p in profiles)
        if all(len(p[1]) == len(profiles[0][1]) for p in profiles):
            self.local_scopes = []
            for index in range(len(profiles[0][1])):
                frames = [p[1][index] for p in profiles]
                env = join_maps([frame[0] for frame in frames], self.limit, strings=True)
                delayed = frames[0][1] if all(frame[1] == frames[0][1] for frame in frames) else None
                self.local_scopes.append((env, delayed))
        else:
            self.local_scopes = []
            self.scopes_unresolved = True
            self.delayed = None
            self.env = {name: Value(None, "conditional_scope", (name,)) for name in self.env}
            self.unresolved("CMD local scope depth depends on control flow", guard=guard)

    def reference_bindings(self):
        return self.percent_env | {"!" + k: v for k, v in self.env.items()} | {"%" + k: v for k, v in self.loop_variables.items()}

    @staticmethod
    def mark_choices(facts, metadata, group, case):
        # Expansion namespaces stay internal; reports use plain variable names.
        values = {}
        for key, items in metadata:
            name = key.lstrip("!%")
            values[name] = tuple(dict.fromkeys((*values.get(name, ()), *items)))
        return mark(facts, tuple(values.items()), group, case)

    @staticmethod
    def references(text):
        pattern = r"%%?([A-Za-z])(?![A-Za-z0-9_]*%)"
        loops = ["%" + m[1] for m in re.finditer(pattern, text)]
        remaining = re.sub(pattern, "", text)
        return loops + [m[1].casefold() for m in re.finditer(r"%([^%]+)%", remaining)] + ["!" + m[1].casefold() for m in re.finditer(r"!([^!]+)!", text)]

    def select(self, row):
        for key, v in row.items():
            binding = v.text if v.text is not None else v
            if key.startswith("!"):
                self.env[key[1:]] = binding
            elif key.startswith("%"):
                self.loop_variables[key[1:]] = binding
            else:
                self.percent_env[key] = binding

    def value(self, node, *, quotes=True):
        rows, _ = choices(self.reference_bindings(), self.references(node.text), self.limit)
        if not rows:
            return bounded(self._value(node, quotes=quotes), self.limit)
        before = dict(self.env), dict(self.percent_env), dict(self.loop_variables)
        results = []
        try:
            for row in rows:
                self.env, self.percent_env, self.loop_variables = map(dict, before)
                self.select(row)
                results.append(self._value(node, quotes=quotes))
        finally:
            self.env, self.percent_env, self.loop_variables = before
        return join(results, self.limit)

    def _value(self, node, *, quotes=True):
        text = node.text
        rendered, quoted, i = [], False, 0
        while i < len(text):
            char = text[i]
            if char == "^" and not quoted and i + 1 < len(text):
                rendered.append(text[i + 1])
                i += 2
                continue
            if char == '"':
                quoted = not quoted
                if not quotes:
                    rendered.append(char)
            else:
                rendered.append(char)
            i += 1
        text = "".join(rendered)
        missing, variables, reasons = [], [], []
        replacement_bytes = 0
        def replacement(binding, name):
            nonlocal replacement_bytes
            binding = bounded(abstract_value(binding), self.limit)
            if binding.text is None:
                missing.append(name)
                reasons.append(binding.reason)
                return ""
            replacement_bytes += len(binding.text.encode("utf-8", errors="surrogatepass"))
            if replacement_bytes > self.limit.bytes:
                missing.append(name)
                reasons.append("value_bytes_limit")
                return ""
            return binding.text
        def expand(match):
            name = match[1].casefold()
            variables.append(name)
            if name not in self.percent_env:
                missing.append(name)
            return replacement(self.percent_env.get(name), name)
        def loop_expand(match):
            name = match[1]
            variables.append(name)
            return replacement(self.loop_variables.get(name), name)
        # Batch %%n and interactive %n are distinct from environment %NAME%.
        text = re.sub(r"%%?([A-Za-z])(?![A-Za-z0-9_]*%)", loop_expand, text)
        text = re.sub(r"%([^%]+)%", expand, text)
        if missing or "%" in text:
            return Value(None, next((r for r in reasons if r), "missing_or_batch_variable"), tuple(variables))
        if "!" in text:
            if self.delayed is None:
                variables.extend(match[1].casefold() for match in re.finditer(r"!([^!]+)!", text))
                return Value(None, "delayed_expansion_unsupported", tuple(variables))
            if self.delayed:
                def delayed_expand(match):
                    name = match[1].casefold()
                    variables.append(name)
                    if name not in self.env:
                        missing.append(name)
                    return replacement(self.env.get(name), name)
                text = re.sub(r"!([^!]+)!", delayed_expand, text)
                if missing or "!" in text:
                    return Value(None, next((r for r in reasons if r), "unresolved_delayed_expansion"), tuple(variables))
        return Value(text, variables=tuple(variables))

    def build(self, root, *, grouped=False, guard=""):
        children = root.children
        pending_cd, stack, i = None, [], 0
        conditional_cwd = False
        pipeline_start, piped = 0, False
        previous_output, previous_files, previous_sql_files = None, None, None
        while i < len(children) and not self.halted:
            node = children[i]
            if node.kind == "operator":
                if node.text != "|":
                    pipeline_start, piped = len(self.facts), False
                    previous_output, previous_files, previous_sql_files = None, None, None
                else:
                    piped = True
                if node.text == "\n":
                    if pending_cd is not None or conditional_cwd:
                        self.cwd = None
                        pending_cd = None
                        conditional_cwd = False
                    if not stack and not grouped:  # A parenthesized block expands % variables once.
                        self.percent_env = dict(self.env)
                        if self.cwd:
                            self.percent_env["cd"] = self.cwd
                    guard = ""
                    if pending_cd is not None:
                        self.cwd = None
                        pending_cd = None
                elif node.text == "&&":
                    guard = "if the preceding command succeeds"
                    if pending_cd is not None:
                        self.cwd = pending_cd
                        conditional_cwd = True
                        pending_cd = None
                elif node.text in {"&", "||"}:
                    guard = "if the preceding command fails" if node.text == "||" else ""
                    if pending_cd is not None or conditional_cwd:
                        self.cwd = None
                        pending_cd = None
                        conditional_cwd = False
                elif node.text == "(":
                    stack.append(self.cwd)
                    self.unresolved("Grouped CMD expansion is only partially modeled", guard=guard)
                elif node.text == ")":
                    if stack:
                        before = stack.pop()
                        if before != self.cwd:
                            self.cwd = None
                    else:
                        self.unresolved("Unmatched CMD group", guard=guard)
                elif node.text == "|":
                    self.unresolved("CMD pipeline selection is conservative", "unresolved-value", guard)
                else:
                    self.unresolved("Unsupported CMD operator", guard=guard)
                i += 1
                continue
            structured_end = self.structured_control(children, i, guard)
            if structured_end is not None:
                i = structured_end
                continue
            pipeline_end = self.pipeline_choices(children, i, guard)
            if pipeline_end is not None:
                i = pipeline_end
                continue
            start = len(self.facts)
            conditional_env = dict(self.env) if "preceding command" in guard else None
            conditional_profile = self.profile() if conditional_env is not None else None
            words = [c for c in node.children if c.kind == "word"]
            redirections = [c for c in node.children if c.kind == "redirection"]
            if words:
                if self.for_pending and stack:
                    # The IN list is data. Never enumerate it or treat its words
                    # as executable commands; FOR variables remain unresolved.
                    if isinstance(self.for_pending, dict):
                        items = [self.value(w) for w in words]
                        self.for_pending["items"].extend(items)
                        if any(v.text is None or any(c in v.text for c in "*?") for v in items):
                            self.for_pending["literal"] = False
                    pending_cd = None
                else:
                    pending_cd = self.command(node, words, guard)
            if conditional_env is not None:
                self.env = join_maps([conditional_env, self.env], self.limit, strings=True)
                self.merge_profiles([conditional_profile, self.profile()], guard)
            routes = {1: "caller", 2: "caller"}
            stdin_values = None
            for redirect in redirections:
                operator = next(c.text for c in redirect.children if c.kind == "operator")
                descriptor = int(next((c.text for c in redirect.children if c.kind == "file_descriptor"), "0" if operator in {"<", "<&"} else "1"))
                target = next((c for c in redirect.children if c.kind == "word"), None)
                if target is None:
                    self.unresolved("Missing redirection target", guard=guard)
                    continue
                value = self.value(target)
                if descriptor == 0 and operator in {"<", "<&"}:
                    stdin_values = (value,) if operator == "<" and (value.text is None or value.text.casefold() not in {"nul", "nul:"}) else ()
                if operator in {">&", "<&"}:
                    if operator == ">&":
                        routes[descriptor] = routes.get(int(value.text), "unknown") if value.text and value.text.isdigit() else "discard" if value.text == "-" else "unknown"
                    continue
                null = value.text is not None and value.text.casefold() in {"nul", "nul:"}
                if operator != "<":
                    routes[descriptor] = "discard" if null else "file"
                if null:
                    continue
                payload_values = {str(i): self.value(w, quotes=False) for i, w in enumerate(words[1:])}
                output_value = evaluate(payload_values, payload_values,
                    lambda row: compose(row.values(), separator=" ", suffix="\r\n", limit=self.limit), self.limit)
                echo_output = bool(words and words[0].text.lstrip("@").casefold() == "echo" and descriptor == 1)
                output = output_value.text if echo_output else None
                self.filesystem("read" if operator == "<" else "write", "ingest" if operator == "<" else "append" if operator == ">>" else "overwrite", (value,), payload=output, guard=guard)
                if echo_output and output_value.alternatives:
                    names = tuple(sorted({n for v in payload_values.values() for n in v.variables}))
                    self.facts[-1] = replace(self.facts[-1], payload_value=replace(output_value, variables=names))
                if operator == "<" and descriptor != 0:
                    self.facts[-1] = replace(self.facts[-1], flags=self.facts[-1].flags | {"not_stdin"})
            if routes[2] == "discard":
                self.unresolved("CMD error reporting is suppressed", "errors-suppressed", guard)
            if routes[1] in {"discard", "file"}:
                self.facts[start:] = [replace(f, flags=f.flags | {"output_consumed"}) if f.kind in {"read", "invoke"} else f for f in self.facts[start:]]
            route_start = pipeline_start if piped else start
            if stdin_values is not None:
                self.facts[start:] = attach_sql_input(self.facts[start:], values=stdin_values, override=True)
                self.facts[start:] = attach_execution_input(self.facts[start:], values=stdin_values, override=True, guard=guard)
            elif piped:
                self.facts[start:] = attach_sql_input(self.facts[start:], payload=previous_output, values=previous_sql_files)
                self.facts[start:] = attach_execution_input(self.facts[start:], payload=previous_output, values=previous_files, guard=guard)
            if execution_consumer(self.facts[start:]):
                self.facts[route_start:] = [replace(f, flags=f.flags | {"output_consumed"}) if f.kind == "read" else f for f in self.facts[route_start:]]
            routed = self.facts[route_start:]
            sink_index = next((j for j in range(len(routed) - 1, -1, -1)
                               if "stdin_sink" in routed[j].flags), None)
            if sink_index is not None:
                routed = route_file_payload(routed, sink_index, stdin_values)
                if stdin_values is not None:
                    routed[sink_index] = replace(routed[sink_index], flags=routed[sink_index].flags | {"stdin_redirected"})
                self.facts[route_start:] = routed
            name = words[0].text.lstrip("@").casefold() if words else ""
            previous_files = file_stream_sources(self.facts[start:]) if name == "type" else None
            previous_sql_files = sql_file_input(self.facts[start:]) if name == "type" else None
            values = [self.value(w, quotes=False).text for w in words[1:]]
            previous_output = " ".join(values) + "\r\n" if name == "echo" and all(v is not None for v in values) and routes[1] not in {"discard", "file"} else None
            i += 1
        if stack:
            self.unresolved("Unmatched CMD group")
        if pending_cd is not None or conditional_cwd:
            self.cwd = None
        return tuple(self.facts)

    def pipeline_choices(self, children, index, guard):
        end = index + 1
        while end + 1 < len(children) and children[end].kind == "operator" and children[end].text == "|" and children[end + 1].kind == "command":
            end += 2
        if end == index + 1:
            return None
        nodes = children[index:end]
        names = [name for node in nodes for name in self.references(node.text)]
        rows, metadata = choices(self.reference_bindings(), names, self.limit)
        if not rows:
            return None
        before = dict(self.env), dict(self.percent_env), dict(self.loop_variables), self.cwd
        profile = self.profile()
        self.choice_serial += 1
        group = self.choice_serial
        for case, row in enumerate(rows):
            self.env, self.percent_env, self.loop_variables = map(dict, before[:3])
            self.cwd = before[3]
            self.restore_profile(profile)
            self.select(row)
            start = len(self.facts)
            self.build(SyntaxNode("program", nodes[0].span, tuple(nodes)), grouped=True, guard=guard)
            self.facts[start:] = self.mark_choices(self.facts[start:], metadata, group, case)
        self.env, self.percent_env, self.loop_variables, self.cwd = before
        self.restore_profile(profile)
        return end

    @staticmethod
    def group_end(children, start):
        depth = 0
        for index in range(start, len(children)):
            child = children[index]
            if child.kind == "operator" and child.text == "(":
                depth += 1
            elif child.kind == "operator" and child.text == ")":
                depth -= 1
                if depth == 0:
                    return index
        return None

    def structured_control(self, children, index, guard):
        node = children[index]
        if node.kind != "command":
            return None
        words = [c for c in node.children if c.kind == "word"]
        if not words or index + 1 >= len(children) or children[index + 1].text != "(":
            return None
        name = words[0].text.lstrip("@").casefold()
        if name not in {"if", "for"}:
            return None
        end = self.group_end(children, index + 1)
        if end is None:
            return None
        before_env, before_cwd = dict(self.env), self.cwd
        before_percent, before_loop = dict(self.percent_env), dict(self.loop_variables)
        before_profile = self.profile()
        if name == "if":
            # Use the ordinary condition parser to reject unsupported conditions.
            start = len(self.facts)
            self.command(node, words, guard)
            if any(f.operation == "unsupported-syntax" and f.payload == "Unsupported CMD IF condition" for f in self.facts[start:]):
                return None
            arms = [children[index + 2:end]]
            next_index = end + 1
            if next_index + 1 < len(children) and children[next_index].kind == "command" and children[next_index].text.strip().casefold() == "else" and children[next_index + 1].text == "(":
                else_end = self.group_end(children, next_index + 1)
                if else_end is not None:
                    arms.append(children[next_index + 2:else_end])
                    next_index = else_end + 1
            states = [] if len(arms) == 2 else [before_env]
            cwds = [] if len(arms) == 2 else [before_cwd]
            profiles = [] if len(arms) == 2 else [before_profile]
            self.choice_serial += 1
            group = self.choice_serial
            for case, arm in enumerate(arms):
                arm_start = len(self.facts)
                self.env, self.cwd = dict(before_env), before_cwd
                self.restore_profile(before_profile)
                self.percent_env = dict(before_percent)
                self.build(SyntaxNode("program", node.span, tuple(arm)), grouped=True,
                           guard=(guard + "; " if guard else "") + "if the CMD condition holds")
                states.append(dict(self.env))
                profiles.append(self.profile())
                self.facts[arm_start:] = [replace(f, flags=f.flags | {"possible"}) for f in mark(self.facts[arm_start:], (), group, case)]
                cwds.append(self.cwd)
                self.halted = False
            self.env = join_maps(states, self.limit, strings=True)
            self.merge_profiles(profiles, guard)
            self.cwd = cwds[0] if all(c == cwds[0] for c in cwds) else None
            self.percent_env = before_percent
            return next_index
        variable = next((w.text.lstrip("%") for w in words[1:] if re.fullmatch(r"%%?[A-Za-z]", w.text)), "")
        if not variable or end + 1 >= len(children) or children[end + 1].kind != "command":
            return None
        do_node = children[end + 1]
        do_words = [c for c in do_node.children if c.kind == "word"]
        if not do_words or do_words[0].text.casefold() != "do":
            return None
        literal = not any(w.text.startswith("/") for w in words[1:])
        items = [self.value(w) for c in children[index + 2:end] for w in c.children if w.kind == "word"]
        if any(v.text is None or any(char in v.text for char in "*?") for v in items):
            literal = False
        binding = join(items, self.limit, variable) if literal else Value(None, "loop_variable_unresolved", (variable,))
        if len(do_words) > 1:
            body = (replace(do_node, children=tuple(c for c in do_node.children if c is not do_words[0])),)
            next_index = end + 2
        elif end + 2 < len(children) and children[end + 2].text == "(":
            body_end = self.group_end(children, end + 2)
            if body_end is None:
                return None
            body = children[end + 3:body_end]
            next_index = body_end + 1
        else:
            return None
        if binding.text is None and not binding.alternatives:
            self.unresolved("CMD FOR iteration values are unresolved", guard=guard)
        start = len(self.facts)
        for _ in range(self.flow_steps):
            previous = dict(self.env)
            previous_profile = self.profile()
            self.loop_variables[variable] = binding
            self.percent_env = dict(before_percent)
            self.build(SyntaxNode("program", node.span, tuple(body)), grouped=True,
                       guard=(guard + "; " if guard else "") + "if the CMD loop body runs")
            self.env = join_maps([before_env, previous, self.env], self.limit, strings=True)
            self.merge_profiles([before_profile, previous_profile, self.profile()], guard)
            self.halted = before_profile[3]
            if self.env == previous and self.profile() == previous_profile:
                break
        else:
            self.env = {name: Value(None, "control_flow_limit", (name,)) for name in self.env}
            self.cwd = None
            self.unresolved("Loop state exceeds the configured control-flow budget", "unresolved-value", guard)
            widened = dict(self.env)
            self.build(SyntaxNode("program", node.span, tuple(body)), grouped=True, guard="if the CMD loop body runs")
            self.env = join_maps([widened, self.env], self.limit, strings=True)
        self.facts[start:] = list(dict.fromkeys(self.facts[start:]))
        self.percent_env, self.loop_variables = before_percent, before_loop
        if self.cwd != before_cwd:
            self.cwd = None
        return next_index

    def command(self, node, words, guard):
        rows, metadata = choices(self.reference_bindings(), [name for w in words for name in self.references(w.text)], self.limit)
        if rows:
            before = dict(self.env), dict(self.percent_env), dict(self.loop_variables), self.cwd
            states, destinations, profiles = [], [], []
            profile = self.profile()
            self.choice_serial += 1
            group = self.choice_serial
            for case, row in enumerate(rows):
                case_start = len(self.facts)
                self.env, self.percent_env, self.loop_variables = map(dict, before[:3])
                self.cwd = before[3]
                self.restore_profile(profile)
                self.select(row)
                destinations.append(self._command(node, words, guard))
                states.append(dict(self.env))
                profiles.append(self.profile())
                self.facts[case_start:] = self.mark_choices(self.facts[case_start:], metadata, group, case)
            self.env = join_maps(states, self.limit, strings=True)
            self.merge_profiles(profiles, guard)
            self.percent_env, self.loop_variables = before[1:3]
            self.cwd = before[3]
            if all(d == destinations[0] for d in destinations):
                return destinations[0]
            self.cwd = None
            return None
        return self._command(node, words, guard)

    def _command(self, node, words, guard):
        name_value = self.value(words[0])
        name = (name_value.text or "").lstrip("@").casefold()
        invocation_name = name or None
        command_path = name if is_command_path(name, self.shell) else None
        if command_path:
            if is_source_path(command_path):
                dialect = "cmd" if command_path.endswith((".cmd", ".bat")) else "powershell" if command_path.endswith((".ps", ".ps1")) else "artifact"
                self.emit("execute", dialect, values=(Value(name_value.text.lstrip("@")),), flags={"direct_source"} if dialect != "artifact" else (), guard=guard)
                return
            self.emit("path_invocation", "execute", values=(Value(name_value.text.lstrip("@")),), guard=guard)
            name = command_basename(name, self.shell)
        if name.endswith(".exe"):
            name = name[:-4]
        if name in {"npm.cmd", "npx.cmd", "pip.cmd", "pnpm.cmd", "yarn.cmd"}:
            name = name[:-4]
        args = list(bounded_arguments((self.value(w) for w in words[1:]), self.limit))
        if describe_admin(self, name, args, guard):
            return
        if name == "rem" or name.startswith("::"):
            return
        if name in {"cmd", "cmd.exe"}:
            position = next((i for i, v in enumerate(args) if v.text and v.text.casefold() in {"/c", "/k"}), None)
            if position is None:
                self.emit("execute", "cmd", guard=guard)
                return
            unsupported = False
            for value in args[:position]:
                if value.text and value.text.casefold() not in {"/s", "/d", "/q", "/a", "/u", "/v:off", "/e:on"}:
                    self.unresolved(value.text, "unknown-option", guard)
                    unsupported = True
            if unsupported:
                self.emit("execute", "cmd", flags={"unknown_source"}, guard=guard)
                return
            operand = words[position + 2:]
            raw = node.text[operand[0].span.start - node.span.start:operand[-1].span.end - node.span.start] if operand else ""
            if raw.startswith('"') and raw.endswith('"'):
                raw = raw[1:-1]
            # Percent expansion belongs to the launching physical line. Carets
            # inside the quoted /c tail remain for the inner CMD parse.
            missing = False
            variables = []
            expanded_bytes = 0
            def outer_expand(match):
                nonlocal missing, expanded_bytes
                name = match[1].casefold()
                variables.append(name)
                binding = bounded(abstract_value(self.percent_env.get(name)), self.limit)
                if binding.text is None:
                    missing = True
                    return ""
                expanded_bytes += len(binding.text.encode("utf-8", errors="surrogatepass"))
                if expanded_bytes > self.limit.bytes:
                    missing = True
                    return ""
                return binding.text
            raw = re.sub(r"%([^%]+)%", outer_expand, raw)
            self.emit("execute", "cmd", flags={"inline_source"}, payload=None if missing else raw, guard=guard,
                      values=(Value(None, "missing_variable", tuple(variables)),) if missing else ())
            return
        if name in {"powershell", "powershell.exe", "pwsh", "pwsh.exe"}:
            self.interpreter_values(name, args, guard)
            return
        if name == "set":
            raw_tail = " ".join(w.text for w in words[1:]).strip('"')
            if args and (args[0].text or "").casefold() in {"/a", "/p"}:
                keys = re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:[+*/%&|^-]?=|\+\+|--)", raw_tail)
                if not keys:
                    keys = list(self.env)
                for key in keys:
                    self.env[key.casefold()] = Value(None, "runtime_assignment", (key.casefold(),))
                self.unresolved("Arithmetic or prompted CMD assignment is unresolved", guard=guard,
                                values=tuple(Value(None, "runtime_assignment", (key.casefold(),)) for key in keys))
                return
            tail = compose(args, separator=" ", limit=self.limit)
            if tail.text is None:
                if "=" in raw_tail:
                    key = raw_tail.split("=", 1)[0]
                    if key and not any(c in key for c in "%!"):
                        self.env[key.casefold()] = Value(None, tail.reason or "unresolved_assignment", (key.casefold(),))
                    else:
                        self.env = {k: Value(None, "unresolved_assignment", (k,)) for k in self.env}
                self.unresolved("CMD assignment value is unresolved", "unresolved-value", guard, values=(tail,))
                return
            if "=" in tail.text:
                key, binding = tail.text.split("=", 1)
                self.env[key.casefold()] = binding
                if key.casefold() == "path":
                    self.emit("environment", "environment-modified", targets=("PATH",), guard=guard)
            return
        if name == "setlocal":
            self.local_scopes.append((dict(self.env), self.delayed))
            for value in args:
                option = (value.text or "").casefold()
                if option in {"enabledelayedexpansion", "disabledelayedexpansion"}:
                    self.delayed = option == "enabledelayedexpansion"
                elif option not in {"enableextensions"}:
                    self.delayed = None
                    self.unresolved("Unsupported SETLOCAL option", "unknown-option", guard)
            return
        if name == "endlocal":
            if self.local_scopes:
                self.env, self.delayed = self.local_scopes.pop()
            else:
                if self.scopes_unresolved:
                    self.env = {name: Value(None, "conditional_scope", (name,)) for name in self.env}
                    self.delayed = None
                self.unresolved("ENDLOCAL without a known local scope", guard=guard)
            return
        if name == "call" and args and args[0].text and args[0].text.casefold().endswith((".cmd", ".bat")):
            self.emit("execute", "cmd", values=(args[0],), flags={"direct_source"}, guard=guard)
            return
        if name == "if":
            # Evaluate no condition. Locate supported condition syntax and keep
            # the visible body under a guard; conditional state is not definite.
            index = 1
            while index < len(words) and words[index].text.casefold() in {"/i", "not"}:
                index += 1
            if index < len(words) and words[index].text.casefold() in {"exist", "defined", "errorlevel", "cmdextversion"}:
                index += 2
            elif index < len(words) and "==" in words[index].text:
                index += 1
            elif index + 2 < len(words) and words[index + 1].text.casefold() in {"equ", "neq", "lss", "leq", "gtr", "geq"}:
                index += 3
            else:
                self.unresolved("Unsupported CMD IF condition", guard=guard)
                return
            before = dict(self.env)
            previous_cwd, previous_halted = self.cwd, self.halted
            profile = self.profile()
            else_index = next((i for i in range(index, len(words)) if words[i].text.casefold() == "else"), None)
            arms = [words[index:else_index]] if else_index is not None else [words[index:]]
            if else_index is not None:
                arms.append(words[else_index + 1:])
            states, cwds = ([] if else_index is not None else [before]), ([] if else_index is not None else [previous_cwd])
            profiles = [] if else_index is not None else [profile]
            self.choice_serial += 1
            group = self.choice_serial
            for case, arm in enumerate(arms):
                self.env, self.cwd = dict(before), previous_cwd
                self.restore_profile(profile)
                start = len(self.facts)
                if arm:
                    destination = self.command(node, arm, (guard + "; " if guard else "") + "if the CMD condition holds")
                    if destination is not None:
                        self.cwd = None
                states.append(dict(self.env))
                profiles.append(self.profile())
                cwds.append(self.cwd)
                self.facts[start:] = [replace(f, flags=f.flags | {"possible"}) for f in mark(self.facts[start:], (), group, case)]
            self.env = join_maps(states, self.limit, strings=True)
            self.merge_profiles(profiles, guard)
            self.cwd = cwds[0] if all(c == cwds[0] for c in cwds) else None
            self.halted = previous_halted
            return
        if name == "for":
            variable = next((w.text.lstrip("%") for w in words[1:] if re.fullmatch(r"%%?[A-Za-z]", w.text)), "")
            self.for_pending = {"name": variable, "items": [], "literal": not any(w.text.startswith("/") for w in words[1:])}
            self.unresolved("CMD FOR values are not enumerated", guard=guard)
            return
        if name == "do" and self.for_pending:
            pending = self.for_pending
            self.for_pending = False
            if pending["name"]:
                self.loop_variables[pending["name"]] = join(pending["items"], self.limit, pending["name"]) if pending["literal"] else Value(None, "loop_variable_unresolved", (pending["name"],))
            if len(words) > 1:
                before = dict(self.env)
                self.command(node, words[1:], "if the CMD loop body runs")
                self.env = join_maps([before, self.env], self.limit, strings=True)
            return
        if name in {"call", "goto"}:
            self.unresolved("CMD reparse/jump syntax is outside the supported subset", guard=guard)
            return
        if name in {"cd", "chdir"}:
            operands = [v for v in args if not v.text or v.text.casefold() != "/d"]
            value = operands[0] if operands else Value(self.cwd)
            self.filesystem("read", "list", (value,), guard=guard)
            target = self.paths.resolve(value, self.cwd)
            if target and self.cwd and self.paths.windows and not any(v.text and v.text.casefold() == "/d" for v in args):
                if self.paths.module.splitdrive(target)[0].casefold() != self.paths.module.splitdrive(self.cwd)[0].casefold():
                    self.unresolved("Cross-drive CD without /d does not select that drive", "unresolved-value", guard)
                    return None
            # No pending cwd change is needed when success and failure both
            # retain the current directory, including a bare CD query.
            if target and self.cwd and self.paths.key(target) == self.paths.key(self.cwd):
                return None
            return target
        if name in {"rd", "rmdir", "del", "erase", "type", "dir", "mkdir", "md"}:
            allowed = {"/s", "/q", "/f", "/a", "/p"} if name in {"rd", "rmdir", "del", "erase"} else {"/s", "/b", "/a"} if name == "dir" else set()
            flags, operands, malformed, unknown = set(), [], False, False
            for word, value in zip(words[1:], args):
                text = value.text
                if text and text.startswith("/"):
                    if text.casefold() not in allowed:
                        self.unresolved(text, "unknown-option", guard)
                        unknown = True
                    else:
                        flags.add(text.casefold())
                    continue
                # rd is a builtin, not a C-runtime argv consumer. A backslash before
                # an opening quote remains a separate rooted operand. The quoted
                # operand retains its own trailing backslash and source spelling.
                if name in {"rd", "rmdir"} and word.text.startswith('\\"'):
                    operands.append(Value("\\"))
                    operands.append(Value(word.text[2:].rstrip('"')))
                    malformed = True
                else:
                    if text and any(c in text for c in "*?"):
                        value = replace(value, pattern=True)
                    operands.append(value)
            if unknown:
                operands = [Value(None, "unknown_option_binding")]
            if name in {"rd", "rmdir", "del", "erase"}:
                deletion_flags = ({"-r"} if "/s" in flags else set()) | ({"-f"} if flags & {"/q", "/f"} else set())
                if name in {"del", "erase"}:
                    deletion_flags.add("files_only")
                if malformed:
                    deletion_flags.add("literal_backslash_quote")
                self.filesystem("delete", "delete", operands, deletion_flags, guard=guard)
            elif name in {"type", "dir"}:
                self.filesystem("read", "ingest" if name == "type" else "list", operands, guard=guard)
            else:
                self.filesystem("write", "create_directory", operands, guard=guard)
            return
        if name == "exit":
            if not guard:
                self.halted = True
            return
        if name in {"echo", "ver", "cls", "title", "pause"}:
            return
        if name in {"copy", "move", "ren", "rename"}:
            operands, unknown = [], False
            for value in args:
                if value.text and value.text.startswith("/"):
                    if value.text.casefold() not in {"/y", "/-y", "/v", "/b", "/a"}:
                        self.unresolved(value.text, "unknown-option", guard)
                        unknown = True
                else:
                    operands.append(value)
            source, destination = operands if len(operands) == 2 and not unknown else (Value(None), Value(None))
            if source.text and any(c in source.text for c in "*?+"):
                source = replace(source, pattern=True)
            if name in {"ren", "rename"}:
                absolute = self.paths.resolve(source, self.cwd)
                destination = Value(self.paths.module.join(self.paths.module.dirname(absolute), destination.text)) if absolute and destination.text else Value(None)
            self.filesystem("read", "list", (source,), guard=guard)
            self.emit("transfer", "copy" if name == "copy" else "move", values=(destination,),
                      flags={"-T"} if name in {"ren", "rename"} else (), guard=guard)
            self.facts[-1] = replace(self.facts[-1], transfer_sources=(source,))
            return
        if name == "taskkill":
            flags = [v.text.casefold() for v in args if v.text]
            for option in flags:
                if option.startswith("/") and option not in {"/f", "/t", "/pid", "/im"}:
                    self.unresolved(option, "unknown-option", guard)
            index = next((i for i, v in enumerate(flags) if v in {"/pid", "/im"}), None)
            target = flags[index + 1] if index is not None and index + 1 < len(flags) else "unresolved"
            self.emit("system", "force-process-termination", targets=(target,), payload="force" if "/f" in flags else "terminate", guard=guard)
            return
        if name == "shutdown":
            if any(v.text and v.text.casefold() in {"/s", "/r", "/p", "/h"} for v in args):
                self.emit("system", "machine-power-change", guard=guard)
            else:
                self.unresolved("Unsupported shutdown operation", guard=guard)
            return
        if name in {"sc", "schtasks", "setx"}:
            texts = [v.text.casefold() for v in args if v.text]
            if name == "setx":
                self.emit("environment", "environment-modified", targets=(texts[0] if texts else "unresolved",), guard=guard)
            elif name == "sc" and texts and texts[0] in {"create", "start", "config", "stop", "delete", "pause", "continue"} or name == "schtasks" and any(t in {"/create", "/run", "/change", "/delete", "/end"} for t in texts):
                target_index = texts.index("/tn") + 1 if name == "schtasks" and "/tn" in texts else 1
                target = args[target_index].text if target_index < len(args) else "unresolved"
                self.emit("system", "service-change", targets=(target or "unresolved",), payload=name + " " + texts[0], guard=guard)
            elif name == "sc" and texts and texts[0] in {"query", "queryex", "qc", "qdescription"} or name == "schtasks" and "/query" in texts:
                pass
            else:
                self.unresolved("Unsupported service/task operation", guard=guard)
            return
        if name.endswith((".bat", ".cmd")):
            self.emit("execute", "cmd", values=(name_value,), flags={"direct_source"}, guard=guard)
            return
        if supports_native_command(name, self.shell):
            for fact in describe(name, tuple(args), self.cwd, shell=self.shell):
                targets = tuple(p for v in fact.values if (p := self.paths.resolve(v, self.cwd)) is not None) if fact.kind in {"read", "write", "delete"} else fact.targets
                self.facts.append(replace(fact, targets=targets, cwd=self.cwd, source=self.source, context=self.context, guard=guard, shell=self.shell, bindings=tuple(self.env.items())))
                if command_path:
                    self.facts[-1] = replace(self.facts[-1], command_path=command_path,
                                            command_name=invocation_name if fact.operation == "unknown-command" else fact.command_name)
            return
        self.unresolved(name or "Dynamic command name", "unknown-command", guard, command_name=invocation_name,
                        values=(name_value,) if not name else ())
        if command_path:
            self.facts[-1] = replace(self.facts[-1], command_path=command_path)
