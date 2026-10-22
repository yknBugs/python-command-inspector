"""Ordered shallow Bash semantics; no filesystem, imports, or evaluation."""
from dataclasses import dataclass, field, replace
import re
from ..shared.null_devices import is_null_device
from ..paths import PathStyle
from ..shared.streams import attach_execution_input, file_stream_sources, execution_consumer
from ..shared.options import CommandSpec, parse_options, take_wrapper_options
from ..misc.common import SPECS
from ..shared.commands import (INTERPRETERS, NETWORK_SINKS, SUDO_SPEC, credential_like_path,
                               describe, resolve_path, route_file_payload, stdin_network_sink)
from ..sql.clients import attach_sql_input, sql_file_input
from ..models import Fact, SyntaxNode, Value
from ..wildcards import literal_pattern
from ..shared.value_flow import DEFAULT_LIMIT, value as abstract_value, join, join_maps, choices, evaluate, mark, ValueLimits, compose, bounded_arguments

#: Node kinds that can appear as the operator inside a `file_redirect`.
REDIRECT_OPERATORS = {">", ">>", "<", ">&", "<&", "&>", "&>>", ">|", "<>"}
READ_SPEC = CommandSpec("rse", takes_value=("-a", "-d", "-i", "-n", "-N", "-p", "-t", "-u"))


def word_variables(node: SyntaxNode) -> tuple[str, ...]:
    """Variable references retained as metadata when expansion is unsupported."""
    names, pending = set(), [node]
    arithmetic = node.kind == "arithmetic_expansion"
    while pending:
        current = pending.pop()
        if current.kind in {"simple_expansion", "expansion"}:
            text = current.text[1:] if current.kind == "simple_expansion" else current.text[2:-1]
            match = re.match(r"[!#]?([A-Za-z_][A-Za-z0-9_]*)", text)
            if match:
                names.add(match[1])
        elif arithmetic and current.kind == "variable_name":
            names.add(current.text)
        pending.extend(current.children)
    return tuple(sorted(names))


def resolve_word(node: SyntaxNode, env: dict[str, Value], quoted=False, limit=DEFAULT_LIMIT) -> Value:
    return evaluate(env, word_variables(node), lambda bindings: _resolve_word(node, bindings, quoted, limit), limit)


def _resolve_word(node, env, quoted, limit):
    kind, text = node.kind, node.text
    if kind == "raw_string":
        return Value(text[1:-1])
    if kind in {"simple_expansion", "expansion"}:
        name = text[1:] if kind == "simple_expansion" else text[2:-1]
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            return Value(None, "unsupported_parameter_expansion", word_variables(node))
        value = env.get(name, Value(None, "missing_variable", (name,)))
        if not quoted and value.text and any(c.isspace() for c in value.text):
            return Value(None, "unquoted_split_or_glob", (name,))
        pattern = not quoted and value.text is not None and any(c in value.text for c in "*?[")
        return Value(value.text, value.reason, (name,), pattern, value.text if pattern else None)
    if kind in {"command_substitution", "arithmetic_expansion", "process_substitution", "ansi_c_string"}:
        return Value(None, "runtime_or_unsupported_expansion", word_variables(node))
    if kind in {"string", "concatenation", "command_name"}:
        parts = []
        cursor = node.span.start
        for child in node.children:
            if kind == "string" and child.span.start > cursor:
                # The Bash grammar omits literal newline extras from string
                # children. They still belong to the quoted argument, including
                # Python indentation and leading/trailing line breaks.
                gap = text[cursor - node.span.start:child.span.start - node.span.start]
                if not gap.isspace():
                    return Value(None, "unsupported_string_gap", word_variables(node))
                parts.append(Value(gap))
            if child.kind not in {'"', "'"}:
                parts.append(resolve_word(child, env, quoted or kind == "string", limit))
            cursor = child.span.end
        variables = tuple(dict.fromkeys(v for part in parts for v in part.variables))
        concrete = all(p.text is not None for p in parts)
        pattern = any(p.pattern for p in parts)
        composed = compose(parts, limit=limit)
        return Value(composed.text, composed.reason, variables, pattern if composed.text is not None else False,
                     "".join(p.pattern_text or (p.text if p.pattern else literal_pattern(p.text))
                             for p in parts) if composed.text is not None and pattern else None)
    if kind in {"word", "string_content", "number", "variable_name"}:
        # Bash only treats backslash specially before selected characters inside quotes.
        if kind == "string_content":
            return Value(re.sub(r'\\([\$`"\\\n])', lambda m: "" if m[1] == "\n" else m[1], text))
        pattern = not quoted and bool(re.search(r"(?<!\\)[*?\[]", text))
        spelling = re.sub(r"\\(.)", lambda m: literal_pattern(m[1]), text) if pattern else None
        return Value(re.sub(r"\\(.)", r"\1", text), pattern=pattern, pattern_text=spelling)
    return Value(None, "unsupported_word")


@dataclass
class State:
    cwd: str | None
    env: dict[str, Value]
    exported: set[str] = field(default_factory=set)
    readonly: set[str] = field(default_factory=set)
    terminated: bool = False
    possibly_readonly: set[str] = field(default_factory=set)

    def copy(self):
        return State(self.cwd, dict(self.env), set(self.exported), set(self.readonly), self.terminated, set(self.possibly_readonly))


class SemanticBuilder:
    def __init__(self, cwd: str | None, env: dict[str, str], *, source="command", context="invoked_now", possible_values=DEFAULT_LIMIT, control_flow_steps=256, value_bytes=524288):
        # The caller supplies an environment, so every supplied name is exported.
        self.limit = ValueLimits(possible_values, value_bytes)
        self.flow_steps = control_flow_steps
        self.choice_serial = 0
        self.state = State(cwd, {k: abstract_value(v) for k, v in env.items()}, set(env))
        self.facts: list[Fact] = []
        self.source = source
        self.context = context
        self.stdout_destination = "caller_stdout"

    def emit(self, fact: Fact, guard=""):
        if fact.kind in {"read", "invoke"}:
            route = self.stdout_destination
            flag = "output_consumed" if route in {"file", "discard"} else "output_to_pipe" if route == "pipe" else "output_to_caller"
            fact = replace(fact, flags=fact.flags | {flag})
        self.facts.append(replace(fact, source=self.source, context=self.context, guard=guard or fact.guard, cwd=self.state.cwd,
                                  bindings=tuple((k, v.text if v.text is not None else v) for k, v in self.state.env.items() if v.text is not None or v.alternatives)))

    def build(self, root: SyntaxNode) -> tuple[Fact, ...]:
        self.walk(root)
        return tuple(self.facts)

    def walk(self, node: SyntaxNode, guard="", cd_success=False):
        if node.kind in {"command", "redirected_statement", "pipeline", "declaration_command"}:
            rows, metadata = choices(self.state.env, word_variables(node), self.limit)
            if rows:
                before, states = self.state.copy(), []
                self.choice_serial += 1
                group = self.choice_serial
                for case, row in enumerate(rows):
                    case_start = len(self.facts)
                    self.state = before.copy()
                    self.state.env.update(row)
                    self._walk(node, guard, cd_success)
                    states.append(self.state.copy())
                    self.facts[case_start:] = mark(self.facts[case_start:], metadata, group, case)
                self.state = before.copy()
                # Bindings that the command did not mutate retain their whole set.
                for name in set().union(*(state.env.keys() for state in states)):
                    if any(state.env.get(name) != (before.env | row).get(name) for state, row in zip(states, rows)):
                        self.state.env[name] = join((state.env.get(name) for state in states), self.limit, name)
                self.state.cwd = states[0].cwd if all(state.cwd == states[0].cwd for state in states) else None
                self.state.exported = set.union(*(state.exported for state in states))
                self.state.readonly = set.intersection(*(state.readonly for state in states))
                self.state.possibly_readonly = set.union(*(state.readonly | state.possibly_readonly for state in states)) - self.state.readonly
                self.state.terminated = all(state.terminated for state in states)
                return
        return self._walk(node, guard, cd_success)

    def _walk(self, node: SyntaxNode, guard="", cd_success=False):
        if self.state.terminated:
            return
        kind = node.kind
        if kind == "program":
            for index, child in enumerate(node.children):
                background = index + 1 < len(node.children) and node.children[index + 1].kind == '&'
                before = self.state.copy() if background else None
                self.walk(child, guard)
                if background:
                    self.state = before
        elif kind == "list":
            before = self.state.copy()
            exits = []
            children = node.children
            operator = next((c.text for c in children if c.kind in {"&&", "||"}), "")
            if operator == "||":
                self.emit(Fact("unresolved", "unsupported-syntax", payload="Alternative command branches retain uncertain state"), guard)
            for index, child in enumerate(children):
                if child.kind in {"&&", "||"}:
                    continue
                child_guard = guard if index == 0 else (guard + "; " if guard else "") + ("if the preceding command succeeds" if operator == "&&" else "if the preceding command fails")
                nested_exits = self.walk(child, child_guard, cd_success=operator == "&&")
                if child.kind == "list" and nested_exits:
                    exits.extend(nested_exits)
                exits.append(self.state.copy())
            # Following sequence commands cannot assume a conditional branch ran.
            if not cd_success:
                if before.cwd != self.state.cwd:
                    self.state.cwd = None
                self.state.env = join_maps([state.env for state in exits], self.limit)
                self.state.readonly = set.intersection(*(state.readonly for state in exits))
                self.state.possibly_readonly = set.union(*(state.readonly | state.possibly_readonly for state in exits)) - self.state.readonly
                self.state.exported = set.union(*(state.exported for state in exits))
            return exits
        elif kind in {"subshell", "compound_statement"}:
            before = self.state.copy()
            for index, child in enumerate(node.children):
                background = index + 1 < len(node.children) and node.children[index + 1].kind == '&'
                before_background = self.state.copy() if background else None
                self.walk(child, guard)
                if background:
                    self.state = before_background
            if kind == "subshell":
                self.state = before
        elif kind == "pipeline":
            before = self.state.copy()
            start = len(self.facts)
            destination = self.stdout_destination
            stages = [c for c in node.children if c.kind not in {"|", "|&"}]
            previous_facts = []
            previous_output = None
            for index, child in enumerate(stages):
                self.state = before.copy()
                self.stdout_destination = "pipe" if index < len(stages) - 1 else destination
                stage_start = len(self.facts)
                stage_output = self.literal_output(child)
                self.walk(child, guard)
                if index:
                    prior = stages[index - 1]
                    prior_name = next((c.text for c in prior.children if c.kind == "command_name"), "")
                    values = sql_file_input(previous_facts) if prior.kind == "command" and prior_name == "cat" else None
                    file_values = file_stream_sources(previous_facts) if prior.kind == "command" and prior_name == "cat" else None
                    pipe_payload = previous_output
                    self.facts[stage_start:] = attach_sql_input(self.facts[stage_start:], payload=pipe_payload, values=values, guard=guard)
                    self.facts[stage_start:] = attach_execution_input(self.facts[stage_start:], values=file_values, payload=pipe_payload, guard=guard)
                previous_facts = self.facts[stage_start:]
                previous_output = stage_output
            self.stdout_destination = destination
            self.state = before
            emitted = self.facts[start:]
            sink = next((c for c in reversed(node.children) if c.kind == "command"), None)
            sink_name = next((c.text for c in sink.children if c.kind == "command_name"), "") if sink else ""
            if sink_name in {"wc", "less", "more"} or execution_consumer(previous_facts):
                self.facts[start:] = [replace(f, flags=f.flags | {"output_consumed"}) if f.kind in {"read", "invoke"} and "output_to_pipe" in f.flags else f for f in emitted]
            else:
                self.facts[start:] = [replace(f, flags=f.flags | {"selection_uncertain"}) if f.kind in {"read", "invoke"} else f for f in emitted]
            if sink_name in {"bash", "sh", "zsh"} and any(f.kind == "network" for f in emitted):
                self.facts[start:] = [replace(f, operation="download", flags=f.flags | {"to_interpreter"}) if f.kind == "network" else f for f in self.facts[start:]]
            if sink_name in NETWORK_SINKS or any(f.kind == "invoke" and stdin_network_sink(f) for f in self.facts[start:]):
                routed = self.facts[start:]
                index = next((i for i in range(len(routed) - 1, -1, -1) if stdin_network_sink(routed[i])), None)
                if index is not None:
                    self.facts[start:] = route_file_payload(routed, index)
        elif kind == "variable_assignment":
            self.assignment(node, guard)
        elif kind == "unset_command":
            self.walk_substitutions(node)
            names = [c.text for c in node.children if c.kind == "variable_name"]
            options = [c.text for c in node.children if c.kind == "word" and c.text.startswith("-")]
            if options == ["-f"]:
                return  # Removing functions does not unset ordinary bindings.
            if any(option not in {"-v", "--"} for option in options) or any(c.kind not in {"unset", "variable_name", "word"} for c in node.children):
                self.emit(Fact("unresolved", "unsupported-syntax", payload="Unset binding selection is unresolved"), guard)
                names = [name for name in self.state.env if name not in self.state.readonly]
            for name in names:
                if name in self.state.readonly:
                    self.emit(Fact("assignment", "readonly-assignment-failed", (name,), payload=name), guard)
                    continue
                if name in self.state.possibly_readonly:
                    self.state.env[name] = Value(None, "conditional_readonly", (name,))
                    self.emit(Fact("unresolved", "unresolved-value", values=(self.state.env[name],), payload="Unset may fail for a conditionally readonly binding: " + name), guard)
                    continue
                self.state.env.pop(name, None)
                if name == "PATH" or name in self.state.exported:
                    self.emit(Fact("environment", "environment-modified", (name,)), guard)
                self.state.exported.discard(name)
        elif kind == "declaration_command":
            declaration = node.children[0].text if node.children else ""
            readonly = declaration == "readonly" or any(
                child.kind == "word" and child.text.startswith("-") and "r" in child.text[1:]
                for child in node.children)
            for child in node.children[1:]:
                if child.kind == "variable_assignment":
                    self.assignment(child, guard, exported=declaration == "export", readonly=readonly, fatal=False)
                elif child.kind == "word" and child.text.startswith("-"):
                    continue
                else:
                    self.walk_substitutions(child)
                    name = resolve_word(child, self.state.env, limit=self.limit).text
                    if name is None or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                        self.emit(Fact("unresolved", "unsupported-syntax", payload="Declaration without a modeled assignment"), guard)
                        self.invalidate_loop_variables(set(self.state.env), guard)
                        continue
                    # `export NAME` / `readonly NAME` constrain an existing binding.
                    if declaration == "export":
                        self.state.exported.add(name)
                    if readonly:
                        self.state.readonly.add(name)
        elif kind == "command":
            self.command(node, guard, cd_success)
        elif kind == "test_command":
            if any(c.kind == "((" for c in node.children):
                self.arithmetic_command(node, guard)
            else:
                self.walk_substitutions(node, (guard + "; " if guard else "") + "during command substitution")
                self.invalidate_loop_variables(self.arithmetic_expansion_writes(node), guard)
        elif kind == "negated_command":
            # Negation affects exit status, not the visible command's effects.
            for child in node.children:
                if child.kind != "!":
                    self.walk(child, guard)
        elif kind == "redirected_statement":
            body = next((c for c in node.children if c.kind not in {"file_redirect", "heredoc_redirect"}), None)
            redirects: list[SyntaxNode] = []

            def collect(current):
                if current.kind == "file_redirect":
                    redirects.append(current)
                for child in current.children:
                    collect(child)

            for child in node.children:
                if child.kind in {"file_redirect", "heredoc_redirect"}:
                    collect(child)
            heredoc = next((c for c in node.children if c.kind == "heredoc_redirect"), None)
            # Only a heredoc on fd 0 can supply the interpreter's program. Preserve
            # redirection order: a later stdin redirect replaces that payload.
            heredoc_fd = next((c.text for c in heredoc.children if c.kind == "file_descriptor"), "0") if heredoc else None
            has_stdin_heredoc = heredoc is not None and heredoc_fd == "0"
            overridden = has_stdin_heredoc and any(
                redirect.span.start > heredoc.span.start and
                next((c.kind for c in redirect.children if c.kind in REDIRECT_OPERATORS), "") in {"<", "<>", "<&"} and
                next((c.text for c in redirect.children if c.kind == "file_descriptor"), "0") == "0"
                for redirect in redirects)
            stdin_payload = None
            stdin_variables = ()
            if heredoc:
                start = next((c.text for c in heredoc.children if c.kind == "heredoc_start"), "")
                content = next((c.text for c in heredoc.children if c.kind == "heredoc_body"), "")
                if any(char in start for char in "\"'\\"):
                    stdin_payload = content
                elif "$" not in content and "`" not in content and "\\" not in content:
                    stdin_payload = content
                else:
                    body_node = next((c for c in heredoc.children if c.kind == "heredoc_body"), None)
                    if body_node is not None:
                        self.walk_substitutions(body_node)
                        stdin_variables = word_variables(body_node)
                    self.emit(Fact("unresolved", "unresolved-value", unresolved_variables=stdin_variables,
                                   payload="Here-document content depends on shell expansion"), guard)
            payload = self.literal_output(body) if body else None
            if has_stdin_heredoc and self.stdin_passthrough(body):
                # A here-document is the body's standard input, so it only becomes
                # the *written* content of a redirected file when the body forwards
                # standard input to standard output. `bash <<EOF > out` writes
                # bash's output to `out`, not the here-document.
                payload = None if overridden else stdin_payload
            routes = {1: self.stdout_destination, 2: "caller_stderr"}
            for redirect in redirects:
                children = redirect.children
                operator = next((c.kind for c in children if c.kind in REDIRECT_OPERATORS), "")
                if operator in {">&", "<&"}:
                    descriptor = int(next((c.text for c in children if c.kind == "file_descriptor"), "1" if operator == ">&" else "0"))
                    target = children[-1].text if children else ""
                    if operator == ">&":
                        routes[descriptor] = routes.get(int(target), "unknown") if target.isdigit() else "discard" if target == "-" else "unknown"
                    continue
                target_node = children[-1] if children else None
                if target_node is None:
                    continue
                # `> "$(...)"` contains visible commands; the target itself stays
                # unresolved, but the operations inside it must still be reported.
                self.walk_substitutions(target_node)
                target_value = resolve_word(target_node, self.state.env, limit=self.limit)
                null_target = is_null_device(resolve_path(target_value, self.state.cwd), PathStyle(False))
                descriptor = int(next((c.text for c in children if c.kind == "file_descriptor"), "0" if operator in {"<", "<>"} else "1"))
                if operator not in {"<", "<>"}:
                    routes[descriptor] = "discard" if null_target else "file"
                    if redirect.text.startswith("&>"):
                        routes[2] = routes[1]
                if null_target:
                    continue
                target = resolve_path(target_value, self.state.cwd)
                operation = "ingest" if operator == "<" else "append" if operator in {">>", "&>>"} else "overwrite"
                self.emit(Fact("read" if operator == "<" else "write", operation,
                               (target,) if target else (), (target_value,),
                               flags=frozenset({"not_stdin"}) if operator == "<" and descriptor != 0 else frozenset(), payload=payload,
                               unresolved_variables=word_variables(body) if operator != "<" and payload is None and body else ()), guard)
            if routes[2] == "discard":
                self.emit(Fact("unresolved", "errors-suppressed"), guard)
            if body:
                start = len(self.facts)
                destination = self.stdout_destination
                self.stdout_destination = routes[1]
                self.walk(body, guard, cd_success)
                self.stdout_destination = destination
                # A named stdin file can be published without a pipeline.
                routed = self.facts[start:]
                sink_index = next((i for i in range(len(routed) - 1, -1, -1) if "stdin_sink" in routed[i].flags), None)
                # Only this statement's fd-0 redirects replace incoming data.
                stdin_redirects = [r for r in redirects
                                   if next((c.text for c in r.children if c.kind == "file_descriptor"), "0") == "0"
                                   and any(c.kind in {"<", "<>", "<&"} for c in r.children)]
                sql_facts = self.facts[start:]
                # The grammar can wrap a whole pipeline in the final command's
                # redirect. Use syntax identity, not just the last SQL fact, so
                # input cannot leak to earlier stages or command substitutions.
                sql_body = body
                if body.kind == "pipeline":
                    sql_body = next((c for c in reversed(body.children) if c.kind not in {"|", "|&"}), None)
                while sql_body is not None and sql_body.kind == "redirected_statement":
                    sql_body = next((c for c in sql_body.children if c.kind not in {"file_redirect", "heredoc_redirect"}), None)
                sql_invocation = sql_body.span.start if sql_body is not None and sql_body.kind == "command" else None
                if sql_invocation is not None and stdin_redirects and (not has_stdin_heredoc or overridden):
                    last = stdin_redirects[-1]
                    selected = resolve_word(last.children[-1], self.state.env, limit=self.limit)
                    values = (selected,) if any(c.kind == "<" for c in last.children) else (Value(None),)
                    self.facts[start:] = attach_sql_input(sql_facts, values=values, override=True, guard=guard, invocation=sql_invocation)
                elif sql_invocation is not None and has_stdin_heredoc:
                    self.facts[start:] = attach_sql_input(sql_facts, payload=stdin_payload, override=True, guard=guard, invocation=sql_invocation)
                if stdin_redirects or has_stdin_heredoc:
                    # A redirect on the final pipeline stage replaces its pipe
                    # input, including when the grammar wraps the whole pipeline.
                    selected = resolve_word(stdin_redirects[-1].children[-1], self.state.env, limit=self.limit) if stdin_redirects else None
                    source_values = (selected,) if selected is not None and any(c.kind == "<" for c in stdin_redirects[-1].children) and (not has_stdin_heredoc or overridden) else ()
                    self.facts[start:] = [replace(f, flags=(f.flags - {"pipeline_stdin"}) | {"stdin_source", "stdin_redirected"},
                                                 stdin_payload=None if overridden or not has_stdin_heredoc else stdin_payload,
                                                 stdin_sources=source_values,
                                                 unresolved_variables=tuple(sorted(set(f.unresolved_variables) | set(stdin_variables)))
                                                 if has_stdin_heredoc and not overridden else f.unresolved_variables)
                                          if f.kind in {"execute", "invoke", "credential_input"} and f.guard == guard and
                                          f"stdin_invocation:{sql_invocation}" in f.flags
                                          else f for f in self.facts[start:]]
                    if execution_consumer(self.facts[start:]):
                        selected_targets = {resolve_path(v, self.state.cwd) for v in source_values}
                        self.facts[start:] = [replace(f, flags=f.flags | {"output_consumed"})
                                              if f.kind == "read" and f.operation == "ingest" and set(f.targets) <= selected_targets
                                              else f for f in self.facts[start:]]
                if sink_index is not None and stdin_redirects and (not has_stdin_heredoc or overridden):
                    last = stdin_redirects[-1] if stdin_redirects else None
                    selected = resolve_word(last.children[-1], self.state.env, limit=self.limit)
                    input_values = (selected,) if any(c.kind == "<" for c in last.children) and not is_null_device(resolve_path(selected, self.state.cwd), PathStyle(False)) else ()
                    self.facts[start:] = route_file_payload(routed, sink_index, input_values)
                elif sink_index is not None and has_stdin_heredoc:
                    self.facts[start:] = route_file_payload(routed, sink_index, ())
                if sink_index is not None and (has_stdin_heredoc or stdin_redirects):
                    self.facts[start + sink_index] = replace(self.facts[start + sink_index],
                        flags=self.facts[start + sink_index].flags | {"stdin_redirected"})
        elif kind in {"for_statement", "c_style_for_statement"}:
            self.for_loop(node, guard)
        elif kind == "while_statement":  # The Bash grammar uses this for until too.
            self.while_loop(node, guard)
        elif kind in {"if_statement", "case_statement"}:
            self.branches(node, guard)
        elif kind == "function_definition":
            self.emit(Fact("unresolved", "unsupported-syntax", payload="Control-flow reachability is not fully modeled"), guard)
            before, context = self.state.copy(), self.context
            self.context = "defined_body"
            for child in node.children:
                if child.kind in {"command", "redirected_statement", "compound_statement", "do_group", "list"}:
                    self.walk(child, "if this body runs")
            self.state, self.context = before, context
        elif kind == "do_group":
            for child in node.children:
                self.walk(child, guard)
        elif kind in {"comment", ";", "\n", "(", ")", "{", "}", "if", "then", "fi", "do", "done"}:
            pass
        else:
            self.emit(Fact("unresolved", "unsupported-syntax", payload="Unsupported shell syntax: " + kind), guard)

    def substitutions_in(self, node: SyntaxNode):
        """Yield command and process substitutions anywhere below ``node``."""
        if node.kind in {"command_substitution", "process_substitution"}:
            yield node
            return
        for child in node.children:
            yield from self.substitutions_in(child)

    def branches(self, node, guard):
        """Inspect alternatives independently and conservatively join their state."""
        branch_guard = (guard + "; " if guard else "") + "if this body runs"
        separators = {";", "\n", "if", "then", "fi", "elif", "else", ";;", ";&", ";;&"}
        def walk_items(items, label):
            for child in items:
                if child.kind not in separators:
                    self.walk(child, label)
        if node.kind == "if_statement":
            then = next((i for i, c in enumerate(node.children) if c.kind == "then"), len(node.children))
            walk_items(node.children[1:then], guard)
            entry = self.state.copy()
            body, alternatives = [], []
            for child in node.children[then + 1:]:
                if child.kind in {"elif_clause", "else_clause"}:
                    alternatives.append(child.children)
                else:
                    body.append(child)
            arms = [body, *alternatives]
        else:
            for child in node.children:
                if child.kind == "case_item":
                    break
                self.walk_substitutions(child)
            entry = self.state.copy()
            arms = []
            for item in node.children:
                if item.kind == "case_item":
                    boundary = next((i for i, c in enumerate(item.children) if c.kind == ")"), len(item.children))
                    # Case patterns can contain visible substitutions too.
                    for child in item.children[:boundary]:
                        self.walk_substitutions(child)
                    arms.append(item.children[boundary + 1:])
        exhaustive_case = node.kind == "case_statement" and any(
            item.kind == "case_item" and any(c.kind in {"word", "extglob_pattern"} and c.text == "*" for c in item.children[:next((i for i, c in enumerate(item.children) if c.kind == ")"), 0)])
            for item in node.children)
        states = [] if node.kind == "if_statement" or exhaustive_case else [entry]
        fallthrough = None
        retests = []
        condition_entry = entry
        condition_facts = []
        self.choice_serial += 1
        group = self.choice_serial
        for case, arm in enumerate(arms):
            arm_start = len(self.facts)
            self.state = condition_entry.copy() if node.kind == "if_statement" else entry.copy()
            if arm and arm[0].kind == "elif":
                boundary = next((i for i, c in enumerate(arm) if c.kind == "then"), len(arm))
                walk_items(arm[:boundary], branch_guard)
                condition_facts.extend(self.facts[arm_start:])
                del self.facts[arm_start:]
                condition_entry = self.state.copy()
                arm = arm[boundary + 1:]
            predecessors = [*retests, *([fallthrough] if fallthrough is not None else [])]
            if predecessors:
                incoming = [entry, *(state for _, state in predecessors)]
                for name in set().union(*(state.env.keys() for state in incoming)):
                    self.state.env[name] = join((state.env.get(name) for state in incoming), self.limit, name)
                if any(entry.cwd != state.cwd for state in incoming):
                    self.state.cwd = None
                self.state.readonly = set.intersection(*(state.readonly for state in incoming))
                self.state.exported.update(set().union(*(state.exported for state in incoming)))
                self.state.possibly_readonly.update(set().union(*(state.readonly | state.possibly_readonly for state in incoming)) - self.state.readonly)
            self.facts.extend(condition_facts)
            walk_items(arm, branch_guard)
            if len(self.facts) == arm_start:
                # Keep even effect-free arms in the choice stream so detector
                # fallthrough cannot accidentally inherit a different arm.
                self.emit(Fact("control", "branch-boundary"), branch_guard)
            self.facts[arm_start:] = [replace(f, flags=f.flags | {"possible"},
                choice_predecessors=f.choice_predecessors + ((group, tuple(index for index, _ in predecessors)),))
                for f in mark(self.facts[arm_start:], (), group, case)]
            states.append(self.state)
            fallthrough = None
            if node.kind == "case_statement":
                if any(c.kind == ";;&" for c in arm):
                    # Retesting may skip any number of intervening clauses.
                    retests.append((case, self.state.copy()))
                elif any(c.kind == ";&" for c in arm):
                    fallthrough = (case, self.state.copy())
        if node.kind == "if_statement" and not any(c.kind == "else_clause" for c in node.children):
            states.append(condition_entry)
        self.state = entry.copy()
        self.state.readonly = set.intersection(*(s.readonly for s in states)) if states else set(entry.readonly)
        for name in set().union(*(s.env.keys() for s in states)):
            if any(s.env.get(name) != entry.env.get(name) for s in states):
                self.state.env[name] = join((s.env.get(name) for s in states), self.limit, name)
        if any(s.cwd != entry.cwd for s in states):
            self.state.cwd = None
        self.state.exported.update(set().union(*(s.exported for s in states)))
        self.state.possibly_readonly.update(set().union(*(s.readonly | s.possibly_readonly for s in states)) - self.state.readonly)

    def walk_substitutions(self, node, guard="during command substitution"):
        """Analyze the visible commands inside substitutions below ``node``.

        Their runtime output stays unresolved; only visible effects are collected.
        Quotes and redirection introduce intermediate nodes, so a direct-children
        check missed both ``A="$(...)"`` and ``> "$(...)"`` entirely.
        """
        for substitution in self.substitutions_in(node):
            before = self.state.copy()
            for child in substitution.children:
                if child.kind in {"command", "list", "pipeline", "redirected_statement"}:
                    self.walk(child, guard)
            self.state = before

    def for_loop(self, node, guard):
        """Bind a finite item domain, then inspect an abstract body fixed point."""
        before = self.state.copy()
        notice_start = len(self.facts)
        variable = next((c.text for c in node.children if c.kind == "variable_name"), "")
        body = next((c for c in node.children if c.kind in {"do_group", "compound_statement"}), None)
        variables = {variable} if variable else set()
        for child in node.children:
            if child is not body:
                self.walk_substitutions(child)
                if node.kind == "c_style_for_statement":
                    variables.update(self.arithmetic_writes(child))
        self.invalidate_loop_variables(variables, guard)
        if variable and node.kind == "for_statement" and any(c.kind == "in" for c in node.children):
            items = [resolve_word(c, before.env, limit=self.limit) for c in node.children
                     if c.kind in {"word", "string", "raw_string", "simple_expansion", "expansion", "concatenation"}]
            # A glob selects filesystem entries at runtime, not literal item names.
            if items and not any(candidate.pattern for item in items for candidate in (item.alternatives or (item,))):
                self.state.env[variable] = join(items, self.limit, variable)
        iteration_binding = self.state.env.get(variable)
        if node.kind != "for_statement" or not variable or iteration_binding is None or (iteration_binding.text is None and not iteration_binding.alternatives):
            notice = Fact("unresolved", "unsupported-syntax", payload="Loop iteration counts are not modeled", source=self.source, context=self.context, guard=guard, cwd=self.state.cwd)
            self.facts.insert(notice_start, notice)
        if body:
            seed = self.state.copy()
            iteration_binding = self.state.env.get(variable)
            def pass_body():
                if variable and iteration_binding is not None and node.kind == "for_statement":
                    self.state.env[variable] = iteration_binding
                self.walk(body, (guard + "; " if guard else "") + "if the loop body runs")
            self.fixed_loop(seed, pass_body)
        self.merge_loop_state(before, variables)

    def fixed_loop(self, seed, body):
        start = len(self.facts)
        for _ in range(self.flow_steps):
            previous = self.state.copy()
            self.state.terminated = seed.terminated
            body()
            after = self.state.copy()
            self.state.env = join_maps([seed.env, previous.env, after.env], self.limit)
            self.state.cwd = seed.cwd if seed.cwd == previous.cwd == after.cwd else None
            self.state.terminated = seed.terminated
            if self.state == previous:
                break
        else:
            self.state.env = {name: v if name in self.state.readonly else Value(None, "control_flow_limit", (name,)) for name, v in self.state.env.items()}
            self.state.cwd = None
            self.emit(Fact("unresolved", "unresolved-value", payload="Loop state exceeds the configured control-flow budget"))
            widened = self.state.copy()
            body()
            self.state.env = join_maps([widened.env, self.state.env], self.limit)
        # Fixed-point passes describe the same body, not extra executions.
        self.facts[start:] = list(dict.fromkeys(self.facts[start:]))

    def while_loop(self, node, guard):
        before = self.state.copy()
        self.emit(Fact("unresolved", "unsupported-syntax", payload="Loop iteration counts are not modeled"), guard)
        body = next((c for c in node.children if c.kind == "do_group"), None)
        exits = []
        def pass_body():
            for child in node.children:
                if child is not body and child.kind not in {"while", "until", ";", "\n"}:
                    self.walk(child, (guard + "; " if guard else "") + "when evaluating the loop condition")
            exits.append(self.state.copy())
            if body:
                self.state.terminated = before.terminated
                self.walk(body, (guard + "; " if guard else "") + "if the loop body runs")
        self.fixed_loop(before, pass_body)
        self.state.env = join_maps([self.state.env, *(state.env for state in exits)], self.limit)
        self.merge_loop_state(before)

    def invalidate_loop_variables(self, variables, guard):
        for name in sorted(variables):
            if name in self.state.readonly:
                self.emit(Fact("assignment", "readonly-assignment-failed", (name,), payload=name), guard)
                continue
            self.state.env[name] = Value(None, "loop_variable_unresolved", (name,))
            if name == "PATH":
                self.emit(Fact("environment", "environment-modified", (name,)), guard)

    def merge_loop_state(self, before, variables=()):
        after = self.state
        self.state = before
        for name in before.env.keys() | after.env.keys():
            if (name in variables and name not in before.readonly) or before.env.get(name) != after.env.get(name):
                self.state.env[name] = join((before.env.get(name), after.env.get(name)), self.limit, name)
        self.state.possibly_readonly.update((after.readonly | after.possibly_readonly) - before.readonly)
        if before.cwd != after.cwd:
            self.state.cwd = None

    def arithmetic_writes(self, node):
        """Find syntactic header writes without evaluating arithmetic or output."""
        assignment_operators = {"=", "+=", "-=", "*=", "/=", "%=", "<<=", ">>=", "&=", "^=", "|="}
        names, pending = set(), [node]
        while pending:
            current = pending.pop()
            # Assignments inside command/process substitutions have their own scope.
            if current.kind in {"command_substitution", "process_substitution"}:
                continue
            # In arithmetic tests the vendor grammar may expose i++/--i as
            # a single word instead of a postfix/unary expression.
            if current.kind == "word":
                increment = re.fullmatch(r"(?:\+\+|--)([A-Za-z_][A-Za-z0-9_]*)|([A-Za-z_][A-Za-z0-9_]*)(?:\+\+|--)", current.text)
                if increment:
                    names.add(increment[1] or increment[2])
            target = None
            if current.kind == "variable_assignment":
                target = next((c for c in current.children if c.kind == "variable_name"), None)
            elif current.kind == "binary_expression" and any(c.kind in assignment_operators for c in current.children):
                target = current.children[0] if current.children else None
            elif current.kind in {"postfix_expression", "unary_expression"} and any(c.kind in {"++", "--"} for c in current.children):
                target = next((c for c in current.children if c.kind not in {"++", "--"}), None)
            if target is not None and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", target.text):
                names.add(target.text)
            pending.extend(current.children)
        return names

    def arithmetic_command(self, node, guard):
        self.emit(Fact("unresolved", "unsupported-syntax", payload="Arithmetic expression values are not evaluated"), guard)
        self.walk_substitutions(node, (guard + "; " if guard else "") + "during command substitution")
        self.invalidate_loop_variables(self.arithmetic_writes(node), guard)

    def arithmetic_expansion_writes(self, node):
        names, pending = set(), [node]
        while pending:
            current = pending.pop()
            if current.kind in {"command_substitution", "process_substitution"}:
                continue
            if current.kind == "arithmetic_expansion":
                names.update(self.arithmetic_writes(current))
            else:
                pending.extend(current.children)
        return names

    def read_bindings(self, args, guard):
        """read writes names from runtime input; never consume or enumerate it."""
        operands, _, bound, unknown = parse_options(args, READ_SPEC)
        selected = (bound["-a"],) if "-a" in bound else operands or (Value("REPLY"),)
        names = {v.text for v in selected if v.text is not None and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", v.text)}
        uncertain = bool(unknown) or any(v.text is None or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", v.text) for v in selected)
        if uncertain:
            names.update(k for k in self.state.env if k not in self.state.readonly)
        self.emit(Fact("unresolved", "unsupported-syntax", payload="read input and assignment success are unresolved"), guard)
        for option in unknown:
            self.emit(Fact("unresolved", "unknown-option", payload=option), guard)
        self.invalidate_loop_variables(names, guard)

    def assignment(self, node, guard, exported=False, readonly=False, fatal=True):
        value_node = node.children[-1] if node.children else None
        if value_node is not None and value_node.kind != "=":
            self.walk_substitutions(value_node)
            self.invalidate_loop_variables(self.arithmetic_expansion_writes(value_node), guard)
        name = next((c.text for c in node.children if c.kind == "variable_name"), "")
        if not name:
            return
        value = resolve_word(value_node, self.state.env, quoted=True, limit=self.limit) if value_node is not None and value_node.kind != "=" else Value("")
        if name in self.state.readonly:
            # A read-only binding rejects the write and keeps its previous value.
            self.emit(Fact("assignment", "readonly-assignment-failed", (name,), payload=name), guard)
            self.state.terminated = fatal
            return
        if name in self.state.possibly_readonly:
            if self.state.env.get(name) != value:
                value = join((self.state.env.get(name), value), self.limit, name)
            self.emit(Fact("assignment", "readonly-assignment-failed", (name,), payload=name, flags=frozenset({"possible"})),
                      (guard + "; " if guard else "") + "if the binding is readonly on this path")
        if readonly:
            self.state.readonly.add(name)
            self.state.possibly_readonly.discard(name)
        self.state.env[name] = value
        if exported or name in self.state.exported:
            # Assigning to an already-exported name keeps it exported.
            self.state.exported.add(name)
        if name == "PATH" or exported:
            self.emit(Fact("environment", "environment-modified", (name,)), guard)

    def command(self, node, guard, cd_success):
        name_node = next((c for c in node.children if c.kind == "command_name"), None)
        if not name_node:
            self.emit(Fact("unresolved", "unknown-command", payload="Command name is unresolved"), guard)
            return
        if (len(name_node.children) == 1 and name_node.children[0].kind == "arithmetic_expansion"
                and name_node.children[0].text.startswith("((")):
            self.arithmetic_command(name_node.children[0], guard)
            return
        self.invalidate_loop_variables(self.arithmetic_expansion_writes(node), guard)
        name_value = resolve_word(name_node, self.state.env, limit=self.limit)
        name = name_value.text
        args = bounded_arguments((resolve_word(c, self.state.env, limit=self.limit) for c in node.children if c.kind not in {"command_name", "variable_assignment"}), self.limit)
        # Only exported bindings reach a child shell. A plain assignment is a shell
        # variable that the child never sees, so copying the whole namespace into a
        # nested interpreter invented targets that shell does not have.
        child_bindings = {k: v.text if v.text is not None else v for k, v in self.state.env.items()
                          if k in self.state.exported and (v.text is not None or v.alternatives)}
        for child in node.children:
            self.walk_substitutions(child)
        # Prefix assignments affect child env, but argument expansion used old bindings.
        for child in node.children:
            if child.kind == "variable_assignment":
                binding_name = next((c.text for c in child.children if c.kind == "variable_name"), "")
                value = resolve_word(child.children[-1], self.state.env, quoted=True, limit=self.limit)
                if value.text is not None:
                    child_bindings[binding_name] = value.text
                else:
                    child_bindings.pop(binding_name, None)
                if binding_name == "PATH":
                    self.emit(Fact("environment", "environment-modified", ("PATH",)), guard)
        if name in {"break", "continue"}:
            self.emit(Fact("unresolved", "unsupported-syntax", payload="Loop control transfer is not modeled: " + name), guard)
            if any(v.text is None for v in args):
                self.emit(Fact("unresolved", "unresolved-value", values=tuple(v for v in args if v.text is None), payload="Loop-control count is unresolved"), guard)
            return
        if name == "exit":
            operands = args[1:] if args and args[0].text == '--' else args
            if len(operands) == 1 and operands[0].text == '--help':
                return
            if len(operands) > 1 or any(v.text is None or v.pattern for v in operands):
                self.emit(Fact('unresolved', 'unresolved-value', values=tuple(operands),
                               payload='Bash exit status or argument count is unresolved or invalid'), guard)
                return
            # Numeric status is not needed to determine unconditional shell
            # termination; a literal nonnumeric status also exits with an error.
            if not guard:
                self.state.terminated = True
            return
        if name == "read":
            self.read_bindings(args, guard)
            return
        if name == "env" and not (args and args[0].text and args[0].text.startswith("-")):
            args = list(args)
            while args and args[0].text and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", args[0].text):
                binding_name, value = args.pop(0).text.split("=", 1)
                child_bindings[binding_name] = value
                if binding_name == "PATH":
                    self.emit(Fact("environment", "environment-modified", ("PATH",)), guard)
            if not args or args[0].text is None or args[0].text.startswith("-"):
                self.emit(Fact("unresolved", "unsupported-syntax", payload="env requires a supported literal assignment and command form"), guard)
                return
            name, args = args[0].text, tuple(args[1:])
        sudo_password_stdin = False
        if name == "sudo":
            self.emit(Fact("execution", "privilege-escalation"), guard)
            unknown, index = take_wrapper_options(args, SUDO_SPEC)
            for option in unknown:
                self.emit(Fact("unresolved", "unknown-option", payload=option), guard)
            if unknown:
                # An unknown wrapper option may consume the next token, so the
                # wrapped command position is no longer establishable.
                self.emit(Fact("unresolved", "execution-content-unavailable",
                               payload="Unsupported wrapper options leave the command it runs unresolved"), guard)
                return
            if index is None:
                self.emit(Fact("unresolved", "execution-content-unavailable",
                               payload="The command a wrapper runs could not be determined"), guard)
                return
            _, sudo_flags, _, _ = parse_options(args[:index], SUDO_SPEC)
            sudo_password_stdin = bool(sudo_flags & {'-S', '--stdin'}) and not bool(sudo_flags & {'-n', '--non-interactive', '-A', '--askpass', '--help', '--version', '-V'})
            if sudo_password_stdin:
                self.emit(Fact('credential_input', 'sudo', flags=frozenset({f'stdin_invocation:{node.span.start}'})), guard)
            if index >= len(args):
                return
            name, args = args[index].text, args[index + 1:]
        if name is None:
            self.emit(Fact("unresolved", "unknown-command", values=(name_value,), payload="Command name depends on expansion"), guard)
            return
        if name.lower() in {"powershell", "pwsh", "powershell.exe", "pwsh.exe"} and any(
                v.text and v.text.lower() in {"-e", "-enc", "-encodedcommand", "-encodedarguments"} for v in args):
            self.emit(Fact("content", "encoded-command"), guard)
        for fact in describe(name, args, self.state.cwd):
            if sudo_password_stdin and fact.kind in {'execute', 'invoke'}:
                fact = replace(fact, flags=fact.flags | {'authentication_stdin', 'consumes_stdin'})
            if fact.kind in {"execute", "invoke"}:
                fact = replace(fact, flags=fact.flags | {f"stdin_invocation:{node.span.start}"})
            if fact.kind == "sql_source":
                fact = replace(fact, flags=fact.flags | {f"sql_invocation:{node.span.start}"})
            self.emit(fact, guard)
            if fact.kind in {"execute", "git", "invoke"}:
                bindings = dict(fact.bindings) if "clear_bindings" in fact.flags else child_bindings | dict(fact.bindings)
                self.facts[-1] = replace(self.facts[-1], bindings=tuple(bindings.items()))
        if name in {"source", "."}:
            self.state.cwd = None
            self.state.env = {k: v if k in self.state.readonly else Value(None, "sourced_state") for k, v in self.state.env.items()}
        if name == "cd":
            operands, _, _, unknown = parse_options(args, SPECS["cd"])
            target_value = operands[0] if operands else self.state.env.get("HOME", Value(None, "missing_variable", ("HOME",)))
            target = resolve_path(target_value, self.state.cwd) if not unknown else None
            # Changing to the current directory leaves cwd unchanged on either
            # success or failure; other standalone changes remain uncertain.
            self.state.cwd = target if cd_success or target == self.state.cwd else None
        if name not in {"rm"}:
            for value in args:
                if value.text is None:
                    self.emit(Fact("unresolved", "unresolved-value", values=(value,), payload=value.reason or "Runtime-dependent argument"), guard)

    def stdin_passthrough(self, body) -> bool:
        """Whether this body command copies its standard input to its standard output.

        Only then is a here-document the content of a redirected file rather than
        that command's output.
        """
        if body is None or body.kind != "command":
            return False
        name = next((c.text for c in body.children if c.kind == "command_name"), "")
        if name == "tee":
            return True
        if name != "cat":
            return False
        for child in body.children:
            if child.kind == "command_name":
                continue
            text = resolve_word(child, self.state.env, limit=self.limit).text
            if text is None or not text.startswith("-"):
                return False  # `cat FILE` reads the file, not standard input.
        return True

    def literal_output(self, node):
        if node.kind != "command":
            return None
        name = next((c.text for c in node.children if c.kind == "command_name"), "")
        values = [resolve_word(c, self.state.env, limit=self.limit).text for c in node.children if c.kind not in {"command_name", "variable_assignment"}]
        if any(v is None for v in values):
            return None
        if name == "echo" and not any(v.startswith("-") or "\\" in v for v in values):
            return " ".join(values) + "\n"
        if name == "printf" and values:
            format_string = values[0]
            if re.search(r"\\(?![ntr\\])", format_string):
                return None
            # Only literal output and a single %s format are supported initially.
            decoded_format = re.sub(r"\\([ntr\\])", lambda m: {"n": "\n", "t": "\t", "r": "\r", "\\": "\\"}[m[1]], format_string)
            if len(values) == 1 and "%" not in format_string:
                return decoded_format
            elif len(values) == 2 and format_string.count("%s") == 1 and "%" not in format_string.replace("%s", ""):
                return decoded_format.replace("%s", values[1])
            else:
                return None
        return None
