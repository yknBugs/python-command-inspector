"""Shallow PowerShell/CMD facts. No host environment, evaluation, or disk reads."""
from dataclasses import replace
import re
from ..shared.builtins import supports_native_command
from ..shared.commands import describe, credential_like_path, NETWORK_SINKS, route_file_payload, stdin_network_sink
from ..models import Fact, Value
from ..admin.windows import describe_admin
from ..sql.clients import SQL_CLIENTS, attach_sql_input, sql_file_input
from ..paths import style_for
from ..shared.path_commands import is_command_path, is_source_path, command_basename
from ..shared.null_devices import is_null_device
from ..shared.streams import attach_execution_input, file_stream_sources, execution_consumer


from ..shared.windows import WindowsBuilder
from ..shared.value_flow import value as abstract_value, join, join_maps, choices, mark, bounded, compose, bounded_arguments, candidates


PS_ALIASES = {"rm": "remove-item", "del": "remove-item", "erase": "remove-item", "ri": "remove-item",
              "cat": "get-content", "gc": "get-content", "type": "get-content",
              "ls": "get-childitem", "dir": "get-childitem", "gci": "get-childitem",
              "cd": "set-location", "sl": "set-location", "pwd": "get-location", "pushd": "push-location", "popd": "pop-location",
              "cp": "copy-item", "copy": "copy-item", "cpi": "copy-item",
              "mv": "move-item", "move": "move-item", "mi": "move-item", "ren": "rename-item",
              "ni": "new-item", "spps": "stop-process", "sc": "set-content", "ac": "add-content", "echo": "write-output", "sleep": "start-sleep", "iwr": "invoke-webrequest", "irm": "invoke-restmethod", "iex": "invoke-expression"}
PS_OPTIONS = {
    "set-executionpolicy": ({"force", "whatif", "confirm"}, {"executionpolicy", "scope"}),
    "set-mppreference": ({"force"}, {"disablerealtimemonitoring", "exclusionpath", "exclusionprocess", "exclusionextension"}),
    "add-mppreference": ({"force"}, {"exclusionpath", "exclusionprocess", "exclusionextension"}),
    "remove-mppreference": ({"force"}, {"exclusionpath", "exclusionprocess", "exclusionextension"}),
    "remove-item": ({"recurse", "force", "whatif", "confirm"}, {"path", "literalpath", "filter", "include", "exclude"}),
    "get-content": ({"raw", "wait"}, {"path", "literalpath", "encoding", "totalcount", "tail"}),
    "get-childitem": ({"recurse", "force", "name", "file", "directory"}, {"path", "literalpath", "filter"}),
    "set-location": ({"passthru"}, {"path", "literalpath"}),
    "pop-location": ({"passthru"}, {"stackname"}),
    "push-location": ({"passthru"}, {"path", "literalpath", "stackname"}),
    "set-content": ({"force", "nonewline"}, {"path", "literalpath", "value", "encoding"}),
    "add-content": ({"force", "nonewline"}, {"path", "literalpath", "value", "encoding"}),
    "out-file": ({"append", "force", "noclobber", "nonewline"}, {"filepath", "encoding", "width"}),
    "new-item": ({"force"}, {"path", "name", "itemtype", "value"}),
    "stop-process": ({"force", "whatif", "confirm"}, {"id", "name"}),
    "start-process": ({"wait", "nonewwindow", "passthru"}, {"filepath", "argumentlist", "verb", "workingdirectory"}),
    "start-service": ({"whatif", "confirm"}, {"name", "displayname"}),
    "new-service": ({}, {"name", "binarypathname", "displayname", "startuptype"}),
    "set-service": ({"whatif", "confirm"}, {"name", "startuptype", "status"}),
    "register-scheduledtask": ({"force"}, {"taskname", "action", "trigger", "user"}),
    "invoke-webrequest": ({"usebasicparsing"}, {"uri", "outfile", "method", "body", "headers"}),
    "invoke-restmethod": ({}, {"uri", "outfile", "method", "body", "headers"}),
    "install-module": ({"force", "allowclobber"}, {"name", "scope", "repository"}),
    "install-package": ({"force"}, {"name", "source"}),
    "measure-object": ({"character", "word", "line", "sum"}, {"property"}),
    "write-output": ({"noenumerate"}, {}),
    "restart-computer": ({"force", "wait", "whatif", "confirm"}, {"computername"}),
    "stop-computer": ({"force", "whatif", "confirm"}, {"computername"}),
    "get-date": ({"asutc"}, {"date", "year", "month", "day", "hour", "minute", "second", "millisecond", "displayhint", "format", "uformat", "unixtimeseconds"}),
    "get-location": ({}, {}), "start-sleep": ({}, {"seconds", "milliseconds"}),
}


# Common filesystem/system cmdlets use explicit, per-command parameter sets.
PS_OPTIONS.update({
    "copy-item": ({"recurse", "force", "container", "passthru", "whatif", "confirm"}, {"path", "literalpath", "destination", "filter", "include", "exclude"}),
    "move-item": ({"force", "passthru", "whatif", "confirm"}, {"path", "literalpath", "destination", "filter", "include", "exclude"}),
    "rename-item": ({"force", "passthru", "whatif", "confirm"}, {"path", "literalpath", "newname"}),
    "clear-content": ({"force", "whatif", "confirm"}, {"path", "literalpath"}),
    "get-item": ({"force"}, {"path", "literalpath"}),
    "test-path": ({"isvalid"}, {"path", "literalpath", "pathtype"}),
    "get-process": ({}, {"id", "name"}),
    "get-service": ({}, {"name", "displayname"}),
    "get-scheduledtask": ({}, {"taskname", "taskpath"}),
})
for _name in ("stop-service", "restart-service", "suspend-service", "resume-service"):
    PS_OPTIONS[_name] = ({"force", "whatif", "confirm"}, {"name", "displayname"})
for _name in ("unregister-scheduledtask", "start-scheduledtask", "stop-scheduledtask", "enable-scheduledtask", "disable-scheduledtask", "set-scheduledtask"):
    PS_OPTIONS[_name] = ({"whatif", "confirm"}, {"taskname", "taskpath", "action", "trigger", "user"})
for _name in ("invoke-webrequest", "invoke-restmethod"):
    _switches, _valued = PS_OPTIONS[_name]
    PS_OPTIONS[_name] = (set(_switches) | {"usebasicparsing", "usedefaultcredentials"},
                        set(_valued) | {"infile", "credential", "authentication", "token", "contenttype", "timeoutsec"})
PS_PARAMETER_ALIASES = {"ea": "erroraction", "wa": "warningaction", "ev": "errorvariable",
                        "lp": "literalpath", "pspath": "literalpath"}
PS_ALIASES.update({"select": "select-object", "ft": "format-table", "fl": "format-list",
                   "sls": "select-string", "where": "where-object", "?": "where-object",
                   "sort": "sort-object", "group": "group-object",
                   "%": "foreach-object", "foreach": "foreach-object"})
PS_OPTIONS.update({
    "foreach-object": ({"whatif", "confirm", "asjob", "usenewrunspace"},
                       {"process", "begin", "end", "remainingscripts", "inputobject", "membername", "argumentlist", "parallel", "throttlelimit", "timeoutseconds"}),
    "select-object": ({"unique", "wait", "caseinsensitive"}, {"property", "excludeproperty", "expandproperty", "first", "last", "skip", "skiplast", "index", "skipindex", "inputobject"}),
    "format-table": ({"autosize", "hidetableheaders", "wrap", "force", "showerror", "displayerror"}, {"property", "groupby", "view"}),
    "format-list": ({"force", "showerror", "displayerror"}, {"property", "groupby", "view"}),
    "out-string": ({"stream", "nonewline"}, {"width", "inputobject"}),
    "out-null": (set(), {"inputobject"}),
    "write-host": ({"nonewline"}, {"object", "separator", "foregroundcolor", "backgroundcolor"}),
    "where-object": ({"not", "casesensitive", "eq", "ne", "gt", "ge", "lt", "le", "like", "notlike", "match", "notmatch", "contains", "notcontains", "in", "notin", "is", "isnot", "ceq", "cne", "clike", "cmatch"}, {"filterscript", "property", "value", "inputobject"}),
    "sort-object": ({"descending", "unique", "stable", "casesensitive"}, {"property", "culture", "top", "bottom", "inputobject"}),
    "group-object": ({"noelement", "ashashtable", "asstring", "casesensitive"}, {"property", "culture", "inputobject"}),
    "convertfrom-json": ({"ashashtable", "noenumerate"}, {"inputobject", "depth", "datekind"}),
    "select-string": ({"simplematch", "casesensitive", "quiet", "list", "allmatches", "notmatch", "raw", "noemphasis"}, {"pattern", "path", "literalpath", "inputobject", "include", "exclude", "context", "encoding", "culture"}),
    "add-type": ({"passthru", "ignorewarnings"}, {"typedefinition", "name", "memberdefinition", "namespace", "language", "referencedassemblies", "outputassembly", "outputtype", "path", "literalpath", "assemblyname", "compileroptions"}),
})
PS_OPTIONS['get-childitem'] = (PS_OPTIONS['get-childitem'][0] | {'hidden', 'system', 'readonly', 'followsymlink'}, PS_OPTIONS['get-childitem'][1] | {'include', 'exclude', 'depth', 'attributes'})
PS_OPTIONS['get-content'] = (PS_OPTIONS['get-content'][0] | {'force', 'asbytestream'}, PS_OPTIONS['get-content'][1] | {'readcount', 'filter', 'include', 'exclude', 'delimiter'})


class PowerShellBuilder(WindowsBuilder):
    def __init__(self, cwd, env, **kwargs):
        super().__init__(cwd, env, shell="powershell", **kwargs)
        self.variables = {"home": abstract_value(self.env.get("userprofile", self.env.get("home"))),
                          "true": Value("true"), "false": Value("false"), "null": Value("")}
        self.failed = set()
        self.halted = False
        self.pending_cd = None
        self.location_stacks = {}  # case-insensitive name -> tuple of saved cwd values, or unknown
        self.arrays = {}
        self.pipeline_input = None
        self.pipeline_values = None
        self.state_observer = None

    @staticmethod
    def numeric_range_command(node):
        """Recognize the grammar's bare integer-range misparse, without expansion.

        Argument-mode tokens and explicit command invocations remain commands.
        Redirections are handled separately by the normal command wrapper.
        """
        if node.kind != "command":
            return False
        name = next((c for c in node.children if c.kind == "command_name"), None)
        if name is None or not re.fullmatch(r"[+-]?[0-9]+\.\.[+-]?[0-9]+", name.text):
            return False
        return all(c is name or (c.kind == "command_elements" and all(
            part.kind in {"command_argument_sep", "redirection"} for part in c.children
        )) for c in node.children)

    def value(self, node):
        bindings = self.variables | {"env:" + k: abstract_value(v) for k, v in self.env.items()}
        rows, _ = choices(bindings, self.expression_variables(node), self.limit)
        if not rows:
            return bounded(self._value(node), self.limit)
        before, env = self.variables, self.env
        results = []
        try:
            for row in rows:
                self.variables = before | {k: v for k, v in row.items() if not k.startswith("env:")}
                self.env = env | {k[4:]: v for k, v in row.items() if k.startswith("env:")}
                results.append(self._value(node))
        finally:
            self.variables, self.env = before, env
        return join(results, self.limit)

    def _value(self, node):
        from ..shared.runtime_values import runtime_output, component
        shaped = runtime_output(node.text, 'powershell')
        if shaped is not None:
            return shaped
        if node.kind == 'native_equals_argument':
            if len(node.children) != 2:
                return Value(None, 'unsupported_expression', self.expression_variables(node))
            return compose((self.value(node.children[0]), Value('='), self.value(node.children[1])), limit=self.limit)
        if self.numeric_range_command(node):
            return component('range_expression')
        if node.kind == 'command':
            return Value(None, 'command_output', self.expression_variables(node))
        text = node.text.strip()
        if text.startswith("@'") and text.endswith("'@"):
            return Value(text[2:-2].strip("\r\n"))
        if node.kind in {"verbatim_string_characters", "generic_token"} and text.startswith("'") and text.endswith("'"):
            return Value(text[1:-1].replace("''", "'"))
        if node.kind == "hash_literal_expression":
            entries = []
            variables = set()
            for key, expression in self.mapping_entries(node):
                value = self.value(expression)
                variables.update(value.variables)
                if value.text is None:
                    return Value(None, "dynamic_mapping", tuple(sorted(set(value.variables) | set(self.expression_variables(node)))))
                entries.append(key + ": " + value.text)
            return Value("\n".join(entries), "literal_mapping", tuple(sorted(variables)))
        # Grammar wrappers are transparent only when they contain one expression.
        if node.kind not in {"generic_token", "command_name", "command_parameter", "expandable_string_literal", "expandable_here_string_literal", "variable", "integer_literal", "decimal_integer_literal"}:
            named = [c for c in node.children if c.kind not in {"(", ")", '"', "command_argument_sep"}]
            if len(named) == 1:
                return self.value(named[0])
            return Value(None, "unsupported_expression", self.expression_variables(node))
        if text.startswith('@"') and text.endswith('"@'):
            text = text[2:-2].strip("\r\n")
        elif text.startswith('"') and text.endswith('"'):
            text = text[1:-1]
        result, variables, i = [], [], 0
        unresolved_reason = None
        while i < len(text):
            if text[i] == "`" and i + 1 < len(text):
                char = text[i + 1]
                result.append({"n": "\n", "r": "\r", "t": "\t"}.get(char, char))
                i += 2
            elif text[i] == "$":
                match = re.match(r"\$(?:\{([^}]+)\}|((?:env:)?[\w]+))", text[i:], re.I)
                if not match:
                    return Value(None, "dynamic_expression", tuple(sorted(set(variables) | set(self.expression_variables(node)))))
                name = (match[1] or match[2]).casefold()
                variables.append(name)
                binding = abstract_value(self.env.get(name[4:])) if name.startswith("env:") else self.variables.get(name, Value(None))
                variables.extend(binding.variables)
                if binding.text is None:
                    result.append(binding)
                else:
                    result.append(binding.text)
                i += len(match[0])
            else:
                result.append(text[i])
                i += 1
        rendered = compose((part if isinstance(part, Value) else Value(part) for part in result), limit=self.limit)
        return replace(rendered, variables=tuple(variables))

    @staticmethod
    def mapping_entries(node):
        body = next((c for c in node.children if c.kind == "hash_literal_body"), None)
        for entry in body.children if body else ():
            if entry.kind == "hash_entry":
                expression = next((c for c in entry.children[2:] if c.kind not in {";", "\n"}), None)
                if expression is not None:
                    yield entry.children[0].text.strip().strip("'\""), expression

    @staticmethod
    def expression_variables(node, skip_blocks=False):
        names, pending = set(), [node]
        while pending:
            current = pending.pop()
            if skip_blocks and current.kind == "script_block_expression":
                continue
            if current.kind == "variable":
                name = current.text.lstrip("$").strip("{}").casefold()
                if name not in {"true", "false", "null"} and re.fullmatch(r"\w+(?::\w+)?", name):
                    names.add(name)
            pending.extend(current.children)
        return tuple(sorted(names))

    def values(self, node):
        """Literal arrays are finite syntax, not loop/runtime enumeration."""
        if self.numeric_range_command(node):
            from ..shared.runtime_values import component
            return (component('range_expression'),)
        if node.kind == 'command':
            return (self.value(node),)
        if re.fullmatch(r"\$\w+", node.text.strip()):
            name = node.text.strip()[1:].casefold()
            if name in self.arrays:
                return tuple(replace(v, variables=tuple(dict.fromkeys((*v.variables, name)))) for v in self.arrays[name])
        if node.kind == "array_literal_expression" and any(c.kind == "," for c in node.children):
            return tuple(v for c in node.children if c.kind != "," for v in self.values(c))
        if node.kind == "array_expression":
            body = next((c for c in node.children if c.kind == "statement_list"), None)
            return tuple(v for c in body.children if c.kind != "empty_statement" for v in self.values(c)) if body else ()
        named = [c for c in node.children if c.kind not in {"(", ")", '"', "command_argument_sep"}]
        if len(named) == 1 and node.kind not in {"expandable_string_literal", "expandable_here_string_literal", "verbatim_string_characters", "generic_token", "variable"}:
            return self.values(named[0])
        return (self.value(node),)

    def literal_output(self, node):
        if node.kind != "command":
            values = self.values(node)
        elif self.command_name(node) == "write-output":
            elements = next((c for c in node.children if c.kind == "command_elements"), None)
            values = tuple(v for c in elements.children if c.kind != "command_argument_sep" for v in self.values(c)) if elements else ()
        else:
            return None
        return compose(values, separator="\n", limit=self.limit).text if values else None

    def build(self, root):
        self.walk(root)
        return tuple(self.facts)

    def snapshot(self):
        return (dict(self.variables), dict(self.arrays), dict(self.env), self._cwd, set(self.failed), self.halted, self.pending_cd, None if self.location_stacks is None else dict(self.location_stacks))

    def restore(self, state):
        variables, arrays, env, cwd, failed, self.halted, self.pending_cd, stacks = state
        self._cwd = cwd
        self.location_stacks = None if stacks is None else dict(stacks)
        self.variables, self.arrays, self.env, self.failed = dict(variables), dict(arrays), dict(env), set(failed)

    def merge_states(self, states):
        self.variables = join_maps([s[0] for s in states], self.limit)
        self.env = join_maps([s[2] for s in states], self.limit, strings=True)
        self.arrays = {k: v for k, v in states[0][1].items() if all(s[1].get(k) == v for s in states)}
        self._cwd = join(tuple(s[3] for s in states), self.limit)
        if any(s[7] is None for s in states):
            self.location_stacks = None
        else:
            keys = set().union(*(s[7] for s in states))
            self.location_stacks = {}
            for key in keys:
                stacks = [s[7].get(key, ()) for s in states]
                self.location_stacks[key] = (tuple(join(entries, self.limit) for entries in zip(*stacks))
                    if all(stack is not None for stack in stacks) and len({len(stack) for stack in stacks}) == 1 else None)
        self.failed = set().union(*(s[4] for s in states))
        self.halted = all(s[5] for s in states)
        # Every case changed location: && can narrow to their success targets.
        self.pending_cd = join((s[6] for s in states), self.limit) if all(s[6] is not None for s in states) else None

    def walk(self, node, guard=""):
        if node.kind in {"command", "invokation_expression", "pipeline_chain"}:
            bindings = self.variables | {"env:" + k: abstract_value(v) for k, v in self.env.items()}
            # A bounded location expands the same way a bounded variable does:
            # one case per surviving directory, each with a concrete cwd, so a
            # relative operand keeps one target per branch.
            cwd_key = "\0cwd"
            locations = self.cwd_choices()
            names = self.expression_variables(node, skip_blocks=True)
            if len(locations) > 1:
                bindings[cwd_key] = self._cwd
                names = (*names, cwd_key)
            rows, metadata = choices(bindings, names, self.limit)
            if rows:
                metadata = tuple(item for item in metadata if item[0] != cwd_key)
                before, states = self.snapshot(), []
                self.choice_serial += 1
                group = self.choice_serial
                for case, row in enumerate(rows):
                    case_start = len(self.facts)
                    self.restore(before)
                    self.variables.update({k: v for k, v in row.items() if not k.startswith("env:") and k != cwd_key})
                    self.env.update({k[4:]: v.text if v.text is not None else v for k, v in row.items() if k.startswith("env:")})
                    if cwd_key in row:
                        self._cwd = abstract_value(row[cwd_key])
                    self._walk(node, guard)
                    states.append(self.snapshot())
                    self.facts[case_start:] = mark(self.facts[case_start:], metadata, group, case)
                    if cwd_key in row:
                        self.facts[case_start:] = [replace(f, flags=f.flags | {"possible"}) for f in self.facts[case_start:]]
                self.merge_states(states)
                return
        self._walk(node, guard)

    def _walk(self, node, guard=""):
        if self.halted:
            return
        if node.kind == "assignment_expression":
            left = next((c for c in node.children if c.kind == "left_assignment_expression"), None)
            if (left and any(c.kind == 'assignement_operator' and c.text == '=' for c in node.children)
                    and re.fullmatch(r'(?i)\[(?:system\.)?console\]::(?:outputencoding|inputencoding)', left.text.strip())):
                right = node.children[-1]
                if re.fullmatch(r'(?i)\[(?:system\.)?text\.utf8encoding\]::new\(\s*(?:(?:\$false|\$true)(?:\s*,\s*(?:\$false|\$true))?)?\s*\)|\[(?:system\.)?text\.encoding\]::utf8', right.text.strip()):
                    return
                self.scan_subexpressions(right, guard)
                self.unresolved('Console encoding assignment is outside the supported forms', guard=guard)
                return
            # The RHS is a full pipeline, not just a value expression. Walk it
            # once even when the destination cannot be tracked (or is readonly).
            right = node.children[-1]
            self.walk(right, guard)
            if left is None or not re.fullmatch(r"\$(?:env:)?\w+", left.text, re.I):
                if left is not None:
                    self.scan_subexpressions(left, guard)
                self.unresolved("Assignment target is outside the supported variable forms", guard=guard)
                return
            name = left.text[1:].casefold()
            operator = next((c.text for c in node.children if c.kind == "assignement_operator"), "")
            values = self.values(right)
            value = values[0] if len(values) == 1 else Value(None, "array_binding")
            if operator != "=":
                value = Value(None, "compound_assignment")
                self.unresolved("Compound assignment is unresolved", guard=guard)
            if name in {"home", "true", "false", "null"}:
                self.failed.add(name)
                self.emit("assignment", "readonly-assignment-failed", targets=(name,), guard=guard)
                if all((v.text or "").casefold() == "stop" for v in candidates(self.variables.get("erroractionpreference", Value("")))):
                    self.halted = True
            elif name.startswith("env:"):
                self.env[name[4:]] = replace(value, local_definition=not guard)
                self.emit("environment", "environment-modified", targets=(name,), guard=guard)
            else:
                self.arrays.pop(name, None)
                if operator == "=" and len(values) != 1:
                    self.arrays[name] = values
                self.variables[name] = value
                if name == "erroractionpreference" and value.text and value.text.casefold() in {"ignore", "silentlycontinue"}:
                    self.unresolved("PowerShell error reporting is suppressed", "errors-suppressed", guard)
            if self.state_observer is not None:
                self.state_observer(self.snapshot())
            return
        if node.kind == "invokation_expression":
            from .methods import describe_method
            describe_method(self, node, guard)
            return
        if node.kind == "command":
            self.command(node, guard)
            return
        if node.kind in {"if_statement", "foreach_statement", "for_statement", "while_statement", "do_statement", "function_statement", "try_statement", "switch_statement"}:
            self.control_flow(node, guard)
            return
        if node.kind == "pipeline":
            chained = any(c.kind == "pipeline_chain_tail" for c in node.children)
            if chained:
                stable, states = None, []
                for child in node.children:
                    if child.kind == "pipeline_chain_tail":
                        operator = child.text.strip()
                        if stable is None:
                            stable = self.snapshot()
                        if self.pending_cd is not None:
                            if operator == "&&":
                                self._cwd = self.pending_cd
                            self.pending_cd = None
                        guard = "if the preceding command succeeds" if operator == "&&" else "if the preceding command fails"
                    else:
                        self.walk(child, guard)
                        states.append(self.snapshot())
                # Following statements join skipped and completed chain paths.
                if stable is not None:
                    self.merge_states([stable, *states])
                    self.halted = stable[5]
                self.pending_cd = None
                return
            for child in node.children:
                self.walk(child, guard)
            self.pending_cd = None
            return
        if node.kind == "pipeline_chain":
            commands = [c for c in node.children if c.kind == "command"]
            if any(c.text in {"&&", "||"} for c in node.children):
                before = self._cwd
                for index, child in enumerate(node.children):
                    self.walk(child, guard if index == 0 else "conditional on the preceding command")
                self._cwd = join((before, self._cwd), self.limit)
                return
            start = len(self.facts)
            previous_input, previous_values = self.pipeline_input, self.pipeline_values
            stages = [c for c in node.children if c.text != "|"]
            previous_facts = []
            for index, child in enumerate(stages):
                self.pipeline_input = self.literal_output(stages[index - 1]) if index else None
                prior = stages[index - 1] if index else None
                if self.pipeline_input is not None and prior is not None:
                    if prior.kind == "command" and self.command_name(prior) == "write-output":
                        elements = next((c for c in prior.children if c.kind == "command_elements"), None)
                        self.pipeline_values = tuple(v for c in elements.children if c.kind != "command_argument_sep" for v in self.values(c)) if elements else ()
                    else:
                        self.pipeline_values = self.values(prior)
                else:
                    self.pipeline_values = None
                stage_start = len(self.facts)
                self.walk(child, guard)
                if index and self.command_name(stages[index - 1]) == "get-content":
                    values = sql_file_input(previous_facts)
                    if values:
                        self.facts[stage_start:] = attach_sql_input(self.facts[stage_start:], values=values)
                if index:
                    sources = file_stream_sources(previous_facts) if self.command_name(stages[index - 1]) == "get-content" else None
                    self.facts[stage_start:] = attach_execution_input(self.facts[stage_start:], values=sources, payload=self.pipeline_input, guard=guard)
                previous_facts = self.facts[stage_start:]
            self.pipeline_input, self.pipeline_values = previous_input, previous_values
            if len(stages) > 1 and commands:
                sink = self.command_name(commands[-1])
                flags = {"output_consumed"} if sink in {"measure-object", "set-content", "add-content", "out-file", "out-null"} or execution_consumer(previous_facts) else {"selection_uncertain"}
                if sink in {"set-content", "add-content", "out-file", "out-null"}:
                    flags.add("output_redirected")
                self.facts[start:] = [replace(f, flags=f.flags | flags) if f.kind in {"read", "invoke"} else f for f in self.facts[start:]]
                if sink.removesuffix(".exe") in NETWORK_SINKS or any(f.kind == "invoke" and stdin_network_sink(f) for f in self.facts[start:]):
                    routed = self.facts[start:]
                    index = next((i for i in range(len(routed) - 1, -1, -1) if stdin_network_sink(routed[i])), None)
                    if index is not None:
                        self.facts[start:] = route_file_payload(routed, index)
                if sink in {"iex", "invoke-expression"}:
                    self.facts[start:] = [replace(f, operation="download", flags=f.flags | {"to_interpreter"}) if f.kind == "network" else f for f in self.facts[start:]]
                    self.emit("content", "encoded-command", guard=guard)
                    self.unresolved("Pipeline executable content is unavailable", "execution-content-unavailable", guard)
            return
        for child in node.children:
            if child.children or child.kind in {"command", "assignment_expression"}:
                self.walk(child, guard)

    def scan_subexpressions(self, node, guard, *, skip_script_blocks=False):
        if skip_script_blocks:
            if node.kind == "script_block_expression":
                return
            if node.kind in {"command", "assignment_expression", "invokation_expression"}:
                self.walk(node, "during expression evaluation")
                return
            for child in node.children:
                self.scan_subexpressions(child, guard, skip_script_blocks=True)
            return
        if node.kind in {"pipeline", "assignment_expression", "command", "sub_expression", "sub_expression_body", "invokation_expression", "array_expression", "script_block_expression"}:
            self.walk(node, "during expression evaluation")
            return
        for child in node.children:
            self.scan_subexpressions(child, guard, skip_script_blocks=skip_script_blocks)

    def widen_loop(self):
        self.location_stacks = None
        self.variables = {name: binding if name in {"home", "true", "false", "null"} else Value(None, "control_flow_limit", (name,)) for name, binding in self.variables.items()}
        self.env = {name: Value(None, "control_flow_limit", ("env:" + name,)) for name in self.env}
        self.arrays = {}
        self.cwd = None
        self.unresolved("Loop state exceeds the configured control-flow budget", "unresolved-value")

    def joined_snapshot(self, states):
        before, pending = self.snapshot(), self.pending_cd
        self.merge_states(states)
        joined = self.snapshot()
        self.restore(before)
        self.pending_cd = pending
        return joined

    def try_flow(self, node, guard):
        self.unresolved("Exception reachability is not fully modeled", guard=guard)
        entry = self.snapshot()
        prefix = entry
        previous_observer = self.state_observer
        def observe(state):
            nonlocal prefix
            prefix = self.joined_snapshot([prefix, state])
            if previous_observer is not None:
                previous_observer(state)
        body = next((c for c in node.children if c.kind == "statement_block"), None)
        self.choice_serial += 1
        group = self.choice_serial
        start = len(self.facts)
        self.state_observer = observe
        try:
            if body is not None:
                self.walk(body, (guard + "; " if guard else "") + "if the try body runs")
        finally:
            self.state_observer = previous_observer
        states = [self.snapshot()]
        self.facts[start:] = [replace(f, flags=f.flags | {"possible"}) for f in mark(self.facts[start:], (), group, 0)]
        def catches(current):
            for child in current.children:
                if child.kind == "catch_clause":
                    yield from (c for c in child.children if c.kind == "statement_block")
                elif child.kind == "catch_clauses":
                    yield from catches(child)
        for case, catch in enumerate(catches(node), 1):
            self.restore(prefix)
            self.halted = entry[5]
            start = len(self.facts)
            self.walk(catch, (guard + "; " if guard else "") + "if this catch body runs")
            states.append(self.snapshot())
            self.facts[start:] = [replace(f, flags=f.flags | {"possible"}) for f in mark(self.facts[start:], (), group, case)]
        self.merge_states(states)
        self.halted = entry[5]
        final = next((c for c in node.children if c.kind == "finally_clause"), None)
        if final is not None:
            self.walk(final, (guard + "; " if guard else "") + "when the finally body runs")
        self.halted = entry[5]
        self.pending_cd = None

    def if_flow(self, node, guard):
        initial = next((c for c in node.children if c.kind == "pipeline"), None)
        if initial is not None:
            self.walk(initial, guard)
        entry = self.snapshot()
        main = next((c for c in node.children if c.kind == "statement_block"), None)
        arms = [(None, main)] if main is not None else []
        has_else = False
        def collect(current):
            nonlocal has_else
            for child in current.children:
                if child.kind == "elseif_clause":
                    condition = next((c for c in child.children if c.kind == "pipeline"), None)
                    body = next((c for c in child.children if c.kind == "statement_block"), None)
                    if body is not None:
                        arms.append((condition, body))
                elif child.kind == "else_clause":
                    has_else = True
                    body = next((c for c in child.children if c.kind == "statement_block"), None)
                    if body is not None:
                        arms.append((None, body))
                elif child.kind == "elseif_clauses":
                    collect(child)
        collect(node)
        self.choice_serial += 1
        group = self.choice_serial
        states, conditions = [], []
        condition_entry = entry
        for case, (condition, body) in enumerate(arms):
            self.restore(condition_entry)
            start = len(self.facts)
            if condition is not None:
                self.walk(condition, (guard + "; " if guard else "") + "if earlier conditions are false")
                conditions.extend(self.facts[start:])
                del self.facts[start:]
                condition_entry = self.snapshot()
            self.facts.extend(conditions)
            self.walk(body, (guard + "; " if guard else "") + "if this body runs")
            self.facts[start:] = [replace(f, flags=f.flags | {"possible"}) for f in mark(self.facts[start:], (), group, case)]
            states.append(self.snapshot())
        if not has_else:
            states.append(condition_entry)
        self.merge_states(states or [entry])
        self.halted = entry[5]
        self.pending_cd = None

    def control_flow(self, node, guard):
        if node.kind == "if_statement":
            self.if_flow(node, guard)
            return
        if node.kind == "try_statement":
            self.try_flow(node, guard)
            return
        loop = node.kind in {"foreach_statement", "for_statement", "while_statement", "do_statement"}
        start = len(self.facts)
        if node.kind not in {"foreach_statement", "if_statement"}:
            self.unresolved("Loop iteration counts are not modeled" if loop else "Control-flow reachability is not fully modeled", guard=guard)
        before, context = self.snapshot(), self.context
        def blocks(current):
            for child in current.children:
                if child.kind in {"statement_block", "script_block"}:
                    yield child
                elif child.kind in {"else_clause", "elseif_clause", "elseif_clauses", "catch_clauses", "catch_clause", "finally_clause", "switch_body", "switch_clause", "switch_clauses", "ERROR"}:
                    yield from blocks(child)
                elif not loop:
                    self.scan_subexpressions(child, guard)
        bodies = list(blocks(node))
        entry = self.snapshot()
        if node.kind == "function_statement":
            self.context = "defined_body"
        if loop:
            variable = next((c for c in node.children if c.kind == "variable"), None)
            if variable:
                name = variable.text[1:].strip("{}").casefold()
                collection = next((c for c in node.children if c.kind == "pipeline"), None)
                items = self.values(collection) if collection else (Value(None, "loop_variable_unresolved", (name,)),)
                self.variables[name] = join(items, self.limit, name)
                self.arrays.pop(name, None)
            seed = self.snapshot()
            iteration_binding = self.variables[name] if variable else None
            exits = []
            # A bounded abstract fixed point handles loop-carried assignments.
            # This joins states; it does not execute a loop for each input item.
            for _ in range(self.flow_steps):
                previous = self.snapshot()
                self.halted = before[5]
                if variable:
                    self.variables[name] = iteration_binding
                    self.arrays.pop(name, None)
                for child in node.children:
                    if child in bodies:
                        self.walk(child, (guard + "; " if guard else "") + "if the loop body runs")
                    elif child.kind == "while_condition":
                        self.walk(child, (guard + "; " if guard else "") + "if the loop condition is evaluated")
                        exits.append(self.snapshot())
                    else:
                        self.scan_subexpressions(child, guard)
                self.merge_states([seed, previous, self.snapshot()])
                if self.snapshot() == previous:
                    break
            else:
                self.widen_loop()
                widened = self.snapshot()
                for body in bodies:
                    self.walk(body, (guard + "; " if guard else "") + "if the loop body runs")
                self.merge_states([widened, self.snapshot()])
            self.merge_states([before, self.snapshot(), *exits])
            self.facts[start:] = list(dict.fromkeys(self.facts[start:]))
            if node.kind == "foreach_statement" and len(self.facts) > start and (not variable or (seed[0][name].text is None and not seed[0][name].alternatives)):
                self.unresolved("Loop iteration counts are not modeled", guard=guard)
        else:
            states = [] if node.kind == "if_statement" and any(c.kind == "else_clause" for c in node.children) else [entry]
            self.choice_serial += 1
            group = self.choice_serial
            single_input = False
            nonempty_input = False
            has_default = False
            previous_end = node.span.start
            if node.kind == "switch_statement":
                condition = next((c for c in node.children if c.kind == "switch_condition"), None)
                pipeline = next((c for c in condition.children if c.kind == "pipeline"), None) if condition else None
                items = self.values(pipeline) if pipeline else ()
                # A default covers unmatched items, not an empty input stream.
                # Do not mistake an opaque command's spelling for its output.
                pending, command_input = [pipeline] if pipeline else [], False
                while pending:
                    current = pending.pop()
                    command_input |= current.kind == "command"
                    pending.extend(current.children)
                nonempty_input = bool(items) and not command_input and all(
                    item.text is not None or bool(item.alternatives) for item in items)
                single_input = nonempty_input and len(items) == 1
                switch_body = next((c for c in node.children if c.kind == "switch_body"), None)
                previous_end = switch_body.span.start + 1 if switch_body else node.span.start
            matching_states, matching_cases = [entry], []
            for case, body in enumerate(bodies):
                # Switch can run several clauses in source order. Conditions
                # remain unknown, so retain both skipped and preceding paths.
                if node.kind == "switch_statement":
                    label = node.text[previous_end - node.span.start:body.span.start - node.span.start].strip(" \t\r\n;")
                    default = re.fullmatch(r"(?is)(?:\s|<#.*?#>|#[^\r\n]*)*default(?:\s|<#.*?#>|#[^\r\n]*)*", label) is not None
                    has_default |= default
                    previous_end = body.span.end
                    predecessors = tuple(matching_cases) if single_input else tuple(range(case))
                    if single_input and default:
                        predecessors = ()
                        self.restore(entry)
                    else:
                        self.merge_states(matching_states if single_input else states or [entry])
                else:
                    self.restore(entry)
                arm_start = len(self.facts)
                self.walk(body, (guard + "; " if guard else "") + "if this body runs")
                if node.kind == "switch_statement" and len(self.facts) == arm_start:
                    self.emit("control", "branch-boundary", guard=guard)
                self.facts[arm_start:] = [replace(f, flags=f.flags | {"possible"},
                    choice_predecessors=f.choice_predecessors + (((group, predecessors),) if node.kind == "switch_statement" else ()))
                    for f in mark(self.facts[arm_start:], (), group, case)]
                states.append(self.snapshot())
                if node.kind == "switch_statement" and single_input and not default:
                    matching_states.append(self.snapshot())
                    matching_cases.append(case)
            if node.kind == "switch_statement" and nonempty_input and has_default:
                # Each input item must visit a matching clause or default. Keep
                # entry values only when an inspected body itself preserves them.
                states = states[1:]
            self.merge_states(states or [entry])
        if node.kind == "function_statement":
            self.restore(before)
        self.halted = before[5]
        self.pending_cd = None
        self.context = context

    def command_name(self, node):
        name = next((c for c in node.children if c.kind in {"command_name", "command_name_expr"}), None)
        value = self.value(name) if name else Value(None)
        text = value.text.casefold() if value.text is not None else ""
        return PS_ALIASES.get(text, text)

    def command(self, node, guard):
        """Redirection belongs to the shell, including on native/unknown commands."""
        start = len(self.facts)
        elements = next((c for c in node.children if c.kind == "command_elements"), None)
        redirects, kept = [], []
        for item in elements.children if elements else ():
            if item.kind == "redirection":
                if item.children[0].kind != "merging_redirection_operator":
                    redirects.append((item.children[0].text, self.value(item.children[-1])))
                continue
            attached = re.fullmatch(r"([1-6*]?)(>>?)(.+)", item.text) if item.kind == "generic_token" else None
            if attached:
                redirects.append((attached[1] + attached[2], self.value(replace(item, text=attached[3]))))
            else:
                kept.append(item)
        if elements:
            clean = replace(elements, children=tuple(kept))
            node = replace(node, children=tuple(clean if c is elements else c for c in node.children))
        self.command_effects(node, guard)
        self.redirect_output(redirects, start, self.literal_output(node), guard)

    def command_effects(self, node, guard):
        if self.numeric_range_command(node):
            return
        name_node = next((c for c in node.children if c.kind == "command_name_expr"), None)
        if name_node and any(c.kind == "script_block_expression" for c in name_node.children):
            for child in name_node.children:
                self.walk(child, guard)
            return
        name = self.command_name(node)
        invocation_name = name or None
        command_node = next((c for c in node.children if c.kind in {"command_name", "command_name_expr"}), None)
        command_path = self.value(command_node).text if is_command_path(name, self.shell) else None
        if command_path and not is_source_path(command_path):
            name = PS_ALIASES.get(command_basename(name, self.shell), command_basename(name, self.shell))
        if name.endswith(".exe") and name not in {"cmd.exe", "powershell.exe", "pwsh.exe"}:
            name = name[:-4]
        elements = next((c for c in node.children if c.kind == "command_elements"), None)
        nodes = [c for c in elements.children if c.kind != "command_argument_sep"] if elements else []
        for item in nodes:
            self.scan_subexpressions(item, guard, skip_script_blocks=name == "foreach-object")
        if command_path:
            if is_source_path(command_path):
                dialect = "powershell" if command_path.casefold().endswith((".ps", ".ps1")) else "cmd" if command_path.casefold().endswith((".cmd", ".bat")) else "artifact"
                self.emit("execute", dialect, values=(self.value(next(c for c in node.children if c.kind in {"command_name", "command_name_expr"})),),
                          flags={"direct_source"} if dialect != "artifact" else (), guard=guard)
                return
            self.emit("path_invocation", "execute", values=(Value(command_path),), guard=guard)
        if name in {"powershell", "powershell.exe", "pwsh", "pwsh.exe", "cmd", "cmd.exe"}:
            self.interpreter(name, nodes, guard)
            return
        if name.endswith((".ps1", ".cmd", ".bat")):
            self.emit("execute", "powershell" if name.endswith(".ps1") else "cmd", values=(self.value(next(c for c in node.children if c.kind in {"command_name", "command_name_expr"})),), flags={"direct_source"}, guard=guard)
            return
        if name == "invoke-expression":
            self.emit("content", "encoded-command", guard=guard)
            self.unresolved("Dynamically evaluated PowerShell is outside the supported subset", "execution-content-unavailable", guard)
            return
        if describe_admin(self, name, tuple(self.value(c) for c in nodes), guard):
            return
        if name not in PS_OPTIONS:
            # Native task runners use their existing models, never task-definition reads.
            if supports_native_command(name, self.shell):
                args = bounded_arguments((self.value(c) for c in nodes), self.limit)
                facts = describe(name, args, self.cwd, shell=self.shell)
                if self.pipeline_input is not None:
                    facts = attach_sql_input(facts, payload=self.pipeline_input)
                for fact in facts:
                    targets = tuple(p for v in fact.values if (p := self.paths.resolve(v, self.cwd)) is not None) if fact.kind in {"read", "write", "delete"} else fact.targets
                    self.facts.append(replace(fact, targets=targets, cwd=self.cwd, source=self.source, context=self.context,
                                              guard=fact.guard or guard, shell=self.shell, bindings=tuple(self.env.items())))
                    if command_path:
                        self.facts[-1] = replace(self.facts[-1], command_path=command_path,
                                                command_name=invocation_name if fact.operation == "unknown-command" else fact.command_name)
            else:
                self.unresolved(name or "Dynamic command name", "unknown-command", guard, command_name=invocation_name,
                                values=(self.value(name_node),) if name_node is not None and not name else ())
                if command_path:
                    self.facts[-1] = replace(self.facts[-1], command_path=command_path)
            return
        switches, valued = PS_OPTIONS[name]
        switches, valued = set(switches) | {"verbose", "debug"}, set(valued) | {"erroraction", "warningaction", "informationaction", "errorvariable", "warningvariable", "informationvariable", "outvariable", "outbuffer", "pipelinevariable"}
        positional, bound, flags, unknown = [], {}, set(), False
        positional_groups, bound_groups = [], {}
        positional_nodes, bound_nodes = [], {}
        comma_values = []
        i = 0
        while i < len(nodes):
            item = nodes[i]
            if item.kind == "generic_token" and item.text.startswith(","):
                comma_values.append(self.value(replace(item, text=item.text[1:])))
                i += 1
                continue
            if item.kind == "command_parameter":
                key, sep, attached = item.text.lstrip("-").partition(":")
                key = key.casefold()
                key = PS_PARAMETER_ALIASES.get(key, key)
                if key not in switches | valued:
                    matches = [candidate for candidate in switches | valued if candidate.startswith(key)]
                    if len(matches) == 1:
                        key = matches[0]
                if key in switches:
                    # The grammar stores the colon in a separator, outside the
                    # command_parameter node: -Force:$false is three nodes.
                    sep = sep or node.text[item.span.end - node.span.start:].startswith(":")
                    enabled = attached.casefold() not in {"$false", "false"}
                    if sep and not attached and i + 1 < len(nodes):
                        i += 1
                        switch_value = self.value(nodes[i]).text
                        if switch_value is None:
                            unknown = True
                        enabled = switch_value not in {"false", "$false", None}
                    if enabled:
                        flags.add(key)
                elif key in valued:
                    if attached:
                        bound[key] = Value(attached)
                    elif i + 1 < len(nodes) and nodes[i + 1].kind != "command_parameter":
                        i += 1
                        bound_nodes.setdefault(key, []).append(nodes[i])
                        bound_groups[key] = self.values(nodes[i])
                        bound[key] = bound_groups[key][0] if len(bound_groups[key]) == 1 else Value(None, "array_argument")
                    else:
                        unknown = True
                        self.unresolved("Missing parameter value: -" + key, "unknown-option", guard)
                else:
                    unknown = True
                    self.unresolved("-" + key, "unknown-option", guard)
            else:
                positional_nodes.append(item)
                group = self.values(item)
                positional_groups.append(group)
                positional.append(group[0] if len(group) == 1 else Value(None, "array_argument"))
            i += 1
        error = bound.get("erroraction", Value(""))
        if error.text and error.text.casefold() in {"ignore", "silentlycontinue"}:
            self.unresolved("PowerShell error reporting is suppressed", "errors-suppressed", guard)
        if name == "foreach-object":
            from .loops import describe_foreach_object
            describe_foreach_object(self, positional_nodes, bound_nodes, flags, guard)
            return
        if not positional and not bound.keys() & {"literalpath", "path"} and name in {"get-childitem", "push-location"}:
            positional.append(Value(self.cwd))
        path = bound.get("literalpath", bound.get("path", bound.get("filepath", positional[0] if positional else Value(None, "missing_operand"))))
        wildcard_paths = {"remove-item", "get-content", "get-childitem", "get-item", "test-path",
                          "set-content", "add-content", "clear-content", "copy-item", "move-item", "rename-item",
                          "set-location", "push-location", "new-item"}
        if name in wildcard_paths and "literalpath" not in bound and path.text and any(c in path.text for c in "*?["):
            path = replace(path, pattern=True)
        if unknown:
            path = Value(None, "unknown_parameter_binding")
        path_key = next((k for k in ("literalpath", "path", "filepath") if k in bound), None)
        group = bound_groups.get(path_key, (path,)) if path_key else positional_groups[0] if positional_groups else (path,)
        values = (*group, *comma_values) if not unknown else (path,)
        if name in wildcard_paths and "literalpath" not in bound:
            values = tuple(replace(v, pattern=True) if v.text and any(c in v.text for c in "*?[") else v for v in values)
        if name in {"remove-item", "get-content", "get-childitem"}:
            if len(positional) > 1 or unknown:
                self.unresolved("Additional operands or unsupported parameters leave binding unresolved", "unresolved-value", guard)
                values = (Value(None, "unsupported_argument_binding"),)
            values = tuple(replace(v, pattern=True) if "literalpath" not in bound and v.text and any(c in v.text for c in "*?[") else v for v in values)
        if "whatif" in flags:
            self.unresolved("WhatIf previews the operation without performing it", "unresolved-value", guard)
            return
        if name == 'write-output':
            references = {n[4:] for v in positional for n in v.variables if n.startswith('env:')}
            exposed = references & self.input_environment
            exposed = {n for n in exposed if not abstract_value(self.env.get(n)).local_definition}
            self.emit('output', 'environment-value-output', values=tuple(positional), targets=tuple(sorted(exposed)), guard=guard)
        if name == 'select-string':
            patterns = bound_groups.get('pattern', positional_groups[0] if positional_groups else ())
            selected = bound_groups.get('literalpath', bound_groups.get('path', positional_groups[1] if len(positional_groups) > 1 else ()))
            if unknown:
                selected = (Value(None, 'unknown_parameter_binding'),)
            selected = tuple(replace(v, pattern=True) if 'literalpath' not in bound and v.text and any(c in v.text for c in '*?[') else v for v in selected)
            selection_flags = {'output_consumed'} if flags & {'quiet', 'list'} else {'fixed_filter'} if 'simplematch' in flags and len(patterns) == 1 and not bound.keys() & {'context', 'include', 'exclude'} else {'selection_uncertain'}
            if 'casesensitive' not in flags:
                selection_flags.add('-i')
            if 'notmatch' in flags:
                selection_flags.add('-v')
            self.filesystem('read', 'ingest', selected, flags=selection_flags, payload=patterns[0].text if len(patterns) == 1 else None, guard=guard)
            return
        if name == 'add-type':
            self.emit('system', 'runtime-code-loading', guard=guard)
            if 'outputassembly' in bound:
                self.filesystem('write', 'transform', (bound['outputassembly'],), guard=guard)
            return
        if name in {"set-executionpolicy", "set-mppreference", "add-mppreference", "remove-mppreference"}:
            self.emit("system", "security-policy-change", targets=(name,), guard=guard)
        elif name == "remove-item":
            deletion_flags = ({"-r"} if "recurse" in flags else set()) | ({"-f"} if "force" in flags else set())
            failed = {n for v in values for n in v.variables} & self.failed
            if failed:
                deletion_flags.add("failed_assignment")
                if any(v.text is None for v in values):
                    deletion_flags.add("failed_assignment_unknown")
            if bound.keys() & {"filter", "include", "exclude"}:
                deletion_flags.add("selection_unmodeled")
            self.filesystem("delete", "delete", values, deletion_flags, guard=guard)
        elif name in {"get-content", "get-childitem", "get-item", "test-path"}:
            read_flags = {"selection_uncertain"} if (bound.keys() & {"totalcount", "tail", "filter", "readcount", "delimiter", "encoding"}
                                                    or flags & {"asbytestream", "wait"}) else set()
            if bound.keys() & {"filter", "include", "exclude"} or flags & {"file", "directory", "recurse"}:
                read_flags.add("selection_unmodeled")
            self.filesystem("read", "ingest" if name == "get-content" else "list", values, flags=read_flags, guard=guard)
        elif name == "pop-location":
            stack_name = bound.get("stackname", Value("")).text
            if unknown or positional or stack_name is None or any(c in stack_name for c in "*?["):
                self.location_stacks = None
                self.cwd, self.pending_cd = None, None
                self.unresolved("Location stack selection is unresolved", "unresolved-value", guard)
                return
            key = stack_name.casefold()
            stack = self.location_stacks.get(key, ()) if self.location_stacks is not None else None
            if stack is None:
                self.cwd, self.pending_cd = None, None
                self.unresolved("Location stack contents are unresolved", "unresolved-value", guard)
            elif stack:
                self.location_stacks[key] = stack[:-1]
                self.pending_cd = abstract_value(stack[-1])
                # Restoration can fail (e.g. the saved directory was removed).
                self._cwd = join((self._cwd, self.pending_cd), self.limit)
            # An empty stack cannot change the current location.
        elif name in {"set-location", "push-location"}:
            if name == "push-location":
                stack_name = bound.get("stackname", Value("")).text
                if unknown or stack_name is None or any(c in stack_name for c in "*?["):
                    self.location_stacks = None
                elif self.location_stacks is not None:
                    key = stack_name.casefold()
                    stack = self.location_stacks.get(key, ())
                    self.location_stacks[key] = (*stack, self._cwd) if stack is not None and len(stack) < self.flow_steps else None
            elif unknown:
                # Unsupported stack-selection forms may change the default stack.
                self.location_stacks = None
            self.filesystem("read", "list", values, guard=guard)
            # A standalone Set-Location can fail and still allow continuation, so
            # every resolvable destination joins the previous location. Each
            # alternative of a variable bound to several paths is resolved on its
            # own, so a bounded set stays one destination per branch.
            target = join((Value(self.paths.resolve(option, self.cwd), "unresolved_location")
                           for v in values for option in candidates(v)), self.limit)
            self.pending_cd = target
            self._cwd = join((self._cwd, target), self.limit)
        elif name in {"set-content", "add-content", "out-file", "new-item", "clear-content"}:
            payload_index = 0 if bound.keys() & {"path", "literalpath", "filepath"} else 1
            payload_value = bound.get("value", positional[payload_index] if len(positional) > payload_index else Value(self.pipeline_input))
            payload = payload_value.text
            content_values = bound_groups.get("value", positional_groups[payload_index] if len(positional_groups) > payload_index else ())
            if content_values and all(v.text is not None for v in content_values):
                payload = "\n".join(v.text for v in content_values)
            if name == "clear-content":
                payload = ""
            if name == "new-item" and "name" in bound:
                directory = self.paths.resolve(path, self.cwd)
                leaf = bound["name"].text
                values = (Value(self.paths.module.join(directory, leaf)) if directory and leaf is not None else Value(None, "unresolved_item_name"),)
            elif name == "new-item" and any(v.pattern for v in values):
                # Creation requires mapping matched parents to new item names;
                # existing wildcard matches are not creation destinations.
                values = (Value(None, "wildcard_creation_not_modeled"),)
            operation = "create_directory" if name == "new-item" and (bound.get("itemtype", Value("")).text or "").casefold() == "directory" else "append" if name == "add-content" or "append" in flags else "overwrite"
            unknown_variables = {n for v in (payload_value, *content_values) if v.text is None for n in v.variables} if payload is None else set()
            self.filesystem("write", operation, values, payload=payload, guard=guard, unresolved_variables=unknown_variables)
        elif name in {"copy-item", "move-item", "rename-item"}:
            destination = bound.get("destination", bound.get("newname", positional[1] if len(positional) > 1 else Value(None, "missing_destination")))
            if name == "rename-item" and destination.text is not None:
                source = self.paths.resolve(values[0], self.cwd) if len(values) == 1 else None
                destination = Value(self.paths.module.join(self.paths.module.dirname(source), destination.text)) if source else Value(None, "unresolved_source")
            self.filesystem("read", "list", values, guard=guard)
            self.emit("transfer", "copy" if name == "copy-item" else "move", values=(destination,),
                      flags={"-T"} if name == "rename-item" else (), guard=guard)
            self.facts[-1] = replace(self.facts[-1], transfer_sources=tuple(values))
            if any(v.text is None for v in values) or destination.text is None:
                self.unresolved("Copy/move source or destination is unresolved", "unresolved-value", guard, values=(*values, destination))
        elif name == "start-process":
            if bound.get("verb", Value("")).text and bound["verb"].text.casefold() == "runas":
                self.emit("execution", "privilege-escalation", guard=guard)
            else:
                self.unresolved("Started process content is outside the supported direct invocation forms", "execution-content-unavailable", guard)
        elif name == "stop-process":
            target = bound.get("id", bound.get("name", positional[0] if positional else Value(None)))
            self.emit("system", "force-process-termination", targets=(target.text or "unresolved",), payload="force" if "force" in flags else "terminate", guard=guard)
        elif name.endswith(("-service", "-scheduledtask")) and not name.startswith("get-"):
            target = bound.get("name", bound.get("taskname", positional[0] if positional else Value("unresolved")))
            self.emit("system", "service-change", targets=(target.text or "unresolved",), payload=name, guard=guard)
        elif name in {"restart-computer", "stop-computer"}:
            self.emit("system", "machine-power-change", guard=guard)
        elif name in {"install-module", "install-package"}:
            self.emit("system", "package-install", guard=guard)
        elif name in {"invoke-webrequest", "invoke-restmethod"}:
            from ..shared.auth import AUTH_TEXT
            uri_value = bound.get("uri", positional[0] if positional else Value(None))
            uri = uri_value.text
            credentials = [bound[k] for k in ("credential", "token") if k in bound]
            if uri and AUTH_TEXT.search(uri):
                credentials.append(uri_value)
            if "headers" in bound:
                header_nodes = list(bound_nodes.get("headers", ()))
                mappings = []
                while header_nodes:
                    header = header_nodes.pop()
                    if header.kind == "hash_literal_expression":
                        mappings.append(header)
                    else:
                        header_nodes.extend(header.children)
                if mappings:
                    # A literal map preserves provenance per entry: an ordinary
                    # header variable alongside Authorization is not a secret.
                    for mapping in mappings:
                        for key, expression in self.mapping_entries(mapping):
                            if key.casefold() in {"authorization", "proxy-authorization"}:
                                credentials.append(self.value(expression))
                elif bound["headers"].text is None or AUTH_TEXT.search(bound["headers"].text):
                    credentials.append(bound["headers"])
            payload = "\n".join(bound[k].text or "" for k in ("headers", "body") if k in bound)
            credential = bool(bound.keys() & {"credential", "token"}) or "usedefaultcredentials" in flags
            infile = bound.get("infile", Value(None)).text
            credential = credential or credential_like_path(infile.replace("\\", "/") if infile else None)
            network_flags = {"credential_payload"} if credential else set()
            if "infile" in bound:
                network_flags.update({"local_file_payload", "file_sources"})
            self.emit("network", "download" if "outfile" in bound else "request", payload=payload,
                      flags=network_flags, values=(bound["infile"],) if "infile" in bound else (),
                      targets=(uri,) if uri else (), guard=guard)
            self.facts[-1] = replace(self.facts[-1], credential_values=tuple(credentials),
                                    sensitive_variables=frozenset(n for value in credentials for n in value.variables))
            if uri is None or unknown or any(v.text is None for k, v in bound.items() if k in {"headers", "body", "infile"}):
                self.unresolved("Network arguments are not fully resolved", "unresolved-value", guard, values=(*positional, *bound.values()))
            if "outfile" in bound:
                self.filesystem("write", "download", (bound["outfile"],), guard=guard)
    def redirect_output(self, redirects, fact_start, payload, guard):
        # Native PowerShell redirection writes success output, not command input.
        for operator, value in redirects:
            success = operator.startswith(("1", "*", ">"))
            if (value.text is not None and value.text.casefold() in {"", "$null", "null", "nul"}
                    or is_null_device(self.paths.resolve(value, self.cwd), self.paths)):
                if operator.startswith("2") or operator.startswith("*"):
                    self.unresolved("PowerShell error output is discarded", "errors-suppressed", guard)
                if success:
                    self.facts[fact_start:] = [replace(f, flags=f.flags | {"output_consumed", "output_redirected"}) if f.kind in {"read", "invoke"} else f for f in self.facts[fact_start:]]
                continue
            stderr = operator.startswith("2")
            if stderr:
                self.unresolved("PowerShell error output is redirected", "errors-suppressed", guard)
            begin = len(self.facts)
            self.filesystem("write", "append" if ">>" in operator else "overwrite", (value,), payload=payload if success else None, guard=guard)
            if success:
                self.facts[fact_start:begin] = [replace(f, flags=f.flags | {"output_consumed", "output_redirected"}) if f.kind in {"read", "invoke"} else f for f in self.facts[fact_start:begin]]

    def interpreter(self, name, nodes, guard):
        self.interpreter_values(name, [self.value(c) for c in nodes], guard)
