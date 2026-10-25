"""Shared Windows fact construction and interpreter argument binding."""
from dataclasses import replace
from ..models import Fact, Value
from ..paths import style_for
from .value_flow import DEFAULT_LIMIT, ValueLimits, bounded_arguments, value as abstract_value


class WindowsBuilder:
    def __init__(self, cwd, env, *, shell, source="command", context="invoked_now", possible_values=DEFAULT_LIMIT, control_flow_steps=256, value_bytes=524288, trusted_scripts=()):
        self.limit = ValueLimits(possible_values, value_bytes)
        self.flow_steps = control_flow_steps
        self.choice_serial = 0
        self._cwd = abstract_value(cwd)
        self.env = {k.casefold(): v for k, v in env.items()}
        self.input_environment = set(self.env)
        self.paths = style_for(shell, cwd or "C:\\")
        self.shell, self.source, self.context = shell, source, context
        self.facts = []
        self.trusted_scripts = {self.paths.key(p) for p in trusted_scripts}

    @property
    def cwd(self):
        """The concrete location, or None when cwd has alternatives or is unknown."""
        return self._cwd.text

    @cwd.setter
    def cwd(self, value):
        self._cwd = abstract_value(value)

    def cwd_choices(self):
        """Every location the cwd may still denote, in a stable order."""
        if self._cwd.alternatives:
            return tuple(c.text for c in self._cwd.alternatives if c.text is not None)
        return () if self._cwd.text is None else (self._cwd.text,)

    def emit(self, kind, operation, values=(), flags=(), payload=None, guard="", targets=None, *, unresolved_variables=()):
        values = bounded_arguments(values, self.limit)
        # An unknown location still resolves absolute operands, so it is one
        # unnamed space rather than no space at all.
        spaces = self.cwd_choices() or (None,)
        if targets is None:
            # A location that is still a bounded set contributes one target per
            # surviving directory, so no branch loses its own finding.
            targets = tuple(dict.fromkeys(p for space in spaces for v in values
                                          if (p := self.paths.resolve(v, space)) is not None))
        if len(spaces) > 1:
            flags = frozenset(flags) | {"possible"}
        fact = Fact(kind, operation, targets=tuple(targets), values=tuple(values), flags=frozenset(flags),
                    payload=payload, guard=guard, source=self.source, context=self.context,
                    cwd=self.cwd, bindings=tuple(self.env.items()), shell=self.shell, unresolved_variables=tuple(unresolved_variables))
        self.facts.append(fact)
        if kind == 'execute' and 'direct_source' in flags and any(self.paths.key(p) in self.trusted_scripts for p in targets):
            # Skipped source cannot establish the parent's resulting state.
            self.env = {k: Value(None, 'trusted_script_state', (k,)) for k in self.env}
            if hasattr(self, 'variables'):
                self.variables = {k: v if k in {'home', 'true', 'false', 'null'} else Value(None, 'trusted_script_state', (k,)) for k, v in self.variables.items()}
                self.arrays = {}
            self.cwd = None
            if hasattr(self, "location_stacks"):
                self.location_stacks = None
        return fact

    def unresolved(self, reason, rule="unsupported-syntax", guard="", *, command_name=None, values=()):
        self.emit("unresolved", rule, values=values, payload=reason, guard=guard)
        if command_name is not None:
            self.facts[-1] = replace(self.facts[-1], command_name=command_name)

    def filesystem(self, kind, operation, values, flags=(), payload=None, guard="", *, unresolved_variables=()):
        return self.emit(kind, operation, values, flags, payload, guard, unresolved_variables=unresolved_variables)

    def interpreter_values(self, name, values, guard):
        """Bind launcher options only up to its executable source operand."""
        dialect = "cmd" if name.startswith("cmd") else "powershell"
        index = 0
        while index < len(values):
            option = (values[index].text or "").casefold()
            if option in {"-encodedcommand", "-enc", "-e", "-encodedarguments"} and dialect == "powershell":
                self.emit("content", "encoded-command", guard=guard)
                self.emit("execute", dialect, flags={"unknown_source"}, guard=guard)
                return
            if option in ({"/c", "/k"} if dialect == "cmd" else {"-command", "-c"}):
                tail = values[index + 1:]
                if dialect == "powershell" and len(tail) == 1 and tail[0].text == "-":
                    self.emit("execute", dialect, flags={"stdin_program"}, guard=guard)
                    return
                payload = " ".join(v.text for v in tail) if tail and all(v.text is not None for v in tail) else None
                self.emit("execute", dialect, flags={"inline_source"}, payload=payload, guard=guard)
                return
            if dialect == "powershell" and option in {"-file", "-f"}:
                value = values[index + 1] if index + 1 < len(values) else Value(None)
                self.emit("execute", dialect, flags={"stdin_program"} if value.text == "-" else {"direct_source"}, values=(value,), guard=guard)
                return
            simple = {"/d", "/s", "/q", "/a", "/u", "/v:off", "/e:on"} if dialect == "cmd" else {"-noprofile", "-noninteractive", "-nologo", "-sta", "-mta", "-noexit"}
            if option in simple:
                index += 1
                continue
            if dialect == "powershell" and option in {"-executionpolicy", "-windowstyle"} and index + 1 < len(values):
                index += 2
                continue
            if option.startswith(("-", "/")):
                self.unresolved(option, "unknown-option", guard)
                self.emit("execute", dialect, flags={"unknown_source"}, guard=guard)
                return
            self.emit("execute", dialect, flags={"direct_source"}, values=(values[index],), guard=guard)
            return
        self.emit("execute", dialect, guard=guard)
