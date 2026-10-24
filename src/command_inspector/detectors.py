"""Shared transparency rules and detector-requested evidence."""
from dataclasses import replace
import collections
import math
import re
from .catalog import RULES
from .shared.commands import split_interpreter_args
from .config import AnalyzerConfig
from .local_evidence import CachedEvidenceProvider, EvidenceAnswer, EvidenceStatus, MatchTargets, ReadFile, StatTarget, SummarizeDeletion
from .admin.windows import ADMIN_RULES
from .models import Fact, Finding, Level, Value
from .reporting import contains_secret, INJECTION
from .bash.semantics import SemanticBuilder
from .shared.value_flow import candidates
from .bash.syntax import BashFrontend, ParseBudgetExceeded
from .paths import style_for
from .python.syntax import PythonFrontend
from .python.semantics import PythonBuilder
from .javascript.semantics import JavaScriptBuilder
from .wildcards import selection_for
from .shared.null_devices import is_null_device
from .effort import EvidenceEffort, evidence_effort
from .shared.command_names import suspicious_command_name
from .shared.runtime_values import path_scope, language_hint


def raw_device(path: str) -> bool:
    if re.fullmatch(r"(?i)\\\\\.\\(?:PhysicalDrive\d+|[a-z]:)", path):
        return True
    # Android partition devices include by-name aliases and mapper/platform
    # paths. Classify the namespace lexically; never resolve/open a device link.
    if path.startswith("/dev/block/") and path != "/dev/block/":
        return True
    if re.fullmatch(r"/dev/(?:mapper/[^/]+|disk/by-(?:id|uuid|label|path|partuuid|partlabel)/[^/]+|loop\d+|md\d+|dm-\d+)", path):
        return True
    return bool(re.fullmatch(r"/dev/(?:sd[a-z]\d*|hd[a-z]\d*|vd[a-z]\d*|nvme\d+n\d+(?:p\d+)?|mmcblk\d+(?:p\d+)?|(?:r?disk)\d+(?:s\d+)?)", path))


def pattern_base(value: Value) -> str | None:
    """The literal directory a glob starts from, or ``None`` when it is not a glob.

    A pattern has no resolved target, but its lexical base is known before any
    expansion: ``/etc/*`` names ``/etc``. Without this, ``rm -rf /*`` looked like
    an ordinary unresolved value instead of a rooted recursive deletion.
    """
    if not value.pattern or not value.text:
        return None
    # Only an unrestricted final component establishes a whole-directory pattern.
    # A literal prefix like /etc in /etc? does not name the matched directory.
    if not value.text.endswith("/*") or re.search(r"[*?\[]", value.text[:-2]):
        return None
    return value.text[:-2] or "/"


class DetectorContext:
    def __init__(self, config: AnalyzerConfig, cwd: str, env: dict[str, str],
                 evidence: CachedEvidenceProvider, frontend: BashFrontend, command: str = "", *, shell="bash", frontends=None, effort=EvidenceEffort.FULL, workspace_root=None):
        self.config, self.workspace, self.env = config, workspace_root if workspace_root is not None else cwd, dict(env)
        self.evidence, self.frontend = evidence, frontend
        self.effort = evidence_effort(effort)
        self.command = command
        self.shell, self.frontends = shell, frontends or {}
        self.paths = style_for(shell, cwd)
        self.resolve_path = self.paths.resolve
        self.findings: list[Finding] = []
        self.secret_literals: set[str] = set()
        self.changed: set[str] = set()
        self.unknown_changes = False
        self.python_source_changes = {}
        self.python_unknown_sources = False
        self.inspection_context = "invoked_now"
        self.active_possible = ()
        self.inherited_possible = ()
        self.active_conditional = False
        self.inherited_conditional = False

    def emit(self, rule, title, fact, data=None, evidence=(), *, level=None):
        kind, levels, _ = RULES[rule]
        detail = title
        if fact.guard:
            detail += "; " + fact.guard
        if fact.context == "written_content":
            title = "Written script contains: " + title
        elif fact.context in {"direct_artifact", "defined_body"}:
            title = "Invoked source contains: " + title
        facts = {"operation": fact.operation, "source": fact.source, "context": fact.context}
        facts.update(data or {})
        possible = tuple(dict((*self.active_possible, *fact.possible_values)).items())
        sensitive = set(fact.sensitive_variables)
        for credential in fact.credential_values:
            sensitive.update(credential.variables)
            if credential.text and not credential.variables:
                # Inline expansion can replace the originating variable before
                # the inner parser sees it. Prefer explicit provenance; only
                # compare auth operands when that provenance has been lost.
                sensitive.update(name for name, values in possible if any(
                    value and value != "[REDACTED]" and value in credential.text for value in values))
        if "possible" in fact.flags or possible or self.active_conditional:
            facts["possible"] = True
            if possible:
                facts["possible_values"] = {name: ["[REDACTED]"] if name in sensitive else list(values) for name, values in possible}
            detail += "; one of the bounded possible command meanings"
        variables = set(fact.unresolved_variables) | {name for value in fact.values if value.text is None for name in value.variables}
        if variables or rule in {"unresolved-value", "unknown-command", "execution-content-unavailable",
                                 "delete-variable-unresolved", "write-variable-unresolved", "delete-recursion-unresolved"}:
            facts["variables"] = sorted(variables | set(facts.get("variables", ())))
        reasons = sorted({v.reason for v in fact.values if v.reason in {"possible_values_limit", "control_flow_limit", "value_bytes_limit"}})
        if reasons:
            facts["unresolved_reasons"] = reasons
        self.findings.append(Finding(rule, level if level is not None else Level[levels[0]], kind, title, detail, facts, tuple(evidence), frozenset(sensitive)))

    def in_workspace(self, path):
        return any(self.paths.inside(path, root) for root in (self.workspace, *self.config.additional_paths))

    def suspicious_command(self, fact, name):
        hint = suspicious_command_name(name, fact.shell)
        if hint is None:
            return False
        self.emit("unknown-command",
                  "Suspicious command name; possible quoting error or analyzer parsing issue: " + name,
                  fact, {"command": name, "command_resolved": True,
                         "reason": "suspicious_command_name", "name_pattern": hint}, level=Level.HIGH)
        return True

    def tool_invoked(self, fact, name):
        if not name:
            return False
        command = name
        name = style_for(fact.shell, fact.cwd or self.workspace).module.basename(name)
        from .known_tools import fallback_category
        category = fallback_category(name, self.config.known_tools, windows=fact.shell in {"powershell", "cmd"})
        if category is None:
            return False
        tool = name.casefold().removesuffix('.exe') if fact.shell in {"powershell", "cmd"} else name
        self.emit("tool-invoked", "Invokes unmodeled software: " + tool, fact,
                  {"command": command, "command_resolved": True, "reason": "behavior_not_modeled",
                   "tool": tool, "category": category, "behavior_modeled": False})
        # Its behavior is intentionally unknown; later file inspection cannot
        # assume that this application left the workspace unchanged.
        if self.invoked_effect(fact):
            self.unknown_changes = True
        return True

    def path_invocation(self, fact):
        from .shared.path_commands import command_basename, modeled_command
        from .known_tools import fallback_category
        command = fact.values[0].text
        self.suspicious_command(fact, command)
        windows = fact.shell in {"powershell", "cmd"}
        tool = command_basename(command, fact.shell)
        known = modeled_command(tool, windows=windows) or fallback_category(tool, self.config.known_tools, windows=windows) is not None
        paths = style_for(fact.shell, fact.cwd or self.workspace)
        target = paths.resolve(Value(command), fact.cwd)
        answer = (self.answer(StatTarget(target, "windows" if windows else "posix"))
                  if target and not self.may_have_changed(target) else
                  EvidenceAnswer(EvidenceStatus.UNAVAILABLE, reason="changed_earlier" if target else "unresolved_path", complete=False))
        data = {"command": command, "tool": tool, "target": target,
                "path_type": "absolute" if paths.absolute(command) else "relative",
                "evidence_status": answer.status.value, "evidence_reason": answer.reason}
        execution_possible = answer.status != EvidenceStatus.MISSING
        self.emit("command-via-path" if known else "executable-via-path",
                  "Uses " + data["path_type"] + " path to access " + tool if known else "Runs executable: " + command,
                  fact, data)
        if answer.status == EvidenceStatus.MISSING:
            self.emit("execute-target-missing", "Tries to run a nonexistent file: " + command, fact, data)
        elif answer.status == EvidenceStatus.AVAILABLE and answer.complete:
            executable = answer.data.get("executable")
            if answer.data.get("kind") in {"directory", "special"}:
                executable = False
            # Windows execution uses file associations/PATHEXT, never POSIX mode
            # bits from the Linux host. Only supplied facts establish other suffixes.
            if windows and executable is None and answer.data.get("kind") == "file":
                import ntpath
                extension = ntpath.splitext(command)[1].casefold()
                pathext = {k.casefold(): v for k, v in (*self.env.items(), *fact.bindings)}.get("pathext")
                if pathext is not None:
                    from .shared.value_flow import candidates
                    possible = [v.text for v in candidates(pathext)]
                    if all(v is not None for v in possible):
                        answers = {extension in {e.casefold() for e in v.split(";") if e} for v in possible}
                        executable = answers.pop() if len(answers) == 1 else None
                elif extension in {".exe", ".com"}:
                    executable = True
            if executable is False:
                execution_possible = False
                self.emit("execute-target-not-executable", "Tries to run a non-executable file: " + command, fact, data)
        if not known and execution_possible and self.invoked_effect(fact):
            self.unknown_changes = True

    def is_protected(self, path):
        roots = self.config.protected_directories
        if self.paths.windows and roots == AnalyzerConfig().protected_directories:
            drive = self.paths.module.splitdrive(path)[0]
            roots = (drive + "\\", drive + "\\Windows", drive + "\\Windows\\System32")
        return self.paths.key(path) in {self.paths.key(entry) for entry in roots}

    #: Shapes whose meaning cannot be established by reading them.
    _OPAQUE_SHAPES = (
        (re.compile(r"(?i)\b(?:FromBase64String|Invoke-Expression|Invoke-Command)\b|(?:^|[|;&]\s*)iex(?:\s|$)"), "self-evaluating command"),
        (re.compile(r"(?i)\bbase64\b[^|]*\|[^|]*\b(?:ba|z)?sh\b"), "decoded payload piped to a shell"),
        (re.compile(r"""(?i)\b(?:eval|exec)\s*\(?\s*["'][A-Za-z0-9+/=]{40,}"""), "evaluated literal blob"),
    )
    _OPAQUE_BLOB = re.compile(r"^[A-Za-z0-9+/=_-]{80,}$")

    def check_opaque_payload(self, text: str, fact: Fact):
        """Report an argument or source whose content cannot be reviewed by reading it.

        Cheap shape checks only: this is a readability finding, not a decoder.
        """
        for pattern, label in self._OPAQUE_SHAPES:
            if pattern.search(text):
                self.emit("obfuscated-payload", "Opaque payload cannot be reviewed: " + label, fact,
                          {"reason": label})
                return
        for token in text.split():
            if len(token) < 80 or not self._OPAQUE_BLOB.match(token):
                continue
            if token.count(".") > 0 or token.count("/") > 1:
                continue  # a long path, not an encoded blob
            alphabet = collections.Counter(token)
            if len(alphabet) < 4 or -sum(n / len(token) * math.log2(n / len(token))
                                         for n in alphabet.values()) < 1.5:
                continue  # a long literal, not encoded data
            self.emit("obfuscated-payload", "Opaque payload cannot be reviewed: long encoded blob", fact,
                      {"reason": "long_encoded_blob", "length": len(token)})
            return

    def answer(self, request):
        path = request.base if isinstance(request, MatchTargets) else request.path
        if self.may_have_changed(path):
            return EvidenceAnswer(EvidenceStatus.UNAVAILABLE, reason="changed_earlier", complete=False)
        return self.evidence.answer(request, effort=self.effort)

    def invoked_effect(self, fact):
        return (fact.context in {"invoked_now", "direct_artifact"}
                or fact.context == self.inspection_context and fact.context in {"written_content", "defined_body"})

    def python_mutations(self, facts, depth):
        """Visible effect lookahead only: no evidence, imports or execution.

        Python enumerates events without source order. Include modeled writes
        behind literal inline code and native argv before any content reads.
        File-backed code still belongs to normal effort-controlled inspection.
        """
        from .shared.value_flow import expand_fact
        for original in facts:
            if not self.invoked_effect(original):
                continue
            for fact in expand_fact(original, self.config.possible_values, paths=self.paths):
                if fact.kind in {"write", "delete", "transfer", "invalidate"}:
                    yield fact
                    continue
                if depth >= self.config.inline_depth:
                    continue
                children = ()
                if fact.kind == "invoke":
                    from .shared.commands import describe, wrapped_command_name
                    cwd = None if 'unknown_cwd' in fact.flags else fact.cwd
                    if 'override_cwd' in fact.flags:
                        cwd = self.resolve_path(Value(fact.payload), cwd)
                    bindings = dict(fact.bindings)
                    for flag in fact.flags:
                        if flag.startswith('unset_binding:'):
                            bindings.pop(flag.split(':', 1)[1], None)
                    children = tuple(replace(child, cwd=cwd, shell=fact.shell, context=fact.context, source=fact.source,
                                             python_event=fact.python_event,
                                             bindings=child.bindings if 'clear_bindings' in child.flags else tuple((bindings | dict(child.bindings)).items()))
                                     for child in describe(wrapped_command_name(fact), fact.values, cwd, shell=fact.shell))
                elif fact.kind == "execute" and fact.operation in {'powershell', 'cmd'} and 'inline_source' in fact.flags and fact.payload is not None:
                    children = (replace(fact, kind='inline', source=fact.source + ':inline'),)
                elif fact.kind == "execute" and fact.operation not in {'artifact', 'powershell', 'cmd'}:
                    language = self.interpreter_language(fact.operation)
                    options, unknown, _ = split_interpreter_args([v.text for v in fact.values], language)
                    code = next((value for _, kind, value in options if kind == 'code'), None)
                    if not unknown and code is not None:
                        children = (replace(fact, kind='inline', operation=language, payload=code, source=fact.source + ':inline'),)
                elif fact.kind == "inline" and fact.payload is not None:
                    from .pwsh.semantics import PowerShellBuilder
                    from .cmd.semantics import CmdBuilder
                    language = fact.operation
                    frontend = self.frontend if language in {'shell', 'bash'} else self.frontends.get(language)
                    if language == 'python':
                        from .python.syntax import PythonFrontend
                        frontend = PythonFrontend()
                    if frontend is None:
                        continue
                    try:
                        if len(fact.payload.encode('utf-8')) > self.config.file_bytes:
                            yield replace(fact, kind='invalidate', targets=(), values=(Value(None, 'python_effect_lookahead_limit'),))
                            continue
                        kwargs = {'mode': next((flag.split(':', 1)[1] for flag in fact.flags if flag.startswith('python_mode:')), 'exec')} if language == 'python' else {}
                        parsed = frontend.parse(fact.payload, self.config.source_nodes, **kwargs)
                        if parsed.root is None:
                            continue
                        builder = {'shell': SemanticBuilder, 'bash': SemanticBuilder, 'powershell': PowerShellBuilder,
                                   'cmd': CmdBuilder, 'python': PythonBuilder, 'javascript': JavaScriptBuilder}.get(language)
                        if builder is None:
                            continue
                        kwargs = {'paths': self.paths, 'python_bindings': fact.python_bindings} if language == 'python' else {'paths': self.paths, 'javascript_bindings': fact.javascript_bindings} if language == 'javascript' else {}
                        children = builder(fact.cwd, dict(fact.bindings), context=fact.context, source=fact.source,
                                           possible_values=self.config.possible_values, control_flow_steps=self.config.control_flow_steps,
                                           value_bytes=self.config.value_bytes, **kwargs).build(parsed.root)
                    except (ParseBudgetExceeded, RecursionError):
                        children = (replace(fact, kind='invalidate', targets=(), values=(Value(None, 'python_effect_lookahead_limit'),)),)
                if children:
                    yield from self.python_mutations(children, depth + 1)

    def run(self, facts: tuple[Fact, ...], cwd: str | None, *, depth=0, effort=None, context=None):
        previous, previous_context = self.effort, self.inspection_context
        previous_possible = self.active_possible, self.inherited_possible, self.active_conditional, self.inherited_conditional
        self.inherited_possible = self.active_possible
        self.inherited_conditional = self.active_conditional
        isolated = context in {"written_content", "defined_body"}
        before = (self.changed.copy(), self.unknown_changes) if isolated else None
        self.inspection_context = context or previous_context
        previous_python_sources = self.python_source_changes, self.python_unknown_sources
        self.python_source_changes = {path: events.copy() for path, events in self.python_source_changes.items()}
        for fact in self.python_mutations(tuple(f for f in facts if 'python_events' in f.flags), depth):
            if "create_if_missing" in fact.flags:
                continue
            values = fact.values + (fact.transfer_sources if fact.kind == "transfer" and fact.operation == "move" else ())
            for value in values:
                for candidate in candidates(value):
                    path = self.resolve_path(candidate, fact.cwd)
                    selection = selection_for(candidate, fact.cwd, fact.shell, self.paths) if candidate.pattern else None
                    if path is not None or selection is not None:
                        key = self.paths.key(path if path is not None else selection.base)
                        event = (fact.python_event or (fact.source, id(fact)), fact.kind, fact.operation)
                        self.python_source_changes.setdefault(key, set()).add(event)
                    else:
                        self.python_unknown_sources = True
        self.effort = previous if effort is None else evidence_effort(effort)
        try:
            self._run(facts, cwd, depth=depth)
        finally:
            self.active_possible, self.inherited_possible, self.active_conditional, self.inherited_conditional = previous_possible
            self.effort = previous
            self.inspection_context = previous_context
            self.python_source_changes, self.python_unknown_sources = previous_python_sources
            if isolated:
                self.changed, self.unknown_changes = before

    def _run(self, facts, cwd, *, depth, check_command=True):
        if check_command and depth == 0 and self.command and self.shell == "bash":
            self.check_opaque_payload(self.command, Fact("content", "command"))
        from .shared.value_flow import expand_fact
        expanded = []
        for index, item in enumerate(facts):
            rows = expand_fact(item, self.config.possible_values, paths=self.paths)
            expanded.extend(replace(row, choice_path=((-index - 1, case),) + row.choice_path) if len(rows) > 1 else row for case, row in enumerate(rows))
        cursor = 0
        while cursor < len(expanded):
            fact = expanded[cursor]
            cursor += 1
            if fact.choice_path:
                group = fact.choice_path[0][0]
                alternatives = [fact]
                while cursor < len(expanded) and expanded[cursor].choice_path and expanded[cursor].choice_path[0][0] == group:
                    alternatives.append(expanded[cursor])
                    cursor += 1
                before_changes, before_unknown = self.changed.copy(), self.unknown_changes
                changed, unknown = set(before_changes), before_unknown
                from itertools import groupby
                last_changes, last_unknown = set(), False
                outcomes = {}
                for case, arm in groupby(alternatives, key=lambda f: f.choice_path[0][1]):
                    arm = tuple(arm)
                    self.changed, self.unknown_changes = before_changes.copy(), before_unknown
                    predecessors = {predecessor for f in arm for key, cases in f.choice_predecessors if key == group for predecessor in cases}
                    for predecessor in predecessors:
                        prior_changes, prior_unknown = outcomes[predecessor]
                        self.changed.update(prior_changes)
                        self.unknown_changes |= prior_unknown
                    if not any(key == group for f in arm for key, _ in f.choice_predecessors) and any(group in f.choice_fallthrough for f in arm):
                        self.changed.update(last_changes)
                        self.unknown_changes |= last_unknown
                    self._run(tuple(replace(f, choice_path=f.choice_path[1:]) for f in arm), cwd, depth=depth, check_command=False)
                    last_changes, last_unknown = self.changed.copy(), self.unknown_changes
                    outcomes[case] = last_changes, last_unknown
                    changed.update(self.changed)
                    unknown |= self.unknown_changes
                self.changed, self.unknown_changes = changed, unknown
                continue
            self.active_possible = tuple(dict((*self.inherited_possible, *fact.possible_values)).items())
            self.active_conditional = "possible" in fact.flags or self.inherited_conditional
            invocation_cwd = fact.cwd
            if fact.kind == "content" and fact.operation == "encoded-command":
                self.emit("obfuscated-payload", "Opaque payload cannot be reviewed: encoded command argument", fact,
                          {"reason": "encoded command argument"})
            elif fact.kind == "content" and fact.operation == "hardcoded-secret":
                self.secret_literals.update(v.text for v in fact.credential_values if v.text)
                self.emit("hardcoded-secret", "Source contains a hard-coded credential", fact,
                          {"language": fact.shell, "variables": list(fact.targets),
                           "line": int(next(flag[5:] for flag in fact.flags if flag.startswith("line:")))})
            elif fact.kind == 'output':
                secret_names = [n for n in fact.targets if re.search(r'(?i)(password|passwd|secret|private.?key|access.?key|api.?key|token|credential)', n)]
                secret_values = [v for v in fact.values if v.text and contains_secret(v.text)]
                if secret_names or secret_values:
                    self.secret_literals.update(v.text for v in fact.values if v.text and (secret_values or set(v.variables) & set(secret_names)))
                    self.emit('credentials-exposed', 'Outputs credential-bearing content', fact,
                              {'variables': sorted(secret_names or fact.targets)})
                else:
                    normalize = str.casefold if fact.shell in {'cmd', 'powershell'} else str
                    quiet = {normalize(n) for n in self.config.quiet_output_variables}
                    names = [n for n in fact.targets if normalize(n.removeprefix('env:')) not in quiet]
                    if names:
                        self.emit('environment-value-output', 'Outputs a caller-supplied environment value', fact, {'variables': names})
            elif fact.kind == "unresolved":
                if (fact.operation == "unknown-command" and not fact.command_path
                        and self.suspicious_command(fact, fact.command_name)):
                    continue
                if fact.operation == "unknown-command" and self.tool_invoked(fact, fact.command_name):
                    continue
                if fact.operation == "unknown-command" and fact.command_path:
                    from .shared.path_commands import command_basename, modeled_command
                    if not modeled_command(command_basename(fact.command_path, fact.shell), windows=fact.shell in {"powershell", "cmd"}):
                        continue
                if fact.operation in RULES:
                    title = fact.payload or RULES[fact.operation][2]
                    data = None
                    if fact.operation == "unknown-command":
                        title = "Command meaning is unresolved: " + title
                        data = {"command": fact.command_name, "command_resolved": fact.command_name is not None,
                                "reason": fact.payload if fact.payload != fact.command_name else "behavior_not_modeled"}
                    elif fact.operation == "unknown-option":
                        title = "Unsupported command option: " + title
                    self.emit(fact.operation, title, fact, data)
            elif fact.kind == "invalidate":
                if self.invoked_effect(fact):
                    self.changed.update(self.paths.key(p) for p in fact.targets)
                    if not fact.targets or any(self.resolve_path(v, fact.cwd) is None for v in fact.values):
                        self.unknown_changes = True
            elif fact.kind == "inline":
                if fact.payload is None:
                    self.emit("execution-content-unavailable", "Inline code could not be resolved", fact)
                else:
                    self.inspect(fact.payload, fact.operation, fact.source, fact.context,
                                 invocation_cwd, depth + 1, dict(fact.bindings), python_bindings=fact.python_bindings, javascript_bindings=fact.javascript_bindings,
                                 python_mode=next((flag.split(':', 1)[1] for flag in fact.flags if flag.startswith('python_mode:')), 'exec'))
            elif fact.kind == 'credential_input':
                # The sink establishes the role even for an ordinary word that
                # has no token/password shape. Never serialize the password.
                payload = fact.stdin_payload
                if payload is not None and payload.split('\n', 1)[0].rstrip('\r'):
                    password = payload.split('\n', 1)[0].rstrip('\r')
                    self.emit('credentials-exposed', 'Visible stdin supplies a password to sudo',
                              replace(fact, credential_values=(Value(password),)),
                              {'consumer': 'sudo', 'channel': 'stdin'})
            elif fact.kind == "invoke":
                if 'authentication_stdin' in fact.flags:
                    fact = replace(fact, stdin_payload=None, stdin_payload_value=None, stdin_sources=())
                if depth >= self.config.inline_depth:
                    self.emit("unreadable-payload", "Wrapped command exceeds the inspection nesting budget", fact)
                    continue
                from .shared.commands import describe, wrapped_command_name
                nested_cwd = None if "unknown_cwd" in fact.flags else invocation_cwd
                if 'override_cwd' in fact.flags:
                    nested_cwd = self.resolve_path(Value(fact.payload), invocation_cwd)
                bindings = dict(fact.bindings)
                for flag in fact.flags:
                    if flag.startswith('unset_binding:'):
                        bindings.pop(flag.split(':', 1)[1], None)
                nested = []
                command_name = wrapped_command_name(fact)
                described = describe(command_name, fact.values, nested_cwd, shell=fact.shell)
                for child in described:
                    child_bindings = dict(child.bindings) if "clear_bindings" in child.flags else bindings | dict(child.bindings)
                    targets = tuple(p for v in child.values if (p := self.resolve_path(v, nested_cwd)) is not None) if child.kind in {"read", "write", "delete"} else child.targets
                    nested.append(replace(child, targets=targets, source=fact.source, context=fact.context,
                                          cwd=nested_cwd, shell=fact.shell, bindings=tuple(child_bindings.items()),
                                          guard=child.guard or fact.guard, flags=child.flags | (fact.flags & {"output_consumed", "output_redirected", "selection_uncertain"}) |
                                          (fact.flags & {"stdin_source", "pipeline_stdin", "stdin_redirected"} if child.kind in {"execute", "invoke", "credential_input"} else set()),
                                          stdin_payload=(None if "consumes_stdin" in fact.flags else fact.stdin_payload)
                                          if "stdin_source" in fact.flags and child.kind in {"execute", "invoke", "credential_input"} else child.stdin_payload,
                                          stdin_sources=(fact.stdin_sources if "consumes_stdin" not in fact.flags else ())
                                          if "stdin_source" in fact.flags and child.kind in {"execute", "invoke", "credential_input"} else child.stdin_sources))
                if fact.stdin_sources:
                    from .shared.commands import route_file_payload, stdin_network_sink
                    for index, child in enumerate(nested):
                        if stdin_network_sink(child):
                            nested = route_file_payload(nested, index, fact.stdin_sources)
                self.run(tuple(nested), nested_cwd, depth=depth + 1)
            elif fact.kind == "sql":
                self.sql(fact)
            elif fact.kind == "sql_source":
                self.sql_source(fact, invocation_cwd, depth)
            elif fact.kind == "read":
                self.read(fact)
            elif fact.kind == "write":
                self.write(fact, invocation_cwd, depth)
            elif fact.kind == "transfer":
                self.transfer(fact, invocation_cwd, depth)
            elif fact.kind == "delete":
                self.delete(fact)
            elif fact.kind == "execute":
                if 'authentication_stdin' in fact.flags:
                    fact = replace(fact, stdin_payload=None, stdin_payload_value=None, stdin_sources=())
                bindings = {} if "clear_bindings" in fact.flags else dict(fact.bindings)
                if "reset_environment" in fact.flags:
                    kept = {flag.split(":", 1)[1] for flag in fact.flags if flag.startswith("keep_binding:")}
                    bindings = {name: value for name, value in bindings.items() if name in kept}
                for flag in fact.flags:
                    if flag.startswith("unset_binding:"):
                        bindings.pop(flag.split(":", 1)[1], None)
                self.execute(replace(fact, bindings=tuple(bindings.items())),
                             None if "unknown_cwd" in fact.flags else invocation_cwd, depth)
            elif fact.kind == "path_invocation":
                self.path_invocation(fact)
            elif fact.kind == "execution":
                self.emit("privilege-escalation", "Requests a user-context switch" if fact.operation == "user-switch" else "Requests administrator privileges", fact,
                          {"target_user": fact.targets[0] if fact.targets else None} if fact.operation == "user-switch" else None)
            elif fact.kind == "assignment":
                self.emit("readonly-assignment-failed",
                          "Assignment may be rejected by a read-only binding" if "possible" in fact.flags else "Assignment to a read-only binding was rejected; the previous value remains",
                          fact, {"variables": list(fact.targets)})
            elif fact.kind == "environment":
                normalize = str.casefold if fact.shell in {'cmd', 'powershell'} else str
                quiet = {normalize(n) for n in self.config.quiet_environment_variables}
                if fact.targets and all(normalize(n.removeprefix('env:')) in quiet for n in fact.targets):
                    continue
                self.emit("environment-modified", "Changes the shell environment: " + ", ".join(fact.targets), fact,
                          {"variables": list(fact.targets)})
            elif fact.kind == "network":
                credential = (contains_secret(fact.payload or "")
                              or bool(re.search(r"https?://[^/@\s]+:[^/@\s]+@", fact.payload or ""))
                              or bool(fact.flags & {"-u", "--user", "credential_payload"}))
                if credential and "credentials-sent" not in self.config.disabled_rules:
                    self.emit("credentials-sent", "Sends credentials in a network request", fact, {"destinations": list(fact.targets)})
                else:
                    rule = "publish-risk" if "local_file_payload" in fact.flags else "download-content" if fact.operation == "download" else "network-request"
                    if rule in self.config.disabled_rules:
                        rule = "network-request"
                    title = "May publish local files or artifacts to a remote destination" if rule == "publish-risk" else "Downloads and runs code whose contents are unavailable" if "to_interpreter" in fact.flags else "Downloads content" if rule == "download-content" else "Makes a network request"
                    data = {"destinations": list(fact.targets)}
                    if "git_clone" in fact.flags:
                        source = fact.values[0].text
                        title = "Downloads Git repository content" if source is not None else "May download Git repository content from an unresolved source"
                        data.update({"tool": "git", "repository": source, "source_resolved": source is not None,
                                     "download_target": self.resolve_path(fact.values[1], invocation_cwd),
                                     "bundle_uri": "bundle_uri" in fact.flags})
                    if rule == "publish-risk":
                        data["destination_resolved"] = bool(fact.targets)
                        if "file_sources" in fact.flags:
                            data["sources"] = [v.text for v in fact.values]
                            paths = [self.resolve_path(v, invocation_cwd) if v.text != "-" else None for v in fact.values]
                            data["source_paths"] = [p for p in paths if p is not None]
                            data["sources_resolved"] = bool(paths) and all(p is not None for p in paths)
                    self.emit(rule, title, fact, data)
            elif fact.kind in {"system", "git"}:
                if fact.operation == "git-config-modified":
                    scope = next((f[6:] for f in fact.flags if f.startswith("scope:")), "local")
                    if scope == "local" and any((k == "GIT_CONFIG" if fact.shell == "bash" else k.casefold() == "git_config") for k, _ in fact.bindings):
                        scope = "file"
                    importance = "sensitive" if "sensitive" in fact.flags else "minor" if "minor" in fact.flags else "important"
                    # Explicit config files have unknown scope; do not infer a
                    # repository/global location from a filename alone.
                    broad = scope in {"global", "system", "file"}
                    level = Level.HIGH if importance == "sensitive" or broad and importance == "important" else Level.MEDIUM if broad or importance == "important" else Level.LOW
                    self.emit(fact.operation, f"Changes {importance} Git configuration ({scope})", fact,
                              {"keys": list(fact.targets), "scope": scope, "importance": importance,
                               "action": fact.payload or "set"}, level=level)
                    continue
                titles = {"git-push": "Pushes commits to a remote", "git-config-modified": "Changes Git configuration",
                          "git-history-rewrite": "Rewrites or deletes remote Git refs" if "remote_history" in fact.flags else "Rewrites local Git history",
                          "docker-change": "Changes Docker resources: " + (fact.payload or "update"),
                          "git-reset-state-unavailable": "Hard reset may discard local work; repository state is unavailable",
                          "package-install": "Installs software packages", "service-change": f"Changes service/task state: {fact.payload or 'update'}",
                          "package-change": fact.payload or "Changes packages or environments",
                          "system-settings-change": fact.payload or "Changes system settings",
                          "filesystem-selection-delete": fact.payload or "Deletes filtered search results",
                          "runtime-code-loading": "Compiles or loads executable .NET code",
                          "force-process-termination": ("Forcibly terminates " if fact.payload == "force" else "Terminates ")
                                                     + ", ".join(fact.targets),
                          "machine-power-change": "Requests shutdown or reboot", "unmount-drive": "Unmounts a filesystem"}
                data = {"search_roots": list(fact.targets), "selection_resolved": False} if fact.operation == "filesystem-selection-delete" else {"targets": list(fact.targets)}
                if fact.operation in {"service-change", "docker-change"}:
                    data["action"] = fact.payload or "update"
                    data["targets_resolved"] = all(v.text is not None for v in fact.values)
                    data["scope"] = sorted(f for f in fact.flags if f.startswith(("scope:", "--root:", "--host:", "--machine:")))
                    data["options"] = sorted(f for f in fact.flags if f.startswith("-") and ":" not in f)
                    if fact.targets:
                        titles[fact.operation] += ": " + ", ".join(fact.targets)
                if fact.operation == "git-history-rewrite":
                    data["history_scope"] = "remote" if "remote_history" in fact.flags else "local"
                    data["refspecs"] = [v.text for v in fact.values]
                    data["options"] = sorted(f for f in fact.flags if f.startswith("-"))
                self.emit(fact.operation, titles.get(fact.operation, ADMIN_RULES.get(fact.operation, (None, fact.operation))[1]), fact, data)
            elif fact.kind == "device":
                for path in fact.targets:
                    if raw_device(path):
                        self.emit("raw-device-" + fact.operation, ("Reads raw disk " if fact.operation == "read" else "Writes raw disk ") + path, fact, {"target": path})
                        if fact.operation == "write" and self.invoked_effect(fact):
                            self.unknown_changes = True
                    else:
                        operation = "ingest" if fact.operation == "read" else "overwrite"
                        ordinary = replace(fact, kind="read" if fact.operation == "read" else "write", operation=operation, targets=(path,))
                        if fact.operation == "read":
                            # dd streams binary content; location only until routing is modeled.
                            self.location(ordinary)
                        else:
                            self.write(ordinary, invocation_cwd, depth)
            elif fact.kind == "permissions" and fact.operation == "777":
                self.emit("permissions-too-broad", "Grants read, write, and execute access to everyone", fact, {"targets": list(fact.targets), "mode": "777"})

    def location(self, fact):
        bounded_patterns = set()
        for value in fact.values:
            if fact.kind == 'read' and value.pattern:
                selection = selection_for(value, fact.cwd, fact.shell, self.paths)
                if selection is not None:
                    bounded_patterns.add(value)
                    if not self.in_workspace(selection.base):
                        self.emit('read-outside-workspace', 'Reads a selection outside the workspace', fact,
                                  {'scope_root': selection.base, 'pattern': value.text, 'target_resolved': False})
            scope = path_scope(value, self.paths, fact.cwd)
            if scope is not None:
                if not self.in_workspace(scope):
                    self.emit('read-outside-workspace' if fact.kind == 'read' else 'write-outside-workspace',
                              'Runtime target is within ' + scope + ' outside the workspace', fact,
                              {'scope_root': scope, 'target_resolved': False, 'path_basis': 'constrained_runtime'})
                if fact.kind == 'read' and fact.operation == 'ingest':
                    self.emit('ingestion-inspection-incomplete', 'Runtime filename is unknown; content cannot be inspected', fact,
                              {'scope_root': scope, 'target_resolved': False})
        for path in fact.targets:
            allowed_write = fact.kind == "write" and self.paths.key(path) in {self.paths.key(p) for p in self.config.allowed_write_paths}
            if not self.in_workspace(path) and not allowed_write:
                self.emit("read-outside-workspace" if fact.kind == "read" else "write-outside-workspace",
                          ("Reads " if fact.kind == "read" else "Writes ") + path + " outside the workspace", fact,
                          {"target": path, "path_basis": "lexical"})
        if any(v not in bounded_patterns and self.resolve_path(v, fact.cwd) is None and path_scope(v, self.paths, fact.cwd) is None for v in fact.values):
            self.emit("unresolved-value", "File target cannot be resolved from the supplied values", fact)

    def match(self, fact, value):
        selection = selection_for(value, fact.cwd, fact.shell, self.paths)
        if selection is None:
            return EvidenceAnswer(EvidenceStatus.UNAVAILABLE, reason="unresolved_pattern_base", complete=False)
        if "selection_unmodeled" in fact.flags:
            return EvidenceAnswer(EvidenceStatus.UNAVAILABLE, reason="unsupported_selection_parameters", complete=False)
        if fact.shell == "python":
            from .wildcards import unsupported_pattern
            problem = unsupported_pattern(selection.pattern, selection.profile)
            if problem:
                return EvidenceAnswer(EvidenceStatus.UNAVAILABLE, reason=problem, complete=False)
        if fact.shell == "bash" and "[" in selection.pattern and any(
                name in dict(fact.bindings) and any(v.text not in {"C", "POSIX"} for v in candidates(dict(fact.bindings)[name]))
                for name in ("LC_ALL", "LC_COLLATE", "LANG")):
            return EvidenceAnswer(EvidenceStatus.UNAVAILABLE, reason="locale_pattern_not_modeled", complete=False)
        if self.unknown_changes or any(self.paths.inside(p, selection.base) or self.paths.inside(selection.base, p)
                                       for p in self.changed):
            return EvidenceAnswer(EvidenceStatus.UNAVAILABLE, reason="may_have_changed_earlier", complete=False)
        recursive = fact.shell == "cmd" and "files_only" in fact.flags and "-r" in fact.flags
        answer = self.answer(MatchTargets(selection.base, selection.pattern,
                                     self.config.directory_entries, self.config.wildcard_matches,
                                     selection.profile, selection.windows, recursive,
                                     "files_only" in fact.flags))
        # Remove-Item's recursive extension matching depends on host/version.
        if fact.shell == "powershell" and "-r" in fact.flags and selection.pattern != "*":
            return replace(answer, complete=False, reason="powershell_recursive_pattern_semantics_unavailable")
        return answer

    def deletion_rule(self, path, force, recursive):
        if force and recursive and self.is_protected(path):
            rule = "delete-protected-root"
        elif force and recursive and self.paths.key(path) == self.paths.key(self.workspace):
            rule = "delete-workspace-root"
        else:
            rule = "delete-inside-workspace" if self.in_workspace(path) else "delete-outside-workspace"
        if rule in self.config.disabled_rules:
            rule = "delete-inside-workspace" if self.in_workspace(path) else "delete-outside-workspace"
        return rule

    def delete_pattern(self, fact, value, recursive, force, protected_base=None):
        answer = self.match(fact, value)
        paths = answer.data.get("paths", [])
        complete = answer.complete and answer.status in {EvidenceStatus.AVAILABLE, EvidenceStatus.MISSING}
        scope = {"inside" if self.in_workspace(p) else "outside" for p in paths}
        observed_scope = "mixed" if len(scope) > 1 else next(iter(scope), "unknown")
        data = {"pattern": value.text, "matched_targets": paths, "match_count": len(paths),
                "matches_complete": complete, "scope": observed_scope if complete else "unknown",
                "observed_scope": observed_scope,
                "selection_profile": fact.shell,
                "recursive": recursive, "force": force, "path_basis": "lexical"}
        evidence = [{"source": value.text or "", "status": answer.status.value,
                     "complete": complete, "reason": answer.reason, **answer.data}]
        counts = {"files": 0, "directories": 0}
        if self.effort is EvidenceEffort.FULL:
            counts["logical_bytes"] = 0
        affected, counts_complete, paths_complete = set(), complete, complete
        count_reasons = set()
        # Deduplicate overlapping matched directories before counting descendants.
        roots = []
        for path in sorted(paths, key=lambda p: (len(p), self.paths.key(p))):
            if recursive and any(self.paths.inside(path, root) for root in roots):
                continue
            roots.append(path)
        for path in roots:
            count = self.answer(SummarizeDeletion(path, self.config.directory_entries,
                                         recursive, "files_only" in fact.flags, self.config.wildcard_matches))
            for name in counts:
                counts[name] += count.data.get(name, 0)
            affected.update(count.data.get("affected_paths", []))
            counts_complete &= count.complete and count.status == EvidenceStatus.AVAILABLE
            paths_complete &= count.data.get("affected_paths_complete", False)
            if not count.complete or count.status != EvidenceStatus.AVAILABLE:
                count_reasons.add(count.reason or count.status.value)
        ordered = sorted(affected, key=self.paths.key)
        paths_complete &= len(ordered) <= self.config.wildcard_matches
        data.update({**counts, "counts_complete": counts_complete,
                     "affected_paths": ordered[:self.config.wildcard_matches],
                     "affected_paths_complete": paths_complete and counts_complete,
                     "count_reasons": sorted(count_reasons)})
        if protected_base and "delete-protected-root" not in self.config.disabled_rules:
            rule = "delete-protected-root"
            data["target"] = protected_base
            title = "Recursively deletes matching entries under " + protected_base
        elif not complete:
            rule = "delete-variable-unresolved"
            data.update({"patterns": [value.text], "variables": list(value.variables), "reason": answer.reason})
            title = "Deletion pattern has incomplete or unavailable matches: " + (value.text or "")
            # Concrete critical matches still retain their higher-level finding.
            severe = [p for p in paths if self.deletion_rule(p, force, recursive) in {"delete-protected-root", "delete-workspace-root"}]
            if severe:
                rule = max((self.deletion_rule(p, force, recursive) for p in severe), key=lambda r: Level[RULES[r][1][0]])
                title = "Deletion pattern includes a critical directory; matches are incomplete: " + (value.text or "")
        elif not paths:
            rule = "delete-target-missing"
            title = "Deletion pattern currently matches no entries: " + (value.text or "")
        else:
            rule = max((self.deletion_rule(p, force, recursive) for p in paths), key=lambda r: Level[RULES[r][1][0]])
            title = ("Recursively deletes " if recursive else "Deletes ") + str(len(paths)) + " matched targets: " + (value.text or "")
        if not counts_complete:
            title += "; affected-file counts incomplete" if paths else "; scope count unavailable" if not complete else ""
        elif not paths_complete:
            title += "; affected-path list truncated"
        self.emit(rule, title, fact, data, evidence)
        return paths, complete

    def delete(self, fact):
        changed = set()
        recursive = bool(fact.flags & {"-r", "-R", "--recursive"})
        # `unconditional` marks an operation with no prompt and no undo, such as
        # Python's shutil.rmtree, whose target cannot be skipped by permissions.
        force = bool(fact.flags & {"-f", "--force", "unconditional"})
        if "recursion_unresolved" in fact.flags:
            self.emit("delete-recursion-unresolved", "Directory deletion recursion is unresolved", fact,
                      {"targets": list(fact.targets), "recursive": None, "force": force})
        if not fact.values or any(value.text == "" for value in fact.values):
            self.emit("delete-target-missing", "Deletion has no nonempty target operand", fact)
            nonempty = tuple(v for v in fact.values if v.text != "")
            fact = replace(fact, targets=tuple(p for v in nonempty if (p := self.resolve_path(v, fact.cwd)) is not None),
                           values=nonempty)
        changed.update(fact.targets)
        if "failed_assignment" in fact.flags:
            self.emit("delete-after-failed-assignment", "Deletion uses a retained value after a rejected assignment", fact,
                      {"targets": list(fact.targets), "variables": sorted({n for v in fact.values for n in v.variables})},
                      level=Level.HIGH if "failed_assignment_unknown" in fact.flags else Level.BLOCK)
        rooted = []
        for value in fact.values:
            lexical = replace(value, text=value.text.replace("\\", "/")) if self.paths.windows and value.text else value
            if fact.shell == "cmd" and "files_only" in fact.flags and lexical.text and lexical.text.endswith("/*.*"):
                lexical = replace(lexical, text=lexical.text[:-3] + "*")
            base = pattern_base(lexical)
            if base is None:
                continue
            if self.paths.windows and re.fullmatch(r"[A-Za-z]:", base):
                base += "\\"  # D:/* names the drive root, not drive-relative D:.
            resolved = self.resolve_path(Value(base), fact.cwd)
            if resolved and force and recursive and self.is_protected(resolved):
                rooted.append((value, resolved))
        patterns = tuple(v for v in fact.values if v.pattern and v.text is not None)
        for value in patterns:
            base = next((base for rooted_value, base in rooted if rooted_value == value), None)
            selected, complete = self.delete_pattern(fact, value, recursive, force, base)
            changed.update(selected)
            selection = selection_for(value, fact.cwd, fact.shell, self.paths)
            if selection is not None and not complete:
                changed.add(selection.base)
        remaining = tuple(v for v in fact.values if v not in patterns)
        scoped = [(v, path_scope(v, self.paths, fact.cwd)) for v in remaining]
        for value, scope in scoped:
            if scope is not None:
                self.emit('delete-inside-workspace' if self.in_workspace(scope) else 'delete-outside-workspace',
                          'Deletes a runtime-named target within ' + scope, fact,
                          {'scope_root': scope, 'target_resolved': False, 'recursive': recursive, 'force': force,
                           'path_basis': 'constrained_runtime'})
                changed.add(scope)
        unresolved = tuple(v for v, scope in scoped if scope is None and self.resolve_path(v, fact.cwd) is None)
        if unresolved:
            patterns = sorted(v.text or "" for v in unresolved if v.pattern)
            title = ("Deletion target is a pattern whose matches are not enumerated" if patterns
                     else "Deletion target is unresolved; an empty or split value may broaden it")
            self.emit("delete-variable-unresolved", title, fact,
                      {"variables": sorted({v for value in unresolved for v in value.variables}),
                       "patterns": patterns, "recursive": recursive, "force": force})
        for path in fact.targets:
            rule = self.deletion_rule(path, force, recursive)
            answer = self.answer(StatTarget(path))
            evidence = [{"source": path, "status": answer.status.value}]
            if answer.status == EvidenceStatus.AVAILABLE and "recursion_unresolved" not in fact.flags:
                count = self.answer(SummarizeDeletion(path, self.config.directory_entries, recursive,
                                             "files_only" in fact.flags, self.config.wildcard_matches))
                evidence.append({"source": path, "status": count.status.value, "complete": count.complete, **count.data})
            self.emit(rule, ("Force-recursively deletes " if force and recursive else "Recursively deletes " if recursive else "Deletes ") + path + (" because backslash did not escape the quote" if "literal_backslash_quote" in fact.flags and self.is_protected(path) else ""),
                      fact, {"target": path, "recursive": None if "recursion_unresolved" in fact.flags else recursive, "force": force, "path_basis": "lexical"}, evidence)
            if answer.status == EvidenceStatus.MISSING:
                self.emit("delete-target-missing", "Deletion target does not currently exist: " + path, fact, {"target": path})
        if self.invoked_effect(fact):
            self.changed.update(self.paths.key(p) for p in changed)
            if unresolved:
                self.unknown_changes = True

    def may_have_changed(self, path):
        return self.unknown_changes or any(self.paths.inside(path, root) for root in self.changed)

    def read(self, fact):
        fact = self.without_null_targets(fact)
        if fact is None:
            return
        fact = self.expand_file_patterns(fact)
        self.location(fact)
        if fact.operation != "ingest" or "output_consumed" in fact.flags and "output_redirected" not in fact.flags:
            # Metadata/count consumers do not expose source bytes. Explicit
            # file/discard redirection still checks the producer's credentials.
            for path in fact.targets:
                if 'probe_device_contents' in fact.flags and raw_device(path):
                    self.emit('raw-device-read', 'Inspects content on raw disk ' + path, fact, {'target': path})
                self.answer(StatTarget(path))
            return
        for path in fact.targets:
            if "search_recursive" in fact.flags:
                info = self.answer(StatTarget(path))
                if info.data.get("kind") == "directory":
                    # Do not enumerate an implicit recursive search or invent
                    # its file selection. Explicit file operands still ingest.
                    self.emit("ingestion-inspection-incomplete", "Recursive search content selection is not inspected", fact,
                              {"target": path, "reason": "recursive_selection_unavailable"},
                              [{"source": path, "status": info.status.value, "complete": False}])
                    continue
            if raw_device(path):
                self.emit("raw-device-read", "Reads raw disk " + path, fact, {"target": path})
                continue
            if self.may_have_changed(path):
                self.emit("ingestion-inspection-incomplete", "Read target may have changed earlier in this call", fact, {"target": path})
                continue
            if fact.flags & {"head_lines:0", "tail_lines:0"}:
                continue
            answer = self.source_answer(path)
            raw = answer.data.get("bytes")
            text = self.text(raw)
            if text is not None:
                for flag in fact.flags:
                    if flag.startswith("head_lines:"):
                        text = "\n".join(text.splitlines()[:int(flag.split(":")[1])])
                    elif flag.startswith("tail_lines:"):
                        count = int(flag.split(":")[1])
                        text = "\n".join(text.splitlines()[-count:]) if count and answer.complete else ""
                    elif flag.startswith("head_chars:"):
                        text = text[:int(flag.split(":")[1])]
                if "fixed_filter" in fact.flags and fact.payload is not None:
                    pattern = fact.payload
                    ignore_case = bool(fact.flags & {"-i", "--ignore-case"})
                    text = "\n".join(line for line in text.splitlines() if
                                     ((pattern.lower() in line.lower()) if ignore_case else (pattern in line))
                                     != ("-v" in fact.flags))
                qualifier = "may expose" if "selection_uncertain" in fact.flags else "contains"
                if contains_secret(text):
                    selection = "conservative" if qualifier == "may expose" else "fixed_filter" if "fixed_filter" in fact.flags else "character_window" if any(f.startswith('head_chars:') for f in fact.flags) else "line_window" if any(f.startswith(('head_lines:', 'tail_lines:')) for f in fact.flags) else "whole_file"
                    self.emit("credentials-read", f"Read content {qualifier} credentials", fact, {"target": path, "selection": selection})
                if 'output_consumed' not in fact.flags and INJECTION.search(text):
                    self.emit("prompt-injection-read", "Read content contains suspected model-directed instructions", fact, {"target": path})
            if text is None or not answer.complete:
                self.emit("ingestion-inspection-incomplete", "Read content could not be fully inspected", fact, {"target": path, "reason": answer.reason or answer.status.value})

    def transfer(self, fact, cwd, depth):
        """Bound copy/move destinations without simulating successful writes."""
        source_values = fact.transfer_sources
        if any(v.pattern and self.resolve_path(v, cwd) is None for v in source_values):
            self.emit('unresolved-value', 'File transfer source selection cannot be determined', fact,
                      {'reason': 'transfer_selection_unavailable'})
        sources = tuple(p for v in source_values if (p := self.resolve_path(v, cwd)) is not None)
        destination = self.resolve_path(fact.values[0], cwd) if fact.values else None
        invoked = self.invoked_effect(fact)
        no_clobber = bool(fact.flags & {"-n", "--no-clobber"}) and not fact.flags & {"-i", "--interactive", "-f", "--force"}
        targets = []
        directory = "destination_directory" in fact.flags
        if destination is not None:
            answer = self.answer(StatTarget(destination)) if not self.may_have_changed(destination) else EvidenceAnswer(EvidenceStatus.UNAVAILABLE, reason="changed_earlier", complete=False)
            kind = answer.data.get("kind")
            directory |= kind == "directory" and not fact.flags & {"-T", "--no-target-directory"}
            if kind == "file" and no_clobber:
                return
            if directory:
                targets.extend(self.paths.module.join(destination, self.paths.module.basename(p)) for p in sources)
            else:
                targets.append(destination)
                if kind in {"symlink", "special"}:
                    self.emit("unresolved-value", "File transfer destination type is unavailable", fact,
                              {"target": destination, "reason": answer.reason or "destination_type_unavailable"})
                    if invoked:
                        self.unknown_changes = True
        if no_clobber:
            targets = [p for p in targets if self.may_have_changed(p) or
                       self.answer(StatTarget(p)).data.get("kind") != "file"]
            if not targets and destination is not None and len(sources) == len(source_values):
                return
        # Write before invalidating the enclosing directory so current file
        # evidence can still establish individual overwrite candidates.
        write = replace(fact, kind="write", targets=tuple(dict.fromkeys(targets)),
                        values=tuple(Value(p) for p in targets) if targets else fact.values)
        self.write(write, cwd, depth)
        if invoked:
            if directory and destination is not None:
                self.changed.add(self.paths.key(destination))
            if fact.operation == "move":
                self.changed.update(self.paths.key(p) for p in sources)
                for value in source_values:
                    if self.resolve_path(value, cwd) is None:
                        selection = selection_for(value, cwd, fact.shell, self.paths) if value.pattern else None
                        if selection is not None:
                            self.changed.add(self.paths.key(selection.base))
                        else:
                            self.unknown_changes = True

    def write(self, fact, cwd, depth):
        fact = self.without_null_targets(fact)
        if fact is None:
            return
        fact = self.expand_file_patterns(fact)
        self.location(fact)
        scoped = {path_scope(v, self.paths, fact.cwd) for v in fact.values} - {None}
        unresolved = [v for v in fact.values if v.variables and self.resolve_path(v, fact.cwd) is None
                      and path_scope(v, self.paths, fact.cwd) is None]
        if unresolved:
            self.emit("write-variable-unresolved", "Variable-dependent write target cannot be bounded", fact,
                      {"variables": sorted({n for v in unresolved for n in v.variables}),
                       "reason": unresolved[0].reason or "unresolved_target"})
            if self.invoked_effect(fact):
                self.unknown_changes = True
        if self.invoked_effect(fact):
            self.changed.update(self.paths.key(p) for p in scoped)
            for value in fact.values:
                if value.pattern:
                    selection = selection_for(value, fact.cwd, fact.shell, self.paths)
                    if selection is not None:
                        self.changed.add(self.paths.key(selection.base))
                    else:
                        self.unknown_changes = True
        # Any unbounded destination can replace later evidence, independently of
        # variable provenance or the finding's classification. Patterns with a
        # known base are bounded by the invalidation above.
        if self.invoked_effect(fact):
            if (not fact.values and not fact.targets) or any(not v.pattern and self.resolve_path(v, fact.cwd) is None
                    and path_scope(v, self.paths, fact.cwd) is None for v in fact.values):
                self.unknown_changes = True
        unknown_targets = [v for v in fact.values if self.resolve_path(v, fact.cwd) is None]
        if fact.payload is not None and (unknown_targets or not fact.targets):
            if contains_secret(fact.payload):
                self.emit('credentials-written', 'Write payload contains credentials', fact, {'target_resolved': False})
            languages = {self.language(hint) for v in unknown_targets if (hint := language_hint(v))} - {None}
            if not languages and fact.payload.startswith('#!'):
                first_line = fact.payload.splitlines()[0]
                for token, language in [('python', 'python'), ('node', 'javascript'), ('pwsh', 'powershell'), ('bash', 'shell'), ('sh', 'shell')]:
                    if re.search(r'(?:/|\s)' + token + r'(?:\d+(?:\.\d+)*)?(?:\s|$)', first_line):
                        languages.add(language)
                        break
            if fact.operation == 'append':
                if languages:
                    self.emit('unresolved-value', 'Final appended script content cannot be determined', fact,
                              {'reason': 'unresolved_append_target'})
            else:
                for language in sorted(languages):
                    self.inspect(fact.payload, language, fact.source + ':write-payload', 'written_content', cwd,
                                 depth + 1, dict(fact.bindings))
        for path in fact.targets:
            if "create_if_missing" in fact.flags and not self.may_have_changed(path):
                current = self.answer(StatTarget(path))
                if current.status == EvidenceStatus.AVAILABLE:
                    continue
            if raw_device(path):
                self.emit("raw-device-write", "Writes raw disk " + path, fact, {"target": path})
                if self.invoked_effect(fact):
                    self.unknown_changes = True
                continue
            identity = self.paths.key(path).replace("\\", "/")
            basename = self.paths.module.basename(self.paths.key(path))
            if identity in {"/etc/passwd", "/etc/shadow"} or "/.ssh/" in identity and basename.startswith("id_") and not basename.endswith(".pub"):
                self.emit("modify-sensitive-file", "Writes password or private-key file " + path, fact, {"target": path})
            if any(part in identity.split("/") for part in {".codex", ".agents"}) or basename == ("agents.md" if self.paths.windows else "AGENTS.md"):
                self.emit("modify-analyzer-config", "Modifies analyzer or approval configuration " + path, fact, {"target": path})
            if fact.operation in {"overwrite", "copy", "move", "transform"}:
                answer = self.answer(StatTarget(path))
                if answer.status == EvidenceStatus.AVAILABLE and answer.data.get("kind") == "file" and not self.may_have_changed(path):
                    data = {"target": path}
                    if self.effort is EvidenceEffort.FULL and "size" in answer.data:
                        data["existing_bytes"] = answer.data["size"]
                    self.emit("overwrite-existing-file", "May overwrite existing file " + path, fact, data,
                              [{"source": path, "status": answer.status.value, "kind": "file"}])
            elif fact.operation == "create_directory":
                self.answer(StatTarget(path))
            language = self.language(path)
            prefix_answer = self.source_answer(path, python_pending=False) if fact.operation == "append" and fact.payload is not None and language else None
            if self.invoked_effect(fact):
                self.changed.add(self.paths.key(path))
            if fact.payload is not None:
                if contains_secret(fact.payload):
                    self.emit("credentials-written", "Write payload contains credentials", fact, {"target": path})
                if language:
                    if fact.operation == "append":
                        self.inspect_append(fact, path, language, cwd, depth, prefix_answer)
                    else:
                        self.inspect(fact.payload, language, path, "written_content", cwd, depth + 1, dict(fact.bindings))
            elif fact.operation in {"overwrite", "append"} and (language or 'runtime_output' not in fact.flags and path.casefold().endswith(('.exe', '.com', '.dll', '.so', '.dylib', '.jar', '.wasm'))):
                self.emit("unresolved-value", "Written content is not statically available", fact, {"target": path})

    def inspect_append(self, fact, path, language, cwd, depth, answer):
        if answer.status == EvidenceStatus.MISSING:
            # A new file has no prefix; its complete proposed content is literal.
            self.inspect(fact.payload, language, path, "written_content", cwd, depth + 1, dict(fact.bindings))
            return
        prefix = self.text(answer.data.get("bytes"))
        if prefix is None or not answer.complete:
            self.emit("unresolved-value", "Final appended script content cannot be determined", fact,
                      {"target": path, "reason": answer.reason or answer.status.value, "effort": self.effort.value})
            return
        # Existing syntax can make an appended command part of a quote, comment
        # or heredoc. Inspect the exact concatenation, never the suffix alone.
        self.inspect(prefix + fact.payload, language, path, "written_content", cwd, depth + 1,
                     dict(fact.bindings), effort=self.effort.lower())

    def without_null_targets(self, fact):
        targets = tuple(p for p in fact.targets if not is_null_device(p, self.paths))
        values = tuple(v for v in fact.values if not is_null_device(self.resolve_path(v, fact.cwd), self.paths))
        if (fact.targets or fact.values) and not targets and not values:
            return None
        return replace(fact, targets=targets, values=values)

    def expand_file_patterns(self, fact):
        if fact.kind == "read" and (fact.operation != "ingest" or "output_consumed" in fact.flags and "output_redirected" not in fact.flags):
            return fact
        targets, remaining = list(fact.targets), []
        for value in fact.values:
            if not value.pattern:
                remaining.append(value)
                continue
            # Bash redirection requires exactly one pathname; do not reinterpret
            # an ambiguous redirect as a multi-file write.
            if fact.kind == "write" and fact.shell == "bash":
                remaining.append(value)
                continue
            answer = self.match(fact, value)
            paths = answer.data.get("paths", [])
            targets.extend(paths)
            if not answer.complete or answer.status not in {EvidenceStatus.AVAILABLE, EvidenceStatus.MISSING}:
                remaining.append(value)
                if fact.kind == "read" and fact.operation == "ingest":
                    self.emit("ingestion-inspection-incomplete", "Read pattern selection is incomplete", fact,
                              {"pattern": value.text, "matched_targets": paths, "reason": answer.reason or answer.status.value},
                              [{"source": value.text or "", "status": answer.status.value, "complete": False}])
            else:
                remaining.extend(Value(p) for p in paths)
        return replace(fact, targets=tuple(dict.fromkeys(targets)), values=tuple(remaining))

    @staticmethod
    def interpreter_language(name: str) -> str:
        return "python" if name.startswith("python") else "shell" if name in {"bash", "sh", "zsh"} else "javascript"

    def execute(self, fact, cwd, depth):
        if fact.operation in {"powershell", "cmd"}:
            self.emit("uses-interpreter", "Invokes " + fact.operation, fact, {"interpreters": [fact.operation]})
            if "stdin_source" in fact.flags and ("stdin_program" in fact.flags or not fact.flags & {"inline_source", "direct_source", "unknown_source"}):
                self.inspect_stdin(fact, fact.operation, cwd, depth)
            elif "inline_source" in fact.flags:
                if fact.payload is None:
                    self.emit("execution-content-unavailable", "Inline code could not be resolved", fact)
                else:
                    self.inspect(fact.payload, fact.operation, fact.source + ":inline", fact.context, cwd, depth + 1, dict(fact.bindings))
            elif "unknown_source" in fact.flags:
                self.emit("execution-content-unavailable", "Interpreter code target is unresolved", fact)
            elif "direct_source" in fact.flags:
                path = self.resolve_path(fact.values[0], cwd) if fact.values else None
                self.inspect_file(fact, path, fact.operation, cwd, depth)
            return
        if fact.operation != "artifact":
            # Reported before any stdin handling: a here-document program is still
            # an interpreter invocation, and a benign one is LOW rather than silent.
            self.emit("uses-interpreter", "Invokes " + fact.operation, fact, {"interpreters": [fact.operation]})
        args = list(fact.values)
        name = fact.operation
        if name == "artifact":
            path = fact.targets[0] if fact.targets else (self.resolve_path(args[0], cwd) if args else None)
            self.inspect_file(fact, path, "shell" if "source_shell" in fact.flags else None, cwd, depth)
            return
        language = self.interpreter_language(name)
        words = [v.text for v in args]
        options, unknown, operand_start = split_interpreter_args(words, language)
        for option in unknown:
            self.emit("unknown-option", "Interpreter option is unsupported: " + option, fact)
        if unknown:
            self.emit("execution-content-unavailable", "Unsupported interpreter options leave its code target unresolved", fact)
            return
        for option, kind, value in options:
            if kind == "code":
                if value is None:
                    self.emit("execution-content-unavailable", "Inline code could not be resolved", fact)
                else:
                    self.inspect(value, language, fact.source + ":inline", fact.context, cwd, depth + 1, dict(fact.bindings))
                return
            if kind == "module":
                module_operands = [v.text for v in args[operand_start:]]
                if value in {"pytest", "pip", "twine"}:
                    if value == "pip" and "install" in module_operands:
                        self.emit("package-install", "Installs Python packages", fact)
                    elif value == "twine" and module_operands and module_operands[0] == "upload" and "--dry-run" not in module_operands:
                        self.emit("publish-risk", "Publishes local Python package artifacts", fact, {"destinations": [], "destination_resolved": False})
                else:
                    self.emit("unknown-command", "Python module execution is outside the modeled task entry points: " + (value or "unresolved module"), fact,
                              {"command": name, "command_resolved": True, "module": value,
                               "reason": "unsupported_module_entrypoint"})
                return
        operands = args[operand_start:]
        if not operands or operands[0].text == "-" or any(kind == "stdin" for _, kind, _ in options):
            # With no script operand the interpreter reads its program from standard
            # input, which a here-document may supply. A here-document attached to a
            # script or to `-c` is that program's input, not its source, so it must
            # not displace the artifact the call actually names.
            if "stdin_source" in fact.flags:
                self.inspect_stdin(fact, language, cwd, depth)
                return
            if operands or any(kind == "stdin" for _, kind, _ in options):
                self.emit("execution-content-unavailable", "Code supplied on standard input is unavailable", fact)
            return
        self.inspect_file(fact, self.resolve_path(operands[0], cwd), language, cwd, depth)

    def inspect_stdin(self, fact, language, cwd, depth):
        if fact.stdin_payload is not None:
            self.inspect(fact.stdin_payload, language, fact.source + ":stdin", fact.context, cwd, depth + 1, dict(fact.bindings), python_bindings=fact.python_bindings, javascript_bindings=fact.javascript_bindings,
                         python_mode=next((flag.split(':', 1)[1] for flag in fact.flags if flag.startswith('python_mode:')), 'exec'))
            return
        if not fact.stdin_sources:
            self.emit("execution-content-unavailable", "Code supplied on standard input is unavailable", fact)
            return
        if len(fact.stdin_sources) == 1:
            value = fact.stdin_sources[0]
            self.inspect_file(replace(fact, values=(value,)), self.resolve_path(value, cwd), language, cwd, depth)
            return
        chunks, paths, complete = [], [], True
        combined_bytes = 0
        for value in fact.stdin_sources:
            path = self.resolve_path(value, cwd)
            if path is None:
                complete = False
                continue
            paths.append(path)
            answer = self.source_answer(path)
            text = self.text(answer.data.get("bytes"))
            if text is None or not answer.complete:
                complete = False
                self.emit("execution-content-unavailable", "Standard-input source could not be fully inspected", fact,
                          {"target": path, "reason": answer.reason or answer.status.value, "effort": self.effort.value})
            else:
                combined_bytes += len(text.encode("utf-8", errors="surrogatepass"))
                if combined_bytes > self.config.file_bytes:
                    self.emit("unreadable-payload", "Combined standard-input code exceeds the configured inspection budget", fact,
                              {"targets": paths, "reason": "file_bytes_limit"})
                    return
                chunks.append(text)
            if answer.status == EvidenceStatus.MISSING:
                self.emit("execute-target-missing", "Code source file does not currently exist: " + path, fact, {"target": path})
        if not complete:
            self.emit("execution-content-unavailable", "Combined standard-input program is unavailable", fact,
                      {"targets": paths, "effort": self.effort.value})
            return
        context = fact.context if fact.context in {"written_content", "defined_body"} else "direct_artifact"
        self.inspect("".join(chunks), language, fact.source + ":stdin_files", context, cwd, depth + 1,
                     dict(fact.bindings), effort=self.effort.lower(), python_bindings=fact.python_bindings, javascript_bindings=fact.javascript_bindings,
                     python_mode=next((flag.split(':', 1)[1] for flag in fact.flags if flag.startswith('python_mode:')), 'exec'))

    def inspect_file(self, fact, path, language, cwd, depth):
        if path is None or self.may_have_changed(path):
            self.emit("execution-content-unavailable", "Cannot determine the contents of the code being invoked", fact,
                      {"target": path, "reason": "changed_earlier" if path is not None else "unresolved_path"})
            return
        if self.paths.key(path) in {self.paths.key(p) for p in self.config.trusted_scripts}:
            self.emit('trusted-script-invoked', 'Invokes trusted script; content inspection skipped', fact,
                      {'target': path, 'effects': 'not_inspected'})
            if self.invoked_effect(fact):
                self.unknown_changes = True
            return
        # Cache evidence bytes, not invocation effects: the same source must
        # replay its mutations in every branch and at every call site.
        answer = self.source_answer(path)
        text = self.text(answer.data.get("bytes"))
        if language is None:
            language = self.language(path)
            if language is None and text and text.startswith("#!"):
                first_line = text.splitlines()[0]
                language = "python" if "python" in first_line else "shell" if re.search(r"\b(?:bash|sh|zsh)\b", first_line) else None
        if text is None or not answer.complete or language not in {"shell", "python", "powershell", "cmd", "javascript"}:
            self.emit("execution-content-unavailable", "Cannot determine the contents of the code being invoked", fact,
                      {"target": path, "reason": answer.reason or (answer.status.value if text is None else "unsupported_or_incomplete_source"),
                       "effort": self.effort.value, "evidence_status": answer.status.value})
        if answer.status == EvidenceStatus.MISSING:
            self.emit("execute-target-missing", "Code source file does not currently exist: " + path, fact, {"target": path})
        if text is not None and language in {"shell", "python", "powershell", "cmd", "javascript"}:
            # The script runs with the invocation cwd, never its parent directory.
            context = fact.context if fact.context in {"written_content", "defined_body"} else "direct_artifact"
            self.inspect(text, language, path, context, cwd, depth + 1, dict(fact.bindings), effort=self.effort.lower(), python_bindings=fact.python_bindings, javascript_bindings=fact.javascript_bindings,
                         python_mode=next((flag.split(':', 1)[1] for flag in fact.flags if flag.startswith('python_mode:')), 'exec'))

    def source_answer(self, path, *, python_pending=True):
        """One source dependency: Full bytes, Partial metadata, None no query."""
        if not self.may_have_changed(path) and is_null_device(path, self.paths):
            # The empty stream is known from device semantics, not evidence.
            return EvidenceAnswer(EvidenceStatus.AVAILABLE, {"bytes": b""})
        pending = any(self.paths.inside(path, changed) and
                      (python_pending or changed != self.paths.key(path) or len(events) > 1)
                      for changed, events in self.python_source_changes.items())
        # An append may read its own old prefix, but never bypass a different
        # possible mutation merely because source order is unknown.
        if self.python_unknown_sources or pending:
            return EvidenceAnswer(EvidenceStatus.UNAVAILABLE, reason="possible_python_mutation", complete=False)
        if self.effort is EvidenceEffort.FULL:
            return self.answer(ReadFile(path, self.config.file_bytes))
        info = self.answer(StatTarget(path))
        if info.status in {EvidenceStatus.MISSING, EvidenceStatus.UNAVAILABLE, EvidenceStatus.TRUNCATED}:
            return info
        return replace(info, status=EvidenceStatus.UNAVAILABLE, reason="effort_partial", complete=False)

    def sql(self, fact):
        data = {"objects": list(fact.targets)}
        for prefix, key in (("statement:", "statement_index"), ("dialect:", "dialect"), ("object:", "object_kind"), ("action:", "action")):
            value = next((f[len(prefix):] for f in fact.flags if f.startswith(prefix)), None)
            if value is not None:
                data[key] = int(value) if key == "statement_index" else value
        for prefix, key in (("principal:", "principals"), ("privilege:", "privileges")):
            values = sorted(f[len(prefix):] for f in fact.flags if f.startswith(prefix))
            if values:
                data[key] = values
        if "replacement" in fact.flags:
            data["replacement"] = True
        titles = {"sql-unresolved": "SQL could not be inspected completely",
                  "sql-row-change": "Changes SQL rows", "sql-schema-change": "Creates or changes SQL schema objects",
                  "sql-truncate": "Truncates or replaces SQL objects", "sql-remove-schema": "Removes SQL schemas or columns",
                  "sql-privilege-change": "Changes SQL privileges or account attributes",
                  "sql-create-identity": "Creates a SQL database or account", "sql-drop-object": "Drops whole SQL objects"}
        level = None
        if fact.operation == "sql-row-change":
            data["has_where"] = "has_where" in fact.flags
            data["single_target"] = "single_target" in fact.flags
            data["action"] = next((v for v in ("insert", "update", "delete", "merge") if v in fact.flags), "change")
            level = Level.LOW if "insert" in fact.flags and "overwrite" not in fact.flags or {"has_where", "single_target"} <= fact.flags else Level.MEDIUM
        if fact.operation == "sql-unresolved":
            data["reason"] = fact.payload or "unresolved_source"
        self.emit(fact.operation, titles[fact.operation], fact, data, level=level)

    def inspect_sql(self, text, dialect, fact, depth=0, *, effort=None):
        from .sql.syntax import SQLFrontend
        from .sql.semantics import SQLBuilder
        reason = "unresolved_source" if text is None else "inspection_budget" if depth > self.config.inline_depth or len(text.encode()) > self.config.file_bytes else None
        if reason:
            self.sql(replace(fact, kind="sql", operation="sql-unresolved", targets=(), values=(),
                             flags=frozenset({f"dialect:{dialect or 'generic'}", "statement:0", "object:statement"}), payload=reason))
            return
        statements = SQLFrontend().parse(text, dialect, self.config.source_nodes)
        facts = SQLBuilder(dialect, source=fact.source, context=fact.context, guard=fact.guard, node_limit=self.config.source_nodes).build(statements)
        self.run(facts, fact.cwd, depth=depth, effort=effort, context=fact.context)

    def sql_source(self, fact, cwd, depth):
        if "file" not in fact.flags:
            self.inspect_sql(fact.payload, fact.operation, fact, depth + 1)
            return
        for value in fact.values or (Value(None),):
            path = self.resolve_path(value, cwd)
            reason = "unresolved_path" if path is None else "changed_earlier" if self.may_have_changed(path) else None
            evidence = ()
            text = None
            if reason is None:
                answer = self.source_answer(path)
                text = self.text(answer.data.get("bytes"))
                reason = answer.reason or "unsupported_or_incomplete_source" if not answer.complete or text is None else None
                evidence = ({"query": "ReadFile" if self.effort is EvidenceEffort.FULL else "StatTarget" if self.effort is EvidenceEffort.PARTIAL else "None",
                             "path": path, "status": answer.status.value, "complete": answer.complete, "reason": answer.reason},)
            artifact = replace(fact, source=path or fact.source, context=fact.context if fact.context in {"written_content", "defined_body"} else "direct_artifact")
            if reason:
                self.emit("sql-unresolved", "SQL file could not be inspected completely", artifact,
                          {"target": path, "reason": reason, "dialect": fact.operation}, evidence=evidence)
            if text is not None:
                start = len(self.findings)
                self.inspect_sql(text, fact.operation, artifact, depth + 1, effort=self.effort.lower())
                self.findings[start:] = [replace(f, evidence=f.evidence + evidence) for f in self.findings[start:]]

    def inspect(self, text, language, source, context, cwd, depth, env=None, *, effort=None, python_bindings=(), javascript_bindings=(), python_mode='exec'):
        placeholder = Fact("content", "inspect", source=source, context=context)
        if language == "sql":
            self.inspect_sql(text, None, placeholder, depth, effort=effort)
            return
        if depth > self.config.inline_depth or len(text.encode()) > self.config.file_bytes:
            self.emit("unreadable-payload", "Code exceeds the configured inspection budget", placeholder)
            return
        if context == "direct_artifact" and ":" not in source:
            # File content is new text; inline and here-document bodies already
            # appear in the submitted command and were checked there.
            self.check_opaque_payload(text, placeholder)
        if language in {"powershell", "cmd"}:
            from .pwsh.semantics import PowerShellBuilder
            from .cmd.semantics import CmdBuilder
            frontend = self.frontends.get(language)
            if frontend is None:
                self.emit("analysis-unavailable", "Source frontend is unavailable", placeholder)
                return
            try:
                parsed = frontend.parse(text, self.config.source_nodes)
            except ParseBudgetExceeded:
                self.emit("unreadable-payload", "Source exceeds the configured syntax-node budget", placeholder)
                return
            if parsed.diagnostics:
                self.emit("unsupported-syntax", "Windows shell source could not be parsed completely", placeholder)
            builder = PowerShellBuilder if language == "powershell" else CmdBuilder
            facts = builder(cwd, env if env is not None else self.env, source=source, context=context, possible_values=self.config.possible_values, control_flow_steps=self.config.control_flow_steps, value_bytes=self.config.value_bytes, trusted_scripts=self.config.trusted_scripts).build(parsed.root)
            self.run(facts, cwd, depth=depth, effort=effort, context=context)
        elif language == "shell":
            if self.frontend is None:
                self.emit("analysis-unavailable", "Shell source frontend is unavailable", placeholder)
                return
            try:
                parsed = self.frontend.parse(text, self.config.source_nodes)
            except ParseBudgetExceeded:
                self.emit("unreadable-payload", "Source exceeds the configured syntax-node budget", placeholder)
                return
            if parsed.diagnostics:
                self.emit("unsupported-syntax", "Shell source could not be parsed completely", placeholder)
            facts = SemanticBuilder(cwd, env if env is not None else self.env, source=source, context=context, possible_values=self.config.possible_values, control_flow_steps=self.config.control_flow_steps, value_bytes=self.config.value_bytes).build(parsed.root)
            self.run(facts, cwd, depth=depth, effort=effort, context=context)
        elif language == "javascript":
            frontend = self.frontends.get("javascript")
            if frontend is None:
                self.emit("analysis-unavailable", "JavaScript source frontend is unavailable", placeholder)
                return
            try:
                parsed = frontend.parse(text, self.config.source_nodes, allow_top_level_return=source.endswith((".js", ".cjs")))
            except ParseBudgetExceeded:
                self.emit("unreadable-payload", "JavaScript source exceeds the syntax-node budget", placeholder)
                return
            if parsed.diagnostics:
                rule = "written-source-syntax-error" if context == "written_content" else "unsupported-syntax"
                self.emit(rule, "JavaScript source has unsupported syntax or a syntax error", placeholder)
                return
            facts = JavaScriptBuilder(cwd, env if env is not None else self.env, source=source,
                                      context=context, paths=self.paths, possible_values=self.config.possible_values,
                                      control_flow_steps=self.config.control_flow_steps, value_bytes=self.config.value_bytes,
                                      javascript_bindings=javascript_bindings).build(parsed.root)
            self.run(facts, cwd, depth=depth, effort=effort, context=context)
        elif language == "python":
            try:
                parsed = PythonFrontend().parse(text, self.config.source_nodes, mode=python_mode)
            except ParseBudgetExceeded:
                self.emit("unreadable-payload", "Python source exceeds the syntax-node budget", placeholder)
                return
            if parsed.diagnostics:
                rule = "written-source-syntax-error" if context == "written_content" else "unsupported-syntax"
                self.emit(rule, "Python source has a syntax error or exceeds parser limits", placeholder)
                return
            facts = PythonBuilder(cwd, env if env is not None else self.env, source=source,
                                  context=context, paths=self.paths, possible_values=self.config.possible_values,
                                  control_flow_steps=self.config.control_flow_steps, value_bytes=self.config.value_bytes,
                                  python_bindings=python_bindings).build(parsed.root)
            self.run(facts, cwd, depth=depth, effort=effort, context=context)
        else:
            self.emit("execution-content-unavailable", "Source language inspection is not yet implemented", placeholder)

    @staticmethod
    def language(path):
        path = path.casefold()
        if path.endswith((".ps1", ".ps")):
            return "powershell"
        if path.endswith((".bat", ".cmd")):
            return "cmd"
        if path.endswith(".sql"):
            return "sql"
        return "shell" if path.endswith((".sh", ".bash")) else "python" if path.endswith(".py") else "javascript" if path.endswith((".js", ".mjs", ".cjs")) else None

    @staticmethod
    def text(raw):
        if not isinstance(raw, bytes):
            return None
        try:
            text = raw.decode("utf-16") if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else raw.decode("utf-8-sig")
            return None if "\x00" in text else text
        except UnicodeError:
            return None
