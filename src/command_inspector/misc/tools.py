"""Common native tools: bounded argument models, never host subprocesses.

Query output is not obtained from the host. Named file ingestion uses the shared
read detector; wrappers retain a separate invocation fact for bounded recursion.
"""
from dataclasses import replace
import re
from ..models import Fact, Value


def describe_tool(name, args, cwd):
    from ..shared.options import CommandSpec, parse_options, take_wrapper_options
    from ..shared.commands import resolve_path, SUDO_SPEC
    facts = []

    def emit(kind, operation, values=(), flags=(), payload=None, **kwargs):
        facts.append(Fact(kind, operation,
            tuple(p for v in values if (p := resolve_path(v, cwd)) is not None) if kind in {"read", "write", "delete"} else (),
            tuple(values), frozenset(flags), payload, **kwargs))

    def options(spec, values=args):
        operands, flags, bound, unknown = parse_options(values, spec)
        for option in unknown:
            emit("unresolved", "unknown-option", payload=option)
        return operands, flags, bound, unknown

    def invoke(values, flags=(), directory=None):
        if values and values[0].text:
            emit("invoke", values[0].text, values[1:], set(flags) | ({'override_cwd'} if directory is not None else set()), payload=directory.text if directory is not None else None)
        else:
            emit("unresolved", "execution-content-unavailable", payload="Wrapped command cannot be resolved")

    if name in {"source", "."}:
        target = args[:1] or (Value(None),)
        if target[0].text and '/' not in target[0].text:
            emit('unresolved', 'execution-content-unavailable', payload='Sourced basename requires shell PATH lookup')
        else:
            emit("execute", "artifact", target, {"source_shell"})
        return facts
    if name in {"timeout", "xargs", "sudo", "env"}:
        specs = {
            "timeout": CommandSpec("v", ("--foreground", "--preserve-status", "--verbose", "--help", "--version"), ("-s", "--signal", "-k", "--kill-after")),
            "xargs": CommandSpec("0rptx", ("--null", "--no-run-if-empty", "--verbose", "--exit", "--help", "--version"), ("-a", "--arg-file", "-d", "--delimiter", "-E", "-I", "--replace", "-L", "--max-lines", "-n", "--max-args", "-P", "--max-procs", "-s", "--max-chars")),
            "sudo": SUDO_SPEC,
            "env": CommandSpec("i0v", ("--ignore-environment", "--null", "--debug", "--help", "--version"), ("-u", "--unset", "-C", "--chdir", "-S", "--split-string")),
        }
        unknown, index = take_wrapper_options(args, specs[name])
        operands, flags, bound, _ = options(specs[name], args[:index])
        # take_wrapper_options stops at the command/duration; unknown arity cannot
        # safely determine where that command begins.
        if unknown or index is None:
            emit("unresolved", "execution-content-unavailable", payload="Wrapper options leave its command unresolved")
            return facts
        if flags & {"--help", "--version"}:
            return facts
        tail = args[index:]
        if name == "timeout":
            invoke(tail[1:])  # first positional operand is the duration
        elif name == "xargs":
            marker = bound.get("-I", bound.get("--replace", Value(None))).text
            command = tail or (Value("echo"),)
            command = tuple(Value(None, "runtime_input") if marker and v.text and marker in v.text else v for v in command)
            if not marker:
                command = (*command, Value(None, "runtime_input"))
            invoke(command, flags={"consumes_stdin"} if not bound.keys() & {"-a", "--arg-file"} else ())
            for key in ("-a", "--arg-file"):
                if key in bound:
                    emit("read", "list", (bound[key],))
        elif name == "sudo":
            emit("execution", "privilege")
            password_stdin = bool(flags & {'-S', '--stdin'}) and not bool(flags & {'-n', '--non-interactive', '-A', '--askpass', '-V'})
            if password_stdin:
                emit('credential_input', 'sudo')
            invoke(tail, flags={'authentication_stdin', 'consumes_stdin'} if password_stdin else (), directory=bound.get('-C', bound.get('--chdir')))
            if flags & {'-s', '--shell', '-i', '--login'}:
                emit('unresolved', 'execution-content-unavailable', payload='Elevated shell startup or argument evaluation is not modeled')
        else:
            bindings = []
            while tail and tail[0].text and re.match(r"^[A-Za-z_]\w*=", tail[0].text):
                key, value = tail[0].text.split("=", 1)
                bindings.append((key, value))
                tail = tail[1:]
            if bound.keys() & {"-S", "--split-string"}:
                emit("unresolved", "execution-content-unavailable", payload="Environment wrapper changes command parsing")
            elif tail:
                environment_flags = {"clear_bindings"} if flags & {"-i", "--ignore-environment"} else set()
                for key, value in bound.occurrences:
                    if key in {'-u', '--unset'}:
                        if value.text:
                            environment_flags.add('unset_binding:'+value.text)
                        else:
                            environment_flags.add('clear_bindings')
                invoke(tail, environment_flags, directory=bound.get('-C', bound.get('--chdir')))
                facts[-1] = replace(facts[-1], bindings=tuple(bindings))
        return facts
    if name in {"head", "tail", "nl", "cut"}:
        spec = {
            "head": CommandSpec("qvz", ("--quiet", "--silent", "--verbose", "--zero-terminated", "--help", "--version"), ("-n", "--lines", "-c", "--bytes")),
            "tail": CommandSpec("qvfFz", ("--quiet", "--silent", "--verbose", "--retry", "--follow", "--zero-terminated", "--help", "--version"), ("-n", "--lines", "-c", "--bytes", "--pid", "-s", "--sleep-interval", "--max-unchanged-stats")),
            "nl": CommandSpec("p", ("--help", "--version"), tuple("-" + x for x in "bdilnsvw")),
            "cut": CommandSpec("nsz", ("--complement", "--only-delimited", "--zero-terminated", "--help", "--version"), ("-b", "--bytes", "-c", "--characters", "-f", "--fields", "-d", "--delimiter", "--output-delimiter")),
        }[name]
        args = tuple(Value("-n" + v.text[1:]) if name in {"head", "tail"} and v.text and re.fullmatch(r"-\d+", v.text) else v for v in args)
        operands, flags, bound, unknown = options(spec, args)
        if flags & {"--help", "--version"}:
            return facts
        read_flags = {"selection_uncertain"} if name == "cut" or bound else set()
        if name in {"head", "tail"}:
            number = bound.get("-n", bound.get("--lines", Value("10"))).text
            if number and number.isdecimal() and len(number) <= 9 and not flags & {"-z", "--zero-terminated"} and not bound.keys() & {"-c", "--bytes"}:
                read_flags = {name + "_lines:" + number}
            else:
                read_flags.add("selection_uncertain")
        if unknown:
            operands = (Value(None, "unknown_option_operand_binding"),)
        emit("read", "ingest", tuple(v for v in operands if v.text != "-"), read_flags)
        return facts
    if name in {"du", "df", "which", "sleep", "ps", "free", "ss", "netstat", "javap"}:
        spec = {
            "du": CommandSpec("achskmLbPlSxD0", ("--all", "--summarize", "--human-readable", "--total", "--apparent-size", "--bytes", "--si", "--one-file-system", "--help", "--version"), ("-d", "--max-depth", "-B", "--block-size", "--exclude", "-X", "--exclude-from", "--files0-from")),
            "df": CommandSpec("ahiklmPT", ("--all", "--human-readable", "--local", "--portability", "--print-type", "--total", "--si", "--help", "--version"), ("-B", "--block-size", "-t", "--type", "-x", "--exclude-type", "--output")),
            "which": CommandSpec("as", ("--all", "--skip-alias", "--skip-functions", "--skip-dot", "--skip-tilde", "--show-dot", "--show-tilde", "--help", "--version")),
            "sleep": CommandSpec("", ("--help", "--version")),
            "ps": CommandSpec("aAefuxwwHjlLMVy", ("--forest", "--headers", "--no-headers", "--help", "--version"), ("-p", "--pid", "-o", "--format", "-C", "-U", "-u", "-t", "--sort", "--ppid")),
            "free": CommandSpec("bhkmgwtlV", ("--bytes", "--kibi", "--mebi", "--gibi", "--human", "--wide", "--total", "--help", "--version"), ("-s", "--seconds", "-c", "--count")),
            "ss": CommandSpec("atunlpersimox46HOK", ("--all", "--tcp", "--udp", "--listening", "--numeric", "--processes", "--extended", "--summary", "--kill", "--help", "--version"), ("-F", "--filter", "-D", "--diag")),
            "netstat": CommandSpec("atunlpersioxcW46", ("--all", "--tcp", "--udp", "--listening", "--numeric", "--program", "--route", "--statistics", "--help", "--version")),
            "javap": CommandSpec("", ("-help", "--help", "-version", "--version", "-verbose", "-v", "-public", "-protected", "-package", "-private", "-p", "-c", "-s", "-l", "-constants", "-sysinfo"), ("-classpath", "-cp", "--class-path", "--module-path", "--module", "-bootclasspath")),
        }[name]
        operands, flags, bound, unknown = options(spec)
        if name in {"du", "df"} and not flags & {"--help", "--version"}:
            emit("read", "list", (Value(None),) if unknown else operands or ((Value("."),) if name == "du" else ()))
        if name == "ss":
            if flags & {"-K", "--kill"}:
                emit("system", "system-settings-change", payload="Closes network sockets")
            if "-D" in bound or "--diag" in bound:
                emit("write", "transform", (bound.get("-D", bound.get("--diag")),))
        return facts
    if name in {"journalctl", "systemctl", "nvidia-smi"}:
        specs = {
            "journalctl": CommandSpec("abefklqrx", ("--boot", "--follow", "--no-pager", "--pager-end", "--reverse", "--quiet", "--utc", "--disk-usage", "--list-boots", "--system", "--user", "--verify", "--rotate", "--flush", "--sync", "--relinquish-var", "--setup-keys", "--help", "--version"), ("-u", "--unit", "-n", "--lines", "--since", "--until", "-p", "--priority", "-o", "--output", "-g", "--grep", "--identifier", "--file", "--directory", "--vacuum-time", "--vacuum-size", "--vacuum-files")),
            "systemctl": CommandSpec("alq", ("--all", "--full", "--quiet", "--no-pager", "--user", "--system", "--failed", "--now", "--force", "--no-block", "--plain", "--legend", "--no-legend", "--help", "--version"), ("-t", "--type", "--state", "-p", "--property", "--signal", "--kill-whom", "--root", "--machine", "--host")),
            "nvidia-smi": CommandSpec("Lq", ("--list-gpus", "--query", "--help", "-h", "--version", "--gpu-reset"), ("-i", "--id", "--query-gpu", "--query-compute-apps", "--format", "-l", "--loop", "-f", "--filename", "-d", "--display", "-pm", "--persistence-mode", "-pl", "--power-limit", "-ac", "--applications-clocks", "-c", "--compute-mode", "-lgc", "--lock-gpu-clocks")),
        }
        operands, flags, bound, unknown = options(specs[name])
        if flags & {"--help", "-h", "--version"}:
            return facts
        if name == "systemctl":
            operation = operands[0].text if operands else None
            queries = {"status", "show", "cat", "help", "is-active", "is-enabled", "is-failed", "list-units", "list-unit-files", "list-jobs", "list-timers", "list-sockets", "list-dependencies", "get-default"}
            changes = {"start", "stop", "restart", "try-restart", "reload", "reload-or-restart", "enable", "disable", "reenable", "mask", "unmask", "preset", "preset-all", "daemon-reload", "daemon-reexec", "reset-failed", "kill", "edit", "set-default", "set-property", "link", "revert", "isolate", "cancel"}
            if operation in {"reboot", "poweroff", "halt", "suspend", "hibernate", "hybrid-sleep"}:
                emit("system", "machine-power-change")
            elif operation in changes:
                scope = {"scope:user"} if "--user" in flags else {"scope:system"}
                scope.update(k + ":" + v.text for k, v in bound.items() if k in {"--root", "--machine", "--host"} and v.text is not None)
                facts.append(Fact("system", "service-change", targets=tuple(v.text for v in operands[1:] if v.text is not None),
                                  values=operands[1:], flags=frozenset(scope | set(flags)), payload=operation))
            elif operation not in queries:
                emit("unresolved", "unknown-command", payload="Unsupported systemctl operation")
        elif name == "journalctl":
            if any(k.startswith("--vacuum-") for k in bound) or flags & {"--rotate", "--flush", "--sync", "--relinquish-var", "--setup-keys"}:
                emit("system", "system-settings-change", payload="Changes journal storage or state")
        else:
            if flags & {"--gpu-reset"} or bound.keys() & {"-pm", "--persistence-mode", "-pl", "--power-limit", "-ac", "--applications-clocks", "-c", "--compute-mode", "-lgc", "--lock-gpu-clocks"}:
                emit("system", "system-settings-change", payload="Changes GPU settings or resets a GPU")
            for key in ("-f", "--filename"):
                if key in bound:
                    emit("write", "transform", (bound[key],))
        return facts
    return None
