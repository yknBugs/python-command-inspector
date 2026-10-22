"""Visible su shell programs, respecting the wrapper's own option binding."""
import posixpath
import re
from ..models import Fact, Value


def describe_su(args):
    from ..shared.options import CommandSpec, parse_options
    spec = CommandSpec("flmpPThV", ("--fast", "--login", "--preserve-environment", "--pty", "--no-pty", "--help", "--version"),
                       ("-c", "--command", "--session-command", "-C", "-s", "--shell", "-g", "--group", "-G", "--supp-group", "-w", "--whitelist-environment"))
    operands, switches, bound, unknown = parse_options(args, spec)
    facts = [Fact("unresolved", "unknown-option", payload=option) for option in unknown]
    if switches & {"-h", "--help", "-V", "--version"}:
        return facts
    login = bool(switches & {"-l", "--login"}) or bool(operands and operands[0].text == "-")
    if operands and operands[0].text == "-":
        operands = operands[1:]
    user = operands[0].text if operands and not operands[0].pattern else None if operands else "root"
    facts.append(Fact("execution", "user-switch", targets=(user,) if user else ()))
    # GNU su rejects invalid wrapper options before launching its shell. In
    # particular, -c rm -rf /* binds only `rm` as source and rejects su's -r;
    # the trailing arguments are never an rm invocation.
    if unknown:
        return facts
    command_keys = {"-c", "-C", "--command", "--session-command"}
    program = next((value for key, value in reversed(bound.occurrences) if key in command_keys), None)
    if program is None:
        facts.append(Fact("unresolved", "execution-content-unavailable", payload="The switched user's shell program is unavailable"))
        return facts
    shell = next((value for key, value in reversed(bound.occurrences) if key in {"-s", "--shell"}), Value("sh"))
    language = posixpath.basename(shell.text) if shell.text else None
    if language not in {"bash", "sh", "zsh", "python", "python3", "python3.11"}:
        facts.append(Fact("unresolved", "execution-content-unavailable", values=(shell,),
                          payload="The selected su shell cannot be inspected"))
        return facts
    flags = set()
    if login:
        flags.update({"unknown_cwd", "reset_environment"})
        whitelist = next((value for key, value in reversed(bound.occurrences) if key in {"-w", "--whitelist-environment"}), None)
        if whitelist is not None:
            if whitelist.text is None:
                facts.append(Fact("unresolved", "unresolved-value", values=(whitelist,), payload="su environment whitelist is unresolved"))
            else:
                flags.update("keep_binding:" + name for name in whitelist.text.split(",") if re.fullmatch(r"[A-Za-z_]\w*", name))
    if login or not switches & {"-m", "-p", "--preserve-environment"}:
        flags.update("unset_binding:" + name for name in ("HOME", "SHELL", "USER", "LOGNAME"))
    if login:
        flags.add("unset_binding:PATH")
    # Following arguments are shell argv, not additional executable source.
    facts.append(Fact("execute", language, values=(Value("-c"), program), flags=frozenset(flags),
                      guard="if the user switch succeeds"))
    return facts
