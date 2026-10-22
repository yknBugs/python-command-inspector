"""Docker effect classification without daemon access or container state."""
from ..models import Fact, Value


QUERIES = {"ps", "images", "inspect", "logs", "stats", "top", "events", "diff", "wait",
           "version", "info", "history", "port", "search", "help"}
EFFECTS = {"run", "exec", "create", "start", "stop", "restart", "kill", "rm", "rmi", "remove",
           "build", "pull", "push", "tag", "rename", "update", "pause", "unpause",
           "attach", "cp", "commit", "import", "load", "save", "export", "login", "logout"}
GROUPS = {"system", "container", "image", "volume", "network", "builder", "buildx", "compose",
          "context", "config", "secret", "service", "stack", "swarm", "plugin", "manifest", "trust"}
# Constrain effect/query words to real entry points. Sharing a word such as
# `config` across groups must not silently accept an unsupported invocation.
GROUP_COMMANDS = {
    "system": ({"df", "events", "info"}, {"prune"}),
    "container": ({"ls", "inspect", "logs", "stats", "top", "port", "diff", "wait"},
                  {"attach", "commit", "cp", "create", "exec", "export", "kill", "pause", "prune", "rename", "restart", "rm", "run", "start", "stop", "unpause", "update"}),
    "image": ({"ls", "inspect", "history"}, {"build", "import", "load", "prune", "pull", "push", "rm", "save", "tag"}),
    "volume": ({"ls", "inspect"}, {"create", "prune", "rm", "update"}),
    "network": ({"ls", "inspect"}, {"connect", "create", "disconnect", "prune", "rm"}),
    "builder": (set(), {"build", "prune"}),
    "buildx": ({"ls", "inspect", "du", "version"}, {"bake", "build", "create", "prune", "rm", "stop", "use"}),
    "compose": ({"ls", "ps", "config", "images", "logs", "top", "version", "events"},
                {"build", "cp", "create", "down", "exec", "kill", "pause", "pull", "push", "restart", "rm", "run", "start", "stop", "unpause", "up", "watch"}),
    "context": ({"ls", "show", "inspect"}, {"create", "export", "import", "rm", "update", "use"}),
    "config": ({"ls", "inspect"}, {"create", "rm"}),
    "secret": ({"ls", "inspect"}, {"create", "rm"}),
    "service": ({"ls", "inspect", "logs", "ps"}, {"create", "rm", "rollback", "scale", "update"}),
    "stack": ({"ls", "services", "ps"}, {"deploy", "rm"}),
    "swarm": ({"inspect"}, {"init", "join", "leave", "update"}),
    "plugin": ({"ls", "inspect"}, {"create", "disable", "enable", "install", "push", "rm", "set", "upgrade"}),
    "manifest": ({"inspect"}, {"annotate", "create", "push", "rm"}),
    "trust": ({"inspect"}, {"sign", "revoke"}),
}
GLOBAL_VALUES = {"--context", "-c", "--host", "-H", "--config", "--log-level", "-l",
                 "--tlscacert", "--tlscert", "--tlskey"}
GLOBAL_FLAGS = {"--debug", "-D", "--tls", "--tlsverify"}
GROUP_VALUES = {"--file", "-f", "--project-name", "-p", "--project-directory", "--env-file",
                "--profile", "--builder", "--progress", "--parallel"}
GROUP_FLAGS = {"--all-resources", "--compatibility", "--dry-run"}
PAYLOAD_VALUES = {"--name", "--env", "-e", "--env-file", "--volume", "-v", "--mount",
                  "--publish", "-p", "--user", "-u", "--workdir", "-w", "--entrypoint",
                  "--network", "--label", "-l", "--filter", "--until", "--file", "-f",
                  "--tag", "-t", "--build-arg", "--cache-from", "--platform", "--output", "-o"}
def effect_value_options(group, command):
    """Option arity belongs to the subcommand, especially overloaded short flags."""
    values = set(PAYLOAD_VALUES) - {"-f", "-t", "-v", "-p", "-l", "-u", "-e", "-w", "-o"}
    values |= {"--time", "--timeout", "--signal", "--password", "--username", "--context", "--project-name"}
    if command in {"run", "exec", "create"}:
        values |= {"-e", "-u", "-w"}
        if command != "exec":
            values |= {"-v", "-p", "-l"}
    if command in {"build", "bake"}:
        values |= {"-f", "-t", "-o"}
    if command in {"stop", "restart"}:
        values.add("-t")
    if command == "kill":
        values.add("-s")
    if command == "login":
        values |= {"-u", "-p"}
    if command in {"save", "export", "config"}:
        values.add("-o")
    if command == "load":
        values |= {"-i", "--input"}
    if command == "prune":
        values.add("--filter")
    return values


def query_spec(group, command):
    """Bounded option sets; future options keep explicit coverage."""
    from ..shared.options import CommandSpec
    flags, values = set(), set()
    if command in {"ps", "ls", "images"}:
        flags = {"--all", "--quiet", "--no-trunc"}
        values = {"--filter", "-f", "--format"}
        if command == "images" or group == "image":
            flags.add("--digests")
        if command == "ps" or group == "container":
            flags.add("--size")
            values |= {"--last", "-n"}
    elif command == "inspect":
        flags = {"--size"}
        values = {"--format", "-f", "--type"}
    elif command == "logs":
        flags = {"--details", "--follow", "--timestamps", "--no-log-prefix", "--no-color"}
        values = {"--tail", "--since", "--until"}
    elif command == "stats":
        flags = {"--all", "--no-stream", "--no-trunc"}
        values = {"--format"}
    elif command == "events":
        values = {"--filter", "-f", "--format", "--since", "--until"}
    elif command in {"version", "info", "du"}:
        values = {"--format"}
    elif command == "history":
        flags = {"--human", "--no-trunc", "--quiet"}
        values = {"--format"}
    elif command == "search":
        flags = {"--no-trunc"}
        values = {"--filter", "-f", "--format", "--limit"}
    elif command == "df":
        flags = {"--verbose"}
        values = {"--format"}
    if group == "compose" and command == "config":
        flags |= {"--services", "--volumes", "--networks", "--profiles", "--images", "--quiet", "--no-interpolate", "--no-normalize", "--no-consistency", "--resolve-image-digests", "--environment", "--variables"}
        values |= {"--format", "--hash"}
    shorts = {"ps": "aqsl", "ls": "aq", "images": "aq", "logs": "ft", "stats": "a", "history": "Hq", "df": "v", "config": "q"}.get(command, "")
    return CommandSpec(shorts, tuple(sorted(flags)), tuple(sorted(values)))


def describe_docker(args):
    facts, words, i, scope = [], [v.text for v in args], 0, set()
    def skip(values, flags):
        nonlocal i
        while i < len(words) and words[i] and words[i].startswith("-"):
            word = words[i]
            key, sep, _ = word.partition("=")
            if key in {"--help", "-h", "--version", "-v"}:
                return False
            if key in values:
                if not sep and (i + 1 >= len(words) or words[i + 1] is None):
                    facts.append(Fact("unresolved", "unresolved-value", payload="Docker option value is unavailable: " + key))
                    return False
                value = word.split("=", 1)[1] if sep else words[i + 1]
                scope.add("scope:" + key + "=" + value)
                i += 1 if sep else 2
            elif len(word) > 2 and word[:2] in values and not word.startswith("--"):
                scope.add("scope:" + word[:2] + "=" + word[2:])
                i += 1
            elif key in flags:
                if key == "--dry-run" and (not sep or word.split("=", 1)[1].casefold() != "false"):
                    return False
                i += 1
            else:
                facts.append(Fact("unresolved", "unknown-option", payload=key))
                facts.append(Fact("unresolved", "unresolved-value", payload="Docker subcommand binding is unresolved"))
                return False
        return True
    if not skip(GLOBAL_VALUES, GLOBAL_FLAGS):
        return facts
    command = words[i] if i < len(words) else None
    i += 1
    group = command if command in GROUPS else None
    if group:
        if not skip(GROUP_VALUES, GROUP_FLAGS):
            return facts
        command = words[i] if i < len(words) else None
        i += 1
    # Only Docker options before the payload belong to Docker: `docker exec c
    # program --help` executes program and is not Docker's help invocation.
    effect_values = effect_value_options(group, command)
    own_tail = []
    j = i
    while j < len(words) and words[j] and words[j].startswith("-"):
        own_tail.append(words[j])
        if words[j] in {"--help", "-h"}:
            return facts
        j += 2 if words[j] in effect_values else 1
    if command not in {"run", "exec"} and any(w in {"--help", "-h"} for w in words[i:]):
        return facts
    option_tail = own_tail if command in {"run", "exec"} else words[i:]
    if group == "compose" and any(w in {"--dry-run", "--dry-run=true"} for w in option_tail):
        return facts
    queries, effects = GROUP_COMMANDS[group] if group else (QUERIES, EFFECTS)
    writes_config = group == "compose" and command == "config" and any(w and (w in {"--output", "-o"} or w.startswith("--output=")) for w in option_tail)
    if command in queries and not writes_config or command is None and group:
        if command is not None:
            from ..shared.options import parse_options
            spec = query_spec(group, command)
            tail = tuple(Value(w.split("=", 1)[0]) if w and w.split("=", 1)[0] in spec.long and w.endswith(("=true", "=false")) else v
                         for w, v in zip(words[i:], args[i:]))
            operands, _, bound, unknown = parse_options(tail, spec)
            facts.extend(Fact("unresolved", "unknown-option", payload=option) for option in unknown)
            if any(v.text is None for v in (*operands, *bound.values())):
                facts.append(Fact("unresolved", "unresolved-value", payload="Docker query arguments are not fully resolved"))
        return facts
    if command not in effects and not writes_config:
        return facts + [Fact("unresolved", "unknown-command", payload="Unsupported Docker operation")]
    output_values = [w.split("=", 1)[1] for w in option_tail if w and w.startswith("--output=")]
    output_values.extend(option_tail[j + 1] for j, w in enumerate(option_tail[:-1]) if w in {"--output", "-o"})
    publishing = command in {"push", "deploy"} or command in {"build", "bake"} and (
        any(w in {"--push", "--push=true"} for w in option_tail)
        or any(v and ("type=registry" in v or "push=true" in v) for v in output_values))
    # Preserve resource operands, excluding known option values and the opaque
    # run/exec program arguments. Payload words are not resource identifiers.
    operands, option_flags, cursor = [], set(), i
    options_ended = False
    while cursor < len(args):
        word = words[cursor]
        if not options_ended and word == "--":
            options_ended = True
            cursor += 1
            continue
        if not options_ended and word and word.startswith("-"):
            key, sep, _ = word.partition("=")
            option_flags.add(key)
            cursor += 1 if sep or key not in effect_values else 2
            continue
        operands.append(args[cursor])
        if command in {"run", "exec"}:
            break
        cursor += 1
    facts.append(Fact("network" if publishing else "system", "publish" if publishing else "docker-change",
                      targets=tuple(v.text for v in operands if v.text is not None) if not publishing else (),
                      values=args if publishing else tuple(operands),
                      flags=frozenset({"local_file_payload"}) if publishing else frozenset(scope | option_flags),
                      payload=" ".join(w for w in (group, command) if w)))
    if any(w is None for w in words):
        facts.append(Fact("unresolved", "unresolved-value", payload="Docker arguments are not fully resolved"))
    return facts
