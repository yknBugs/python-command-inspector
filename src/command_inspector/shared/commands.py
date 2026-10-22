"""Supported invocation/option models. These derive facts, never findings."""
from dataclasses import replace
import posixpath
import re
from ..models import Fact, Value
from .options import CommandSpec
from .auth import authentication_values


INTERPRETERS = {"bash", "sh", "zsh", "python", "python3", "python3.11", "node"}
TASKS = {"make", "pytest", "npm", "pip", "pip3", "npx", "pnpm", "yarn", "twine"}

#: Commands whose operand is a network destination that receives standard input.
NETWORK_SINKS = {"nc", "netcat", "ncat", "socat"}

#: Names that argue a file holds credentials even before its content is read. Used
#: only where the operation itself transmits or copies the file, so a name is
#: never the sole reason for a read finding.
_CREDENTIAL_PATH = re.compile(
    r"(?:^|/)(?:\.env(?:\.[^/]*)?|\.netrc|\.npmrc|\.pgpass|\.git-credentials|\.htpasswd"
    r"|credentials(?:\.(?:json|ya?ml|ini|txt))?|secrets?(?:\.(?:json|ya?ml|ini|txt))?"
    r"|id_(?:rsa|dsa|ecdsa|ed25519)|[^/]*\.(?:pem|key|p12|pfx)"
    r"|\.aws/credentials|\.ssh/[^/]+|\.kube/config|\.docker/config\.json)$")


def credential_like_path(text: str | None) -> bool:
    return bool(text) and _CREDENTIAL_PATH.search(text.replace("\\", "/")) is not None


#: `[user@]host:path`, the remote side of scp/rsync-style operands.
REMOTE_SPEC = re.compile(r"^(?:scp://|(?:[^@/\s]+@)?(?:\[[^\]]+\]|[^:/\s]+):)")
def remote_operand(text: str | None) -> bool:
    # Windows drive paths are local operands, even on a Linux analysis host.
    return bool(text and not re.match(r"^[A-Za-z]:[\\/]", text)
                and (REMOTE_SPEC.search(text) or text.startswith("rsync://")))


def route_file_payload(facts, network_index, sources=None):
    """Attach visible local read sources to a sink, without additional findings."""
    sink = facts[network_index]
    if sink.kind == "invoke":
        if sources is None:
            sources = tuple(v for f in facts for v in visible_read_sources(f))
        if sources:
            facts[network_index] = replace(sink, stdin_sources=tuple(sources))
        return facts
    if "stdin_redirected" in sink.flags:
        return facts
    if sources is not None and "routed_file_payload" in sink.flags:
        removed = {"local_file_payload", "file_sources", "routed_file_payload"}
        if "routed_credential" in sink.flags:
            removed |= {"credential_payload", "routed_credential"}
        sink = replace(sink, values=(), flags=sink.flags - removed)
        facts[network_index] = sink
    if sources is None:
        sources = tuple(v for f in facts for v in visible_read_sources(f))
    if not sources:
        return facts
    if "stdin_ignored" in sink.flags:
        return facts
    flags = sink.flags | {"local_file_payload", "file_sources", "routed_file_payload"}
    if any(credential_like_path(v.text) for v in sources):
        flags |= {"credential_payload", "routed_credential"}
    facts[network_index] = replace(sink, values=sources, flags=flags)
    return facts


def visible_read_sources(fact, depth=0):
    """Visible wrapped readers for publication routing; no evidence or execution."""
    if fact.flags & {"output_consumed", "not_stdin"}:
        return ()
    if fact.kind == "read" and fact.operation == "ingest":
        return fact.values
    if fact.kind == "invoke":
        if depth >= 3:
            return (Value(None, "wrapped_source_budget"),)
        children = wrapped_facts(fact)
        sources = tuple(v for child in children for v in visible_read_sources(child, depth + 1))
        if fact.flags & {'override_cwd', 'unknown_cwd'}:
            from ..paths import style_for
            directory = children[0].cwd if children else None
            paths = style_for(fact.shell, directory or fact.cwd or '/')
            sources = tuple(Value(paths.resolve(v, directory), 'wrapped_source_directory') for v in sources)
        return sources
    return ()


def stdin_network_sink(fact, depth=0):
    if fact.kind == "network":
        return "stdin_sink" in fact.flags
    if fact.kind == "invoke" and depth < 3:
        return any(stdin_network_sink(child, depth + 1) for child in wrapped_facts(fact))
    return False


def wrapped_command_name(fact):
    from .path_commands import is_command_path
    if is_command_path(fact.operation, fact.shell):
        return fact.operation
    return fact.operation.casefold().removesuffix('.exe') if fact.shell in {'powershell', 'cmd'} else fact.operation


def wrapped_facts(fact):
    """Static wrapper children for flow metadata; never inspect their artifacts."""
    from ..paths import style_for
    directory = None if 'unknown_cwd' in fact.flags else fact.cwd
    if 'override_cwd' in fact.flags:
        directory = style_for(fact.shell, fact.cwd or fact.payload or '/').resolve(Value(fact.payload), fact.cwd)
    return tuple(replace(child, cwd=directory, shell=fact.shell) for child in
                 describe(wrapped_command_name(fact), fact.values, directory, shell=fact.shell))

SCP_SPEC = CommandSpec("346ABCOpqRrTv", ("--",),
                       tuple("-" + c for c in "cDFiJloPSX"))
RSYNC_SPEC = CommandSpec("avzPrtpgolDHAEXRLWnqchuxS",
    ("--archive", "--verbose", "--compress", "--recursive", "--delete", "--delete-before",
     "--delete-after", "--delete-during", "--delete-excluded", "--dry-run", "--progress", "--partial",
     "--checksum", "--quiet", "--stats", "--human-readable", "--itemize-changes", "--numeric-ids",
     "--relative", "--copy-links", "--links", "--times", "--perms", "--owner", "--group", "--"),
    ("-e", "--rsh", "--exclude", "--include", "--exclude-from", "--include-from", "--files-from",
     "--filter", "-f", "--rsync-path", "--port", "--bwlimit", "--password-file", "--log-file"))

#: Flags accepted for the modeled task runners. As with Git, only genuinely
#: unrecognised options should surface.
_TASK_FLAGS = {
    "-q", "-v", "--verbose", "--quiet", "-g", "--global", "-S", "--save", "-D", "--save-dev",
    "--no-save", "--save-exact", "-E", "--legacy-peer-deps", "--production", "--omit", "--include",
    "--force", "-f", "--fund", "--audit", "--no-audit", "--package-lock", "--no-package-lock",
    "-r", "--requirement", "--user", "--upgrade", "-U", "--no-cache-dir", "--index-url", "-i",
    "--target", "-t", "--prefix", "--dry-run", "--yes", "-y", "--no-input", "-e", "--editable",
    "--only-binary", "--no-deps", "--pre", "--break-system-packages", "--disable-pip-version-check",
    "--progress-bar", "--cache-dir", "--no-build-isolation", "--timeout", "--retries", "--root",
    "--no-warn-script-location", "--require-hashes", "--constraint", "-c", "--python", "-p",
    "--package", "--call", "--shell", "--ignore-existing", "--no-install", "--registry", "--workspace",
    "-w", "--k", "--loglevel", "--prefer-offline", "--no-fund", "--include=dev", "--cwd", "--dir",
    "--cache-folder", "--userconfig",
    "--access", "--tag", "--otp", "--provenance", "--repository", "--repository-url", "--skip-existing",
    # Build runners: `make`/`ninja`-style flags, including the attached job count.
    "-k", "--keep-going", "-s", "--silent", "-n", "--dry-run", "-B", "--always-make", "-C", "--directory",
    "-f", "--file", "--makefile", "-e", "--environment-overrides", "-I", "--include-dir", "-i",
    "--ignore-errors", "-r", "--no-builtin-rules", "-R", "--no-builtin-variables", "-S", "--no-keep-going",
    "--no-print-directory", "-p", "--print-data-base", "-d", "--debug", "-L", "--check-symlink-times",
    "-O", "--output-sync", "-l", "--load-average", "--warn-undefined-variables", "--trace",
}

#: Flags that carry a numeric or bare value and so cannot be enumerated.
_TASK_FLAG_PATTERNS = (
    re.compile(r"^-[A-Za-z]*[jJ]\d*$"),          # -j, -j4, -kj4
    re.compile(r"^--jobs(=\d+)?$"),
    re.compile(r"^-O\d*$"),
    re.compile(r"^--output-sync(=[a-z]+)?$"),
    re.compile(r"^-l(\d+(\.\d+)?)?$"),
    re.compile(r"^--load-average(=\d+(\.\d+)?)?$"),
)


def task_flag_known(word: str) -> bool:
    name = word.split("=")[0]
    return name in _TASK_FLAGS or any(pattern.match(word) for pattern in _TASK_FLAG_PATTERNS)


#: How an interpreter consumes its own leading options. "flag" takes no value,
#: "value" consumes the next token, "code" means the next token is source to
#: inspect and ends the option run, "module" is Python's `-m`, and "stdin" means
#: the program arrives on standard input.
INTERPRETER_OPTIONS: dict[str, dict[str, str]] = {
    "shell": {"-c": "code", "-s": "stdin", "-e": "flag", "-x": "flag", "-u": "flag",
              "-n": "flag", "-l": "flag", "-i": "flag", "-o": "value", "+o": "value",
              "--login": "flag", "--noprofile": "flag", "--norc": "flag",
              "--posix": "flag", "--version": "flag", "--help": "flag", "-h": "flag"},
    "python": {"-c": "code", "-m": "module", "-u": "flag", "-B": "flag", "-E": "flag",
               "-I": "flag", "-O": "flag", "-OO": "flag", "-q": "flag", "-s": "flag",
               "-S": "flag", "-v": "flag", "-V": "flag", "--version": "flag",
               "-h": "flag", "--help": "flag", "-W": "value", "-X": "value",
               "--check-hash-based-pycs": "value"},
    "javascript": {"-e": "code", "--eval": "code", "-p": "code", "--print": "code",
                   "-r": "value", "--require": "value", "-v": "flag",
                   "--version": "flag", "-h": "flag", "--help": "flag"},
}

#: `sudo`'s own options, which precede the command it runs. One parse over the
#: whole argument list read `rm`'s `-rf` as sudo options and then returned before
#: analysing the deletion at all.
SUDO_SPEC = CommandSpec(
    "nEbHASkKviVhlPs",
    ("--preserve-env", "--login", "--shell", "--stdin", "--askpass", "--background",
     "--non-interactive", "--set-home", "--reset-timestamp", "--validate", "--list",
     "--help", "--version", "--edit", "--"),
    ("-u", "--user", "-g", "--group", "-h", "--host", "-p", "--prompt", "-C", "--chdir",
     "-T", "--command-timeout", "-r", "--role", "-t", "--type", "-c", "--close-from",
     "--other-user"),
)


def split_interpreter_args(words: list[str | None], language: str):
    """Separate an interpreter's own leading options from the script it runs.

    Returns ``(options, unknown, operand_start)``, where ``options`` is a tuple of
    ``(option, kind, value)`` in order and ``operand_start`` indexes the first
    token belonging to the script.

    Only the leading run belongs to the interpreter. The first non-option token is
    the script and everything after it is that script's argument vector: ``bash
    B.sh -c true`` passes ``-c true`` to B.sh, and ``python demo.py --help`` asks
    demo.py for help. Scanning the whole word list for ``-`` tokens read ``-c`` as
    bash's inline-code option and never opened B.sh.
    """
    spec = INTERPRETER_OPTIONS.get(language, {})
    options: list[tuple[str, str, str | None]] = []
    unknown: list[str] = []
    index = 0
    while index < len(words):
        word = words[index]
        if word is None:
            break
        if word == "--":
            index += 1
            break
        is_option = word.startswith("-") or (language == "shell" and word.startswith("+"))
        if not is_option or word == "-":
            break
        if word.startswith("--"):
            base, sep, attached = word.partition("=")
            parts = [(base, spec.get(base), attached if sep else None)]
        elif word in spec:
            parts = [(word, spec[word], None)]
        else:
            parts = []
            for offset, letter in enumerate(word[1:], 1):
                base = word[0] + letter
                kind = spec.get(base)
                if kind is None:
                    parts.append((base, None, None))
                    break
                # Bash -c takes the next argument; Python accepts -cCODE/-mMODULE.
                if kind in {"value", "code", "module"}:
                    if kind == "code" and language == "shell" and offset + 1 < len(word):
                        parts.append((word, None, None))
                    else:
                        parts.append((base, kind, word[offset + 1:] or None))
                    break
                parts.append((base, kind, None))
        index += 1
        for base, kind, attached in parts:
            if kind is None:
                unknown.append(base)
                continue
            value = None
            if kind in {"code", "value", "module"}:
                if attached is not None:
                    value = attached
                elif index < len(words):
                    value = words[index]
                    index += 1
                if value is None:
                    unknown.append(base)
            options.append((base, kind, value))
        if any(kind in {"code", "module"} for _, kind, _ in parts):
            break
    return tuple(options), tuple(unknown), index


def resolve_path(value: Value, cwd: str | None) -> str | None:
    if value.text is None or value.text.startswith("~"):
        return None
    if not posixpath.isabs(value.text) and cwd is None:
        return None
    if value.pattern:
        return None  # Pattern selection belongs to detector-requested evidence.
    return posixpath.normpath(posixpath.join(cwd or "/", value.text))


def describe(name: str, args: tuple[Value, ...], cwd: str | None, *, shell="bash") -> list[Fact]:
    facts = _describe_invocation(name, args, cwd, shell=shell)
    # Preserve auth context before command models discard passwords from their
    # public effect operands. Plain passwords cannot be redacted by shape alone.
    credentials = authentication_values(name, args)
    sensitive = {name for value in credentials for name in value.variables}
    if any(value.text is None for value in credentials):
        sensitive.update(name for argument in args for name in argument.variables)
    return [replace(f, sensitive_variables=f.sensitive_variables | sensitive,
                    credential_values=f.credential_values + credentials) for f in facts]


def _describe_invocation(name: str, args: tuple[Value, ...], cwd: str | None, *, shell="bash") -> list[Fact]:
    from .path_commands import is_command_path, is_source_path, command_basename
    if is_command_path(name, shell):
        if is_source_path(name):
            return [Fact("execute", "artifact", values=(Value(name),))]
        marker = Fact("path_invocation", "execute", values=(Value(name),))
        return [marker, *(replace(fact, command_path=name,
                                  command_name=name if fact.operation == "unknown-command" else fact.command_name)
                          for fact in describe(command_basename(name, shell), args, cwd, shell=shell))]
    return [replace(fact, command_name=name)
            if fact.kind == "unresolved" and fact.operation == "unknown-command" else fact
            for fact in _describe(name, args, cwd, shell=shell)]


def _describe(name: str, args: tuple[Value, ...], cwd: str | None, *, shell="bash") -> list[Fact]:
    from .builtins import command_registry
    from .registry import CommandInvocation
    # Generic wrappers historically accept POSIX command profiles even from a
    # Windows shell (conda run ... rm). The original shell still supplies path
    # semantics; direct native dispatch uses supports_native_command instead.
    facts = command_registry().describe(CommandInvocation(name, args, cwd, shell), fallback_shell="bash")
    return facts if facts is not None else [Fact("unresolved", "unknown-command", payload=name)]
