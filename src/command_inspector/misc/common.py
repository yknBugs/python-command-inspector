"""Common filesystem, search, network and task-runner command facts."""
import re
from ..models import Fact, Value
from ..shared.options import CommandSpec, parse_options


SPECS = {
    "mv": CommandSpec("finvTb", ("--force", "--interactive", "--no-clobber", "--verbose", "--no-target-directory", "--target-directory", "--help", "--version", "--"), ("-t", "--target-directory")),
    "cp": CommandSpec("afinprRdvPLHTbs", ("--archive", "--force", "--interactive", "--no-clobber", "--recursive", "--verbose", "--no-target-directory", "--target-directory", "--preserve", "--help", "--version", "--"), ("-t", "--target-directory")),
    "rm": CommandSpec("rRfivd", ("--recursive", "--force", "--verbose", "--interactive", "--dir", "--preserve-root", "--no-preserve-root", "--")),
    "cat": CommandSpec("nbsETvA", ("--number", "--")),
    "ls": CommandSpec("alhRdtAFSr1", ("--all", "--long", "--")),
    "mkdir": CommandSpec("pv", ("--parents", "--verbose", "--mode", "--"), ("--mode",)),
    "tee": CommandSpec("ai", ("--append", "--ignore-interrupts", "--")),
    "chmod": CommandSpec("Rfv", ("--recursive", "--verbose", "--")),
    "curl": CommandSpec("sSLIfkOvXHdouTF",
                        ("--silent", "--show-error", "--location", "--head", "--fail", "--insecure",
                         "--output", "--remote-name", "--request", "--header", "--data", "--data-raw",
                         "--data-binary", "--data-urlencode", "--json", "--form", "--upload-file",
                         "--user", "--url", "--form-string", "--"),
                        ("-X", "-H", "-d", "-F", "-T", "-o", "-u", "--output", "--request", "--header",
                         "--data", "--data-raw", "--data-binary", "--data-urlencode", "--json", "--form",
                         "--upload-file", "--user", "--url", "--form-string")),
    "wget": CommandSpec("qO", ("--quiet", "--output-document", "--post-file", "--body-file",
                                 "--post-data", "--body-data", "--method", "--"),
                        ("-O", "--output-document", "--post-file", "--body-file", "--post-data", "--body-data", "--method")),
    "kill": CommandSpec("", ("-9", "-KILL", "-s", "--signal", "-1", "-2", "-3", "-6", "-15", "-HUP", "-INT",
                             "-QUIT", "-TERM", "-STOP", "-CONT", "-USR1", "-USR2", "-0", "-l", "-L", "-V",
                             "--help", "--version", "--"), ("-s", "--signal")),
    "pkill": CommandSpec("efxavn", ("--full", "--exact", "--list-name", "--newest", "--oldest", "--",
                                    "-9", "-KILL", "-TERM", "-l", "-L", "-V", "-h", "--help", "--version"),
                         ("-s", "--signal")),
    "killall": CommandSpec("eiIqvwgrus", ("--exact", "--interactive", "--ignore-case", "--quiet", "--verbose",
                                          "--wait", "--regexp", "--user", "--signal", "--", "-9", "-KILL",
                                          "-TERM", "-l", "-L", "-V", "-h", "--help", "--version"),
                           ("-s", "--signal", "-u", "--user")),
    "cd": CommandSpec("LP", ("--",)),
    "less": CommandSpec("RrSNFXfqiIQegG", ("--RAW-CONTROL-CHARS", "--raw-control-chars", "--chop-long-lines", "--quit-if-one-screen", "--no-init", "--line-numbers", "--ignore-case", "--IGNORE-CASE", "--"), ("-P", "-p", "--prompt", "--pattern")),
    "more": CommandSpec("dlfpcsu", ("--silent", "--logical", "--no-pause", "--print-over", "--clean-print", "--squeeze", "--"), ("-n", "--lines")),
    "pwd": CommandSpec("LP"),
    "wc": CommandSpec("clwmL", ("--bytes", "--lines", "--words", "--chars", "--")),
    "grep": CommandSpec("nFEGPiwxlLcqvrsRhoHza", ("--fixed-strings", "--extended-regexp", "--perl-regexp", "--ignore-case", "--files-with-matches", "--files-without-match", "--count", "--quiet", "--recursive", "--line-number", "--no-messages", "--", "--help", "--version"), ("-e", "-f", "-m", "-A", "-B", "-C", "--regexp", "--file", "--max-count", "--after-context", "--before-context", "--context", "--include", "--exclude", "--exclude-dir")),
    "rg": CommandSpec("nFiclLqvrswxoHzaU", ("--fixed-strings", "--ignore-case", "--files-with-matches", "--files-without-match", "--count", "--quiet", "--files", "--line-number", "--hidden", "--no-ignore", "--no-heading", "--heading", "--follow", "--multiline", "--", "--help", "--version", "--stats"), ("-r", "--replace", "-g", "--glob", "--iglob", "-e", "--regexp", "-f", "--file", "-t", "--type", "-T", "--type-not", "-m", "--max-count", "-A", "-B", "-C", "--context", "--max-depth", "--color", "--sort", "--sortr", "--encoding")),
}


def describe_common(name: str, args: tuple[Value, ...], cwd: str | None, *, shell="bash") -> list[Fact]:
    from ..shared.commands import (resolve_path, credential_like_path, remote_operand,
                                   INTERPRETERS, TASKS, NETWORK_SINKS, SCP_SPEC, RSYNC_SPEC, task_flag_known)
    facts = []
    def fact(kind, operation, operands=(), flags=frozenset(), payload=None):
        paths = tuple(p for v in operands if (p := resolve_path(v, cwd)) is not None)
        facts.append(Fact(kind, operation, paths, tuple(operands), flags, payload))

    spec = SPECS.get(name)
    if spec:
        operands, flags, bound, unknown = parse_options(args, spec)
        for option in unknown:
            facts.append(Fact("unresolved", "unknown-option", payload=option))
        if unknown and name in {"rm", "cat", "ls", "mkdir", "tee", "chmod", "cd", "grep", "rg"}:
            # Unknown arity can change operands; do not bind speculative targets.
            operands = (Value(None, "unknown_option_operand_binding"),)
        if name in {"cp", "mv"}:
            if flags & {"--help", "--version"}:
                return facts
            directory = bound.get("-t", bound.get("--target-directory"))
            sources, destination = (operands, directory) if directory is not None else (operands[:-1], operands[-1] if len(operands) >= 2 else Value(None, "missing_destination"))
            if unknown:
                sources, destination = (Value(None, "unknown_option_operand_binding"),), Value(None, "unknown_option_operand_binding")
            if not sources:
                sources = (Value(None, "missing_source"),)
            transfer_flags = flags | ({"destination_directory"} if directory is not None or len(sources) > 1 else set())
            if (directory is not None or len(sources) > 1) and flags & {"-T", "--no-target-directory"}:
                facts.append(Fact("unresolved", "unresolved-value", payload="Conflicting file transfer destination forms"))
                destination = Value(None, "conflicting_destination_forms")
            fact("read", "list", sources)
            facts.append(Fact("transfer", "copy" if name == "cp" else "move", values=(destination,), flags=frozenset(transfer_flags), transfer_sources=tuple(sources)))
        elif name == "rm":
            fact("delete", "delete", operands, flags)
        elif name in {"cat", "ls"}:
            fact("read", "ingest" if name == "cat" else "list", operands, flags)
        elif name in {"grep", "rg"}:
            if flags & {"--help", "--version"}:
                return facts
            patterns = [v for k, v in bound.occurrences if k in {"-e", "--regexp"}]
            pattern_files = [v for k, v in bound.occurrences if k in {"-f", "--file"}]
            if patterns:
                pattern, targets = patterns[0], operands
            elif pattern_files:
                pattern, targets = Value(None), operands
            elif operands:
                pattern, targets = operands[0], operands[1:]
            else:
                pattern, targets = Value(None), ()
            for value in pattern_files:
                fact("read", "list", (value,))
            if "--files" in flags:
                fact("read", "list", operands or (Value("."),), flags)
            elif targets:
                if flags & {"-l", "-c", "-q", "--files-with-matches", "--count", "--quiet"}:
                    flags = flags | {"output_consumed"}
                elif (pattern.text is not None and len(patterns) <= 1 and not pattern_files
                      and not bound.keys() & {"-r", "--replace", "-A", "-B", "-C", "--context", "--after-context", "--before-context"}
                      and flags & {"-F", "--fixed-strings"}):
                    flags = flags | {"fixed_filter"}
                else:
                    flags = flags | {"selection_uncertain"}
                fact("read", "ingest", targets, flags | ({"search_recursive"} if name == "rg" or flags & {"-r", "-R", "--recursive"} else set()), pattern.text)
            elif unknown:
                fact("read", "ingest", operands, flags)
            elif name == "rg":
                consumed = bool(flags & {"-l", "-c", "-q", "--files-with-matches", "--count", "--quiet"})
                fact("read", "ingest", (Value("."),), flags | {"search_recursive", "selection_uncertain"} | ({"output_consumed"} if consumed else set()), pattern.text)
        elif name in {"mkdir", "tee"}:
            fact("write", "create_directory" if name == "mkdir" else "append" if "-a" in flags or "--append" in flags else "overwrite", operands, flags)
        elif name == "chmod":
            mode = operands[0].text if operands else None
            fact("permissions", mode or "unresolved", operands[1:], flags)
        elif name in {"curl", "wget"}:
            urls = [v.text for v in operands if v.text and re.match(r"https?://", v.text)]
            urls.extend(v.text for key, v in bound.occurrences if key == "--url" and v.text)
            download = name == "wget" or bool(flags & {"-o", "-O", "--output", "--remote-name"})
            # An upload whose payload names a credential file is a transmission even
            # when the bytes are not visible, so `--data-binary @.env` is not merely
            # an ordinary request.
            uploads = []
            for key, value in bound.occurrences:
                text = value.text
                if key in {"-T", "--upload-file", "--post-file", "--body-file"}:
                    uploads.append(text)
                elif text is None and key in {"-d", "--data", "--data-binary", "--json", "--data-urlencode", "-F", "--form"}:
                    uploads.append(None)
                elif not text:
                    continue
                elif key in {"-d", "--data", "--data-binary", "--json"} and text.startswith("@"):
                    uploads.append(text[1:])
                elif key == "--data-urlencode" and "@" in text and "=" not in text.split("@", 1)[0]:
                    uploads.append(text.split("@", 1)[1])
                elif key in {"-F", "--form"}:
                    _, sep, field = text.partition("=")
                    if sep and field.startswith(("@", "<")):
                        uploads.extend(part.strip('"') for part in field[1:].split(";", 1)[0].split(","))
            if any(credential_like_path(path) for path in uploads):
                flags = flags | {"credential_payload"}
            if uploads or flags & {"-T", "--upload-file", "--post-file", "--body-file"}:
                flags = flags | {"local_file_payload", "file_sources"}
            facts.append(Fact("network", "download" if download else "request", tuple(urls),
                              tuple(Value(p) for p in uploads) if uploads else args,
                              flags, " ".join(v.text or "" for v in args)))
            for key in ("-o", "--output", "-O", "--output-document"):
                if key in bound and bound[key].text != "-":
                    fact("write", "download", (bound[key],))
            if not urls:
                facts.append(Fact("unresolved", "unresolved-value", payload="Network destination is unresolved"))
        elif name in {"kill", "pkill", "killall"}:
            # `-0` probes for a process and `-l`/`-V`/`--help` report; none of them
            # terminate anything, and no rule models a process query.
            inspecting_only = bool(flags & {"-l", "-L", "-V", "-h", "--help", "--version"})
            signal_keys = ("--signal", "-s") if name in {"kill", "killall"} else ("--signal",)
            selected = next((bound[k].text for k in signal_keys if k in bound), None)
            if selected is None:
                selected = next((v.text[1:] for v in reversed(args)
                                 if v.text in {"-0", "-9", "-KILL", "-TERM", "-STOP", "-CONT"}), "TERM")
            signal = selected.upper().removeprefix("SIG") if selected is not None else None
            if not inspecting_only and signal not in {"0", "STOP", "CONT", "TSTP", "TTIN", "TTOU"}:
                forced = signal in {"9", "KILL"}
                targets = tuple(v.text or "unresolved" for v in operands) or ("unresolved",)
                facts.append(Fact("system", "force-process-termination", targets, args, flags,
                                  "force" if forced else "terminate"))
        elif name in {"less", "more"}:
            fact("read", "list", operands, flags)
        elif name == "cd":
            if not operands or any(v.text is None for v in operands):
                facts.append(Fact("unresolved", "unresolved-value", payload="Working directory is unresolved"))
            if operands:
                fact("read", "list", operands, flags)
        return facts
    if name in INTERPRETERS:
        facts.append(Fact("execute", name, values=args))
    elif name in {"echo", "printf", "true", "false", ":"}:
        pass
    elif name in TASKS:
        words = [v.text for v in args]
        urls = [w for w in words if w and re.match(r"(?:https?://|git\+|git://|ssh://)", w)]
        subcommand = next((word for word in words if word and not word.startswith("-")), None)
        if name in {"npm", "pnpm", "yarn", "twine"}:
            index = 0
            root_values = {"--prefix", "--registry", "--workspace", "-w", "--cwd", "--dir", "-C",
                           "--repository", "--repository-url", "--cache-folder", "--userconfig"}
            while index < len(words) and words[index] and words[index].startswith("-"):
                key, sep, _ = words[index].partition("=")
                index += 2 if key in root_values and not sep else 1
            subcommand = words[index] if index < len(words) else None
            subwords = words[index:]
        else:
            subwords = words
        installing = name in {"npm", "pip", "pip3"} and subcommand in ({"install", "i"} if name == "npm" else {"install"})
        if installing:
            facts.append(Fact("system", "package-install"))
        publishing = ((name in {"npm", "pnpm", "yarn"} and subcommand == "publish")
                      or name == "yarn" and subwords[:2] == ["npm", "publish"]
                      or name == "twine" and subcommand == "upload")
        if publishing and "--dry-run" not in words:
            facts.append(Fact("network", "publish", tuple(urls), args,
                              frozenset({"local_file_payload"}), payload=name + " publish"))
        if urls and not publishing:
            # A package or tool fetched by URL is code this call downloads and then
            # runs; its contents are not available to the analysis.
            facts.append(Fact("network", "download", tuple(urls), args, frozenset(),
                              " ".join(v.text or "" for v in args)))
            if name == "npx" or installing:
                facts.append(Fact("unresolved", "execution-content-unavailable",
                                  payload="Runs fetched package code whose contents are unavailable"))
        for word in words:
            if word and word.startswith("-") and not task_flag_known(word):
                facts.append(Fact("unresolved", "unknown-option", payload=word.split("=")[0]))
    elif name in {"reboot", "shutdown", "poweroff", "halt", "umount"}:
        fact("system", "unmount-drive" if name == "umount" else "machine-power-change", args)
    elif name in {"scp", "rsync"}:
        operands, flags, _, unknown = parse_options(args, SCP_SPEC if name == "scp" else RSYNC_SPEC)
        for option in unknown:
            facts.append(Fact("unresolved", "unknown-option", payload=option))
        if flags & {"--dry-run", "-n"}:
            return facts
        if unknown:
            facts.append(Fact("unresolved", "unresolved-value", payload="Transfer source and destination binding is unresolved"))
            # Preserve a possible publication even when unknown option arity
            # prevents an exact source/destination list.
            if any(remote_operand(v.text) for v in args):
                facts.append(Fact("network", "publish", values=args, flags=frozenset({"local_file_payload"})))
            return facts
        texts = [v.text for v in operands]
        remote = [t for t in texts if remote_operand(t)]
        destination = texts[-1] if texts else None
        sources = texts[:-1]
        upload = len(texts) >= 2 and (remote_operand(destination) or destination is None)
        download = any(remote_operand(t) for t in sources)
        local_sources = any(not remote_operand(t) for t in sources)
        publish = upload and local_sources
        effect_flags = {"local_file_payload", "file_sources"} if publish else set()
        if publish and any(credential_like_path(s) for s in sources):
            effect_flags.add("credential_payload")
        facts.append(Fact("network", "download" if download else "upload" if upload else "request",
                          tuple(remote), tuple(v for v in operands[:-1] if not remote_operand(v.text)) if publish else args,
                          frozenset(effect_flags),
                          " ".join(t or "" for t in texts)))
        if any(t is None for t in texts):
            facts.append(Fact("unresolved", "unresolved-value", payload="Transfer source or destination is unresolved"))
    elif name in NETWORK_SINKS:
        endpoints = [v.text for v in args if v.text and not v.text.startswith("-")]
        ignored = (name in {"nc", "netcat"} and any(v.text and re.fullmatch(r"-[A-Za-z]*[zd][A-Za-z]*", v.text) for v in args)
                   or name == "ncat" and any(v.text in {"-z", "--recv-only"} for v in args))
        flags = frozenset({"stdin_sink", "stdin_ignored"}) if ignored else frozenset({"stdin_sink"})
        facts.append(Fact("network", "upload", (":".join(endpoints[:2]),) if endpoints else (), args, flags,
                          " ".join(v.text or "" for v in args)))
        if not endpoints:
            facts.append(Fact("unresolved", "unresolved-value", payload="Network destination is unresolved"))
    elif name == "dd":
        for value in args:
            if value.text and value.text.startswith(("if=", "of=")):
                key, target = value.text.split("=", 1)
                fact("device", "read" if key == "if" else "write", (Value(target),))
            elif value.text and not value.text.startswith(("bs=", "count=", "status=")):
                facts.append(Fact("unresolved", "unresolved-value", payload="Unsupported dd operand"))
    else:
        facts.append(Fact("unresolved", "unknown-command", payload=name))
    return facts

