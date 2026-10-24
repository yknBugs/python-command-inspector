"""Static Git invocation models; never consult repository state or run Git."""
import re
from urllib.parse import urlsplit, unquote
from ..models import Fact, Value
from ..reporting import contains_secret
from ..paths import style_for


MINOR_KEYS = {
    "core.filemode", "core.autocrlf", "core.eol", "core.safecrlf", "core.quotepath",
    "i18n.commitencoding", "i18n.logoutputencoding", "gui.encoding",
}
SENSITIVE_KEYS = {"core.sshcommand", "core.hookspath", "safe.directory"}
QUERY_ACTIONS = {"get", "list", "--get", "--get-all", "--get-regexp", "--get-urlmatch",
                 "--get-color", "--get-colorbool", "--list", "-l"}
WRITE_ACTIONS = {"set", "unset", "rename-section", "remove-section", "edit", "--unset",
                 "--unset-all", "--add", "--replace-all", "--rename-section", "--remove-section",
                 "--edit", "-e"}
CONFIG_VALUES = {"--file", "-f", "--blob", "--type", "--default", "--value", "--comment"}
CONFIG_FLAGS = {"--global", "--system", "--local", "--worktree", "--show-origin", "--show-scope",
                "--includes", "--no-includes", "--null", "-z", "--name-only", "--fixed-value",
                "--no-value", "--all", "--append", "--replace-all", "--value", "--bool",
                "--int", "--bool-or-int", "--path", "--expiry-date", "--help", "-h"}
PUSH_VALUES = {"--repo", "--receive-pack", "--exec", "--push-option", "-o"}
PUSH_FLAGS = {"--all", "--branches", "--mirror", "--tags", "--follow-tags", "--atomic",
              "--signed", "--no-signed", "--dry-run", "--force", "--no-force", "--delete",
              "--prune", "--no-prune", "--force-with-lease", "--no-force-with-lease",
              "--force-if-includes", "--no-force-if-includes", "--set-upstream", "--no-verify",
              "--thin", "--no-thin", "--progress", "--quiet", "--verbose", "--ipv4", "--ipv6",
              "--recurse-submodules", "--help", "-h"}
CLONE_VALUES = {"-o", "--origin", "-b", "--branch", "--revision", "-u", "--upload-pack", "--template",
                "--reference", "--reference-if-able", "--separate-git-dir", "--depth", "--shallow-since",
                "--shallow-exclude", "--filter", "-j", "--jobs", "-c", "--config", "--server-option", "--bundle-uri", "--ref-format"}
CLONE_FLAGS = {"--local", "--no-local", "--no-hardlinks", "--shared", "--dissociate", "--quiet", "--verbose",
               "--progress", "--no-checkout", "--bare", "--mirror", "--sparse", "--single-branch", "--no-single-branch",
               "--tags", "--no-tags", "--recurse-submodules", "--recursive", "--no-recurse-submodules",
               "--shallow-submodules", "--no-shallow-submodules", "--remote-submodules", "--no-remote-submodules",
               "--also-filter-submodules", "--reject-shallow", "--no-reject-shallow", "--help", "-h", "--ipv4", "--ipv6"}


QUIET_SUBCOMMANDS = {
    "add", "status", "log", "diff", "show", "branch", "ls-tree", "ls-remote",
    "grep", "ls-files", "cat-file", "rev-parse", "rev-list", "merge-base", "check-ignore",
}
COMMIT_VALUES = {"-m", "--message", "-F", "--file", "-C", "--reuse-message", "-c", "--reedit-message",
                 "--author", "--date", "--fixup", "--squash", "--cleanup", "-t", "--template",
                 "--trailer", "--pathspec-from-file"}
COMMIT_FLAGS = {"--all", "--amend", "--no-edit", "--edit", "--no-verify", "--verify", "--signoff",
                "--no-signoff", "--allow-empty", "--allow-empty-message", "--reset-author", "--dry-run",
                "--short", "--porcelain", "--long", "--branch", "--null", "--verbose", "--quiet",
                "--interactive", "--patch", "--include", "--only", "--status", "--no-status",
                "--no-post-rewrite", "--pathspec-file-nul", "--no-gpg-sign", "--help", "-h"}


def _options(args, valued, switches, short=""):
    """Retain unresolved operands, consume option values, and honor the delimiter."""
    operands, flags, bound, unknown = [], set(), {}, []
    i, end = 0, False
    while i < len(args):
        value, i = args[i], i + 1
        word = value.text
        if end or word is None or not word.startswith("-") or word == "-":
            operands.append(value)
        elif word == "--":
            end = True
        else:
            key, sep, attached = word.partition("=")
            if key in valued:
                flags.add(key)
                if sep:
                    bound[key] = Value(attached)
                elif i < len(args):
                    bound[key], i = args[i], i + 1
                else:
                    unknown.append(key)
            elif key in switches:
                if key in {"--force", "--no-force", "--force-with-lease", "--no-force-with-lease", "--prune", "--no-prune"}:
                    opposite = key.replace("--no-", "--", 1) if key.startswith("--no-") else key.replace("--", "--no-", 1)
                    flags.discard(opposite)
                    if key == "--no-force":
                        flags.discard("-f")
                flags.add(key)
                if sep and key not in {"--force-with-lease", "--signed", "--recurse-submodules"}:
                    unknown.append(key)
            elif not word.startswith("--") and short:
                for offset, letter in enumerate(word[1:], 1):
                    key = "-" + letter
                    if key in valued:
                        flags.add(key)
                        if offset + 1 < len(word):
                            bound[key] = Value(word[offset + 1:])
                        elif i < len(args):
                            bound[key], i = args[i], i + 1
                        else:
                            unknown.append(key)
                        break
                    if letter in short:
                        if letter == "f":
                            flags.discard("--no-force")
                        flags.add(key)
                    else:
                        unknown.append(key)
            else:
                unknown.append(key)
    return operands, flags, bound, unknown


def _config(args):
    # Modern action words are recognized only in the action position, never as a
    # setting's value (e.g. user.name get). Options may precede the action.
    action, remaining = None, []
    i = 0
    while i < len(args):
        value = args[i]
        key = (value.text or "").split("=", 1)[0]
        if value.text == "--":
            remaining.extend(args[i:])
            break
        if key in CONFIG_VALUES:
            remaining.append(value)
            i += 1
            if "=" not in (value.text or "") and i < len(args):
                remaining.append(args[i])
                i += 1
            continue
        if value.text in QUERY_ACTIONS | WRITE_ACTIONS and not value.text.startswith("-"):
            action = value.text
            remaining.extend(args[i + 1:])
            break
        if value.text is None or not value.text.startswith("-"):
            remaining.extend(args[i:])
            break
        remaining.append(value)
        i += 1
    operands, flags, bound, unknown = _options(remaining, CONFIG_VALUES,
                                              CONFIG_FLAGS | QUERY_ACTIONS | WRITE_ACTIONS, "ezl")
    facts = [Fact("unresolved", "unknown-option", payload=w) for w in unknown]
    actions = flags & (QUERY_ACTIONS | WRITE_ACTIONS)
    if action in QUERY_ACTIONS or actions & QUERY_ACTIONS or flags & {"--help", "-h"} or "--blob" in bound:
        return facts
    modifying = action in WRITE_ACTIONS or bool(actions & WRITE_ACTIONS) or len(operands) >= 2
    if not modifying:
        return facts
    scope = "system" if "--system" in flags else "global" if "--global" in flags else "worktree" if "--worktree" in flags else "local"
    if "--file" in bound or "-f" in bound:
        scope = "file"
    key = operands[0].text if operands else None
    folded = (key or "").casefold()
    sensitive = (folded in SENSITIVE_KEYS or folded in {"credential", "http"} or folded.startswith("credential.")
                 or folded.endswith((".extraheader", ".sslverify", ".proxysslverify"))
                 or any(part in {"password", "token", "secret", "apikey", "username"}
                        for part in folded.split("."))
                 or any(contains_secret(v.text or "") or re.search(r"[a-z]+://[^/@\s]+:[^/@\s]+@", v.text or "")
                        for v in operands))
    minor = folded in MINOR_KEYS or folded.startswith(("color.", "advice."))
    effect_flags = {"scope:" + scope, "sensitive" if sensitive else "minor" if minor else "important"}
    facts.append(Fact("git", "git-config-modified", (key,) if key else (),
                      flags=frozenset(effect_flags), payload=action or next(iter(sorted(actions)), "set")))
    if key is None or any(v.text is None for v in operands) or unknown:
        facts.append(Fact("unresolved", "unresolved-value", payload="Git configuration key or value is unresolved"))
    return facts


def _clone(args, cwd, shell):
    operands, flags, bound, unknown = _options(args, CLONE_VALUES, CLONE_FLAGS, "lsqvn46")
    facts = [Fact("unresolved", "unknown-option", payload=option) for option in unknown]
    if flags & {"--help", "-h"}:
        return facts
    if not operands:
        return facts + [Fact("unresolved", "unresolved-value", payload="Git clone repository is missing")]
    paths = style_for(shell, cwd or ("C:\\" if shell in {"cmd", "powershell"} else "/"))
    source = operands[0]
    uncertain = bool(unknown) or len(operands) > 2
    if uncertain:
        source = Value(None, "unknown_option_operand_binding", tuple(sorted({n for v in operands for n in v.variables})))
    text = source.text
    local_file_uri = text is not None and text.casefold().startswith("file://")
    windows_drive = text is not None and paths.windows and bool(paths.module.splitdrive(text)[0])
    remote = text is None or (not local_file_uri and not windows_drive and bool(
        re.match(r"[A-Za-z][\w+.-]*://", text) or re.match(r"[^/\\:]+:", text)))
    destination = operands[1] if len(operands) >= 2 and not uncertain else Value(None, "unresolved_clone_destination")
    if len(operands) == 1 and text is not None and not uncertain:
        try:
            spelling = urlsplit(text).path if "://" in text else text.split(":", 1)[1] if remote else text
        except ValueError:
            spelling = ""
        name = re.split(r"[/\\]", spelling.rstrip("/\\"))[-1]
        if not remote and name.endswith(".bundle"):
            name = name[:-7]
        if name.endswith(".git"):
            name = name[:-4]
        if name and name not in {".", ".."}:
            destination = Value(name + ".git" if flags & {"--bare", "--mirror"} and not name.endswith(".git") else name)
    target = paths.resolve(destination, cwd)
    destination = Value(target, destination.reason or "unresolved_clone_destination", destination.variables) if target is None else Value(target)
    if remote:
        facts.append(Fact("network", "download", targets=(text,) if text else (), values=(source, destination),
                          flags=frozenset({"git_clone"}), payload=text))
    elif text is not None:
        spelling = text
        if local_file_uri:
            try:
                parsed = urlsplit(text)
                spelling = unquote(parsed.path)
                if parsed.netloc and parsed.netloc != "localhost":
                    spelling = "//" + parsed.netloc + spelling
                elif paths.windows and re.match(r"^/[A-Za-z]:", spelling):
                    spelling = spelling[1:]
            except ValueError:
                spelling = None
        local = paths.resolve(Value(spelling), cwd)
        facts.append(Fact("read", "list", targets=(local,) if local else (), values=(Value(local),)))
    bundle = bound.get("--bundle-uri")
    if bundle is not None and (bundle.text is None or not bundle.text.casefold().startswith("file://")):
        facts.append(Fact("network", "download", targets=(bundle.text,) if bundle.text else (), values=(bundle, destination),
                          flags=frozenset({"git_clone", "bundle_uri"}), payload=bundle.text))
    facts.append(Fact("write", "clone", targets=(target,) if target else (), values=(destination,)))
    if "--separate-git-dir" in bound:
        value = bound["--separate-git-dir"]
        git_dir = paths.resolve(value, cwd)
        facts.append(Fact("write", "clone", targets=(git_dir,) if git_dir else (),
                          values=(Value(git_dir, value.reason or "unresolved_clone_destination", value.variables),)))
    if text is None or destination.text is None or uncertain:
        facts.append(Fact("unresolved", "unresolved-value", values=(source, destination), payload="Git clone source or destination is unresolved"))
    return facts


def describe_git(args, cwd, flag_known, *, shell="bash"):
    facts, i = [], 0
    clone_cwd = cwd
    paths = style_for(shell, cwd or ("C:\\" if shell in {"cmd", "powershell"} else "/"))
    # Consume Git's leading options before finding the subcommand. -c config is
    # invocation-only; it does not persistently modify a config file.
    root_values = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env"}
    root_flags = {"--no-pager", "--paginate", "-p", "--bare", "--no-replace-objects",
                  "--literal-pathspecs", "--glob-pathspecs", "--noglob-pathspecs", "--icase-pathspecs"}
    while i < len(args):
        word = args[i].text
        if word in {"--help", "-h", "--version", "-v"}:
            return facts
        if word is None or not word.startswith("-"):
            break
        key, sep, _ = word.partition("=")
        if key in root_values:
            if key == "-C":
                directory = Value(word.partition("=")[2]) if sep else args[i + 1] if i + 1 < len(args) else Value(None)
                if directory.text != "":
                    clone_cwd = paths.resolve(directory, clone_cwd)
            i += 1 if sep else 2
            if i > len(args):
                facts.append(Fact("unresolved", "unknown-option", payload=key))
        elif word.startswith(("-C", "-c")) and len(word) > 2:
            if word.startswith("-C"):
                clone_cwd = paths.resolve(Value(word[2:]), clone_cwd)
            i += 1
        elif key in root_flags:
            i += 1
        else:
            return [Fact("unresolved", "unknown-option", payload=key),
                    Fact("unresolved", "unresolved-value", payload="Git subcommand binding is unresolved")]
    sub = args[i].text if i < len(args) else None
    tail = args[i + 1:]
    if sub == "config":
        return facts + _config(tail)
    if sub == "clone":
        return facts + _clone(tail, clone_cwd, shell)
    if sub in QUIET_SUBCOMMANDS:
        # These subcommands are intentionally quiet at the Git policy layer.
        # Shell substitutions, redirections and other outer effects still apply.
        return facts
    if sub == "commit":
        operands, flags, bound, unknown = _options(tail, COMMIT_VALUES, COMMIT_FLAGS, "avqnespioz")
        facts.extend(Fact("unresolved", "unknown-option", payload=w) for w in unknown)
        if flags & {"--dry-run", "--short", "--porcelain", "--long", "--help", "-h"}:
            return facts
        amend = "--amend" in flags
        facts.append(Fact("git", "git-history-rewrite" if amend else "git-commit",
                          (clone_cwd,) if clone_cwd else (),
                          flags=frozenset({"local_history", "commit_amend", "--amend"}) if amend else frozenset()))
        return facts
    if sub == "push":
        operands, flags, bound, unknown = _options(tail, PUSH_VALUES, PUSH_FLAGS, "nfduvq46o")
        facts.extend(Fact("unresolved", "unknown-option", payload=w) for w in unknown)
        if flags & {"--dry-run", "-n", "--help", "-h"}:
            return facts
        # --repo supplies the remote when no positional repository is present;
        # following positional operands still start with the repository per Git.
        refs = operands[1:]  # The first positional operand is the remote.
        rewriting = bool(flags & {"--force", "-f", "--force-with-lease", "--delete", "-d", "--mirror", "--prune"})
        if "--no-force" in flags:
            rewriting = bool(flags & {"--force-with-lease", "--delete", "-d", "--mirror", "--prune"})
        if "--no-force-with-lease" in flags:
            rewriting = bool(flags & {"--force", "-f", "--delete", "-d", "--mirror", "--prune"})
        rewriting |= any(v.text and v.text.startswith(("+", ":")) for v in refs)
        remote = operands[0].text if operands else bound.get("--repo", Value(None)).text
        facts.append(Fact("git", "git-history-rewrite" if rewriting else "git-push",
                          (remote,) if remote else (), values=tuple(refs),
                          flags=frozenset({"remote_history", *flags}) if rewriting else frozenset()))
        if any(v.text is None for v in operands):
            facts.append(Fact("unresolved", "unresolved-value", payload="Git push remote or refspec is unresolved"))
        return facts
    delimiter = next((i for i, value in enumerate(tail) if value.text == "--"), len(tail))
    option_tail = tail[:delimiter]
    if any(v.text in {"--help", "-h"} for v in option_tail):
        return facts
    if sub == "filter-branch":
        facts.append(Fact("git", "git-history-rewrite", (cwd,) if cwd else (), flags=frozenset({"local_history"})))
    elif sub == "remote":
        operation = tail[0].text if tail else None
        if operation in {"set-url", "add", "remove", "rm", "rename", "set-head", "set-branches", "prune", "update"}:
            facts.append(Fact("git", "git-config-modified", flags=frozenset({"scope:local", "important"}), payload=operation))
        elif operation not in {None, "show", "get-url", "-v", "--verbose"}:
            facts.append(Fact("unresolved", "unknown-command", payload="Unsupported Git remote operation"))
    elif sub == "reset" and any(v.text == "--hard" for v in option_tail):
        facts.append(Fact("git", "git-reset-state-unavailable", (cwd,) if cwd else ()))
    elif sub not in {"merge-tree", "status", "diff", "log", "show", "add", "commit", "reset", "branch", "switch",
                     "checkout", "fetch", "pull", "stash", "tag", "worktree"}:
        facts.append(Fact("unresolved", "unknown-command", payload="Unsupported Git subcommand"))
    for value in tail:
        if value.text == "--":
            break
        if value.text and value.text.startswith("-") and not flag_known(value.text):
            facts.append(Fact("unresolved", "unknown-option", payload=value.text.split("=", 1)[0]))
    return facts
