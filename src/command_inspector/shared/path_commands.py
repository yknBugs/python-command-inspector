"""Lexical executable names; no host lookup or binary inspection."""
import ntpath
import posixpath


SOURCE_SUFFIXES = {".sh", ".bash", ".py", ".ps", ".ps1", ".bat", ".cmd", ".js", ".mjs"}


def is_command_path(name, shell):
    return "/" in name or shell in {"powershell", "cmd"} and "\\" in name


def command_basename(name, shell):
    module = ntpath if shell in {"powershell", "cmd"} else posixpath
    name = module.basename(name)
    return name.casefold().removesuffix(".exe") if shell in {"powershell", "cmd"} else name


def is_source_path(name):
    return posixpath.splitext(name.casefold())[1] in SOURCE_SUFFIXES


def modeled_command(name, *, windows=False):
    from .builtins import command_registry
    from .commands import describe
    from ..models import Fact
    if windows:
        if any(command_registry().supports(name, shell) for shell in ("powershell", "cmd")):
            return True
        from ..pwsh.semantics import PS_OPTIONS, PS_ALIASES
        from ..admin.windows import ADMIN_COMMANDS
        from ..cmd.semantics import CMD_MODELED_COMMANDS
        if name in PS_OPTIONS or name in PS_ALIASES or name in ADMIN_COMMANDS or name in CMD_MODELED_COMMANDS:
            return True
    if name in {"read", "break", "continue", "export", "readonly", "declare", "typeset", "local", "unset", "set"}:
        return True
    return describe(name, (), None) != [Fact("unresolved", "unknown-command", payload=name, command_name=name)]
