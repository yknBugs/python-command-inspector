"""Conservative lexical hints, not a validator for executable filenames.

Shells allow unusual filenames. A match means review the command boundary, not
that a quoting error has been proved. Only resolved command-position text is
eligible; arguments and unsupported subcommand descriptions are never checked.
"""
import re


def suspicious_command_name(name: str | None, shell: str) -> str | None:
    if name is None:
        return None
    if any(ord(c) < 32 or ord(c) == 127 for c in name):
        return "control_character"
    # Preserve ordinary executable paths, including spaces and punctuation in
    # directory/file names. A slash in source code alone is not a path prefix.
    windows = shell in {"powershell", "cmd"}
    if (name.startswith(("/", "./", "../"))
            or windows and (name.startswith(("\\", ".\\", "..\\"))
                            or re.match(r"^[A-Za-z]:", name))
            or re.match(r"^[\w .@+~-]+" + (r"[/\\]" if windows else "/"), name)):
        return None
    if any(c.isspace() for c in name):
        return "whitespace_in_command_name"
    if any(c in name for c in "\"'`;|&<>(){}"):
        return "syntax_in_command_name"
    if not any(c.isalnum() or c == "_" for c in name):
        return "no_identifier_characters"
    return None
