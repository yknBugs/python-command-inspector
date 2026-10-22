"""Static command facts; no execution or filesystem access."""
import re
from dataclasses import replace
from ..models import Fact, Value


def describe_find(args, cwd):
    from ..shared.commands import resolve_path
    facts, roots = [], []
    def emit(kind, operation, values=(), flags=(), payload=None):
        facts.append(Fact(kind, operation, tuple(p for v in values if (p := resolve_path(v, cwd)) is not None), tuple(values), frozenset(flags), payload))
    i = 0
    while i < len(args) and args[i].text in {"-H", "-L", "-P"}:
        i += 1
    while i < len(args) and (args[i].text is None or not args[i].text.startswith(("-", "!", "("))):
        roots.append(args[i]); i += 1
    roots = tuple(roots) or (Value("."),)
    emit("read", "list", roots)
    start = i
    no_value = {"-print", "-print0", "-ls", "-prune", "-quit", "-true", "-false", "-empty", "-readable", "-writable", "-executable", "-depth", "-xdev", "-mount", "-daystart", "-noleaf", "-ignore_readdir_race", "-not", "-a", "-and", "-o", "-or", "!", "(", ")"}
    one_value = {"-name", "-iname", "-path", "-ipath", "-wholename", "-regex", "-iregex", "-type", "-xtype", "-size", "-mtime", "-mmin", "-atime", "-amin", "-ctime", "-cmin", "-newer", "-newermt", "-perm", "-user", "-group", "-uid", "-gid", "-inum", "-links", "-maxdepth", "-mindepth", "-regextype", "-printf"}
    while i < len(args):
        option = args[i].text
        if option in {"-exec", "-execdir", "-ok", "-okdir"}:
            end = i + 1
            while end < len(args) and args[end].text not in {";", "+"}:
                end += 1
            command = tuple(Value(None, "find_result") if v.text and "{}" in v.text else v for v in args[i+1:end])
            if end == len(args) or not command or not command[0].text:
                emit("unresolved", "execution-content-unavailable", payload="Find action command cannot be resolved")
            else:
                emit("invoke", command[0].text, command[1:], {"unknown_cwd"} if option.endswith("dir") else ())
                facts[-1] = replace(facts[-1], guard="if a search result matches")
            i = end + 1; continue
        if option == "-delete":
            # Only an unfiltered traversal can bind deletion to the roots. A
            # predicate may select a completely different set of descendants.
            if all(v.text in {"-depth", "-true"} for v in args[start:i]):
                emit("delete", "delete", roots, {"-r", "-f"})
            else:
                emit("system", "filesystem-selection-delete", roots, payload="Deletes matching search results; selection is not enumerated")
                facts.append(Fact("invalidate", "filtered_delete", targets=tuple(p for v in roots if (p := resolve_path(v, cwd)) is not None), values=roots))
        elif option in {"-fprint", "-fprint0", "-fprintf"}:
            if i + 1 < len(args):
                emit("write", "transform", args[i+1:i+2]); i += 1
                if option == "-fprintf":
                    i += 1
            else:
                emit("unresolved", "unresolved-value", payload="Find output target is missing")
        elif option in one_value:
            if i + 1 >= len(args):
                emit("unresolved", "unknown-option", payload="Missing find predicate value")
            i += 1
        elif option not in no_value:
            emit("unresolved", "unknown-option", payload=option or "Unresolved find predicate")
        i += 1
    return facts

