"""Bounded native Windows administration models; arguments are never executed."""
from ..models import Value

ADMIN_RULES = {
    "volume-format": ("BLOCK", "Requests formatting of a volume."),
    "backup-delete": ("HIGH", "Deletes volume shadow-copy backups."),
    "free-space-wipe": ("HIGH", "Overwrites unused space on the volume containing a directory."),
    "event-log-clear": ("HIGH", "Clears a Windows event log."),
    "registry-change": ("MEDIUM", "Changes Windows registry data."),
    "security-policy-change": ("HIGH", "Changes execution, antivirus, or firewall policy."),
    "account-change": ("HIGH", "Changes Windows accounts or group membership."),
}


ADMIN_COMMANDS = {"format", "diskpart", "vssadmin", "cipher", "wevtutil", "reg", "netsh", "net", "mshta", "certutil", "whoami"}


def describe_admin(builder, name, args, guard):
    """Return whether the command belongs to this family, preserving unknown forms."""
    if name not in ADMIN_COMMANDS:
        return False
    texts = [(v.text or "").casefold() for v in args]
    first = texts[0] if texts else ""
    def effect(rule, values=()):
        builder.emit("system", rule, targets=tuple(v.text or "unresolved" for v in values), guard=guard)
    def unsupported():
        builder.unresolved(f"Unsupported {name} operation or argument binding", guard=guard)
    if texts in (["/?"], ["-?"]):
        return True
    if name == "whoami":
        if any(t not in {"/all", "/user", "/groups", "/priv", "/logonid", "/nh"} for t in texts):
            unsupported()
    elif name == "format":
        operands = [v for v in args if v.text is None or not v.text.startswith("/")]
        if len(operands) == 1 and operands[0].text and not any(c in operands[0].text for c in "*?"):
            effect("volume-format", operands)
        else:
            builder.unresolved("FORMAT volume is missing or unresolved", "unresolved-value", guard)
    elif name == "diskpart":
        # A script filename does not establish that CLEAN/FORMAT occurs in it.
        builder.emit("execute", "diskpart", guard=guard)
        builder.unresolved("DiskPart commands and selected disks are unavailable to this frontend", "execution-content-unavailable", guard)
    elif name == "vssadmin":
        if texts[:2] == ["delete", "shadows"]:
            effect("backup-delete", args[2:])
        elif first == "list" and len(texts) >= 2 and texts[1] in {"shadows", "shadowstorage", "writers", "providers", "volumes"}:
            pass
        else:
            unsupported()
    elif name == "cipher":
        wipes = [Value(v.text[3:]) for v in args if v.text and v.text.casefold().startswith("/w:")]
        if wipes:
            effect("free-space-wipe", wipes)
        elif texts and texts != ["/y"]:
            unsupported()
    elif name == "wevtutil":
        if first in {"cl", "clear-log"}:
            effect("event-log-clear", args[1:2] or (Value(None),))
        elif first not in {"el", "enum-logs", "gl", "get-log", "qe", "query-events", "gli", "get-log-info"}:
            unsupported()
    elif name == "reg":
        if first in {"add", "delete", "import", "restore", "load", "unload", "copy"}:
            effect("registry-change", args[1:2] or (Value(None),))
        elif first not in {"query", "compare"}:
            unsupported()
    elif name == "netsh":
        if texts[:2] == ["advfirewall", "set"] or texts[:3] in (["advfirewall", "firewall", "add"], ["advfirewall", "firewall", "delete"], ["advfirewall", "firewall", "set"]):
            effect("security-policy-change", args[:3])
        elif texts[:2] != ["advfirewall", "show"]:
            unsupported()
    elif name == "net":
        if first in {"user", "localgroup", "group"}:
            if any(t in {"/add", "/delete"} for t in texts) or first == "user" and len(texts) >= 3 and texts[2] != "/domain":
                # Never copy a password into the finding's targets.
                effect("account-change", args[1:2])
            elif len(texts) > 2 and texts[2:] != ["/domain"]:
                unsupported()
        elif first in {"start", "stop", "pause", "continue"} and len(args) > 1:
            effect("service-change", args[1:2])
        else:
            unsupported()
    elif name == "mshta":
        builder.emit("execute", "mshta", guard=guard)
        builder.unresolved("HTA execution content cannot be inspected by this frontend", "execution-content-unavailable", guard)
        if first.startswith(("http://", "https://")):
            builder.emit("network", "download", targets=(args[0].text,), flags={"to_interpreter"}, guard=guard)
    elif name == "certutil":
        operands = [v for v in args if v.text is None or v.text.casefold() != "-f"]
        if operands and (operands[0].text or "").casefold() in {"-decode", "-encode"} and len(operands) == 3:
            builder.filesystem("read", "list", (operands[1],), guard=guard)
            builder.filesystem("write", "overwrite", (operands[2],), guard=guard)
        else:
            unsupported()
    return True
