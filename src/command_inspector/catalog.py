"""Library-owned, versioned meanings and permitted levels."""
from .admin.windows import ADMIN_RULES
from .models import CATALOG_VERSION, SCHEMA_VERSION, Level

# rule: (type, permitted levels, description)
RULES = {
    "command-via-path": ("execution", ("LOW",), "Accesses a recognized command through an absolute or relative path."),
    "executable-via-path": ("execution", ("LOW",), "Runs an executable path whose behavior is not modeled."),
    "execute-target-missing": ("execution", ("LOW",), "Attempts to run a file that does not currently exist."),
    "execute-target-not-executable": ("execution", ("LOW",), "Attempts to run a target that is not executable."),
    "tool-invoked": ("execution", ("MEDIUM",), "Invokes configured software whose behavior is not modeled."),
    "read-outside-workspace": ("filesystem", ("LOW",), "Reads outside the configured workspace."),
    "write-outside-workspace": ("filesystem", ("LOW",), "Writes outside the configured workspace."),
    "delete-inside-workspace": ("filesystem", ("LOW",), "Deletes a named target inside the workspace."),
    "delete-outside-workspace": ("filesystem", ("MEDIUM",), "Deletes a named target outside the workspace."),
    "delete-workspace-root": ("filesystem", ("HIGH",), "Force-recursively deletes the primary workspace itself."),
    "delete-protected-root": ("filesystem", ("BLOCK",), "Force-recursively deletes a configured critical directory or its contents."),
    "delete-after-failed-assignment": ("filesystem", ("BLOCK", "HIGH"), "Deletion uses the retained value after a rejected read-only assignment; HIGH when that value is unavailable."),
    "delete-target-missing": ("filesystem", ("LOW",), "The requested deletion target does not currently exist."),
    "delete-variable-unresolved": ("filesystem", ("MEDIUM",), "Deletion target is unresolved and may broaden through expansion."),
    "delete-recursion-unresolved": ("filesystem", ("MEDIUM",), "Directory deletion has an unresolved recursion argument; recursive deletion is not confirmed."),
    "write-variable-unresolved": ("filesystem", ("MEDIUM",), "A variable-dependent write target cannot be bounded from supplied values."),
    "file-operation-unresolved": ("filesystem", ("MEDIUM",), "File access mode or operation is unresolved; read/write intent cannot be confirmed."),
    "overwrite-existing-file": ("filesystem", ("LOW",), "A write or file transfer may overwrite an existing regular file."),
    "written-source-syntax-error": ("content", ("LOW",), "Written source has a syntax error or cannot be parsed by its source frontend."),
    "modify-analyzer-config": ("filesystem", ("HIGH",), "Writes analyzer or approval configuration."),
    "modify-sensitive-file": ("filesystem", ("HIGH",), "Writes password or private-key files."),
    "uses-interpreter": ("execution", ("LOW",), "Invokes a shell or language interpreter; repeated uses are grouped."),
    "execution-content-unavailable": ("execution", ("MEDIUM",), "Directly invoked code cannot be inspected completely."),
    "privilege-escalation": ("execution", ("HIGH",), "Requests elevated privileges."),
    "network-request": ("network", ("LOW",), "Makes an ordinary network request."),
    "download-content": ("network", ("MEDIUM",), "Downloads content to a destination or interpreter."),
    "publish-risk": ("network", ("MEDIUM",), "May publish local files or artifacts to a remote destination, including unresolved sources."),
    "credentials-exposed": ("content", ("HIGH",), "Visible command input supplies authentication credentials or contains visibly credential-bearing output, independently of its destination."),
    "credentials-sent": ("network", ("HIGH",), "Sends visibly credential-bearing data to a network endpoint."),
    "credentials-read": ("content", ("MEDIUM",), "Reads credential-shaped data into command output."),
    "credentials-written": ("content", ("MEDIUM",), "Authored write payload contains credential-shaped data."),
    "hardcoded-secret": ("content", ("MEDIUM",), "Python or JavaScript source contains a credential-shaped literal or a literal assigned to a credential field."),
    "prompt-injection-read": ("content", ("MEDIUM",), "Read content contains suspected model-directed instructions."),
    "ingestion-inspection-incomplete": ("content", ("LOW",), "Selected read content could not be fully inspected."),
    "environment-modified": ("environment", ("MEDIUM",), "Changes PATH or another non-allowlisted process environment variable inherited by child processes."),
    "readonly-assignment-failed": ("environment", ("MEDIUM",), "An assignment to a read-only binding was rejected and the previous value stands."),
    "errors-suppressed": ("execution", ("LOW",), "Suppresses standard error output."),
    "package-install": ("system", ("MEDIUM",), "Installs software packages."),
    "package-change": ("system", ("MEDIUM",), "Changes installed packages, environments, or package configuration."),
    "system-settings-change": ("system", ("MEDIUM",), "Changes system storage, GPU settings, or network socket state."),
    "filesystem-selection-delete": ("filesystem", ("MEDIUM",), "Deletes filtered search results whose exact selection is unresolved."),
    "runtime-code-loading": ("execution", ("MEDIUM",), "Compiles or loads executable .NET code."),
    "service-change": ("system", ("MEDIUM",), "Changes the state or configuration of a system service or scheduled task."),
    "force-process-termination": ("system", ("MEDIUM",), "Requests termination of a process, by signal or by name."),
    "machine-power-change": ("system", ("HIGH",), "Requests shutdown or reboot."),
    "raw-device-read": ("system", ("HIGH",), "Reads a named raw disk device."),
    "raw-device-write": ("system", ("BLOCK",), "Writes a named raw disk device."),
    "unmount-drive": ("system", ("HIGH",), "Unmounts a filesystem."),
    "permissions-too-broad": ("filesystem", ("LOW",), "Grants mode 777 permissions."),
    "git-push": ("git", ("MEDIUM",), "Pushes commits to a remote."),
    "git-config-modified": ("git", ("LOW", "MEDIUM", "HIGH"), "Changes Git configuration: minor local LOW, minor global MEDIUM, important local MEDIUM, important global HIGH, sensitive HIGH in any scope."),
    "git-history-rewrite": ("git", ("HIGH",), "Requests forced remote ref updates/deletion or explicit local history filtering."),
    "git-reset-state-unavailable": ("git", ("HIGH",), "A hard reset may discard work; read-only Git evidence is unavailable."),
    "docker-change": ("system", ("MEDIUM",), "Requests a noticeable Docker/container/resource effect without modeling daemon state."),
    "sql-unresolved": ("coverage", ("LOW",), "SQL source, syntax, dialect or statement meaning could not be resolved completely."),
    "sql-row-change": ("sql", ("LOW", "MEDIUM"), "INSERT and single-target UPDATE/DELETE with WHERE are LOW; unfiltered, multiple-target, overwrite and MERGE changes are MEDIUM."),
    "sql-schema-change": ("sql", ("LOW",), "Creates a table or makes an ordinary schema change."),
    "sql-truncate": ("sql", ("MEDIUM",), "Truncates SQL objects or replaces an existing table."),
    "sql-remove-schema": ("sql", ("MEDIUM",), "Removes a schema or columns."),
    "sql-privilege-change": ("sql", ("MEDIUM",), "Changes SQL privileges or account attributes."),
    "sql-create-identity": ("sql", ("MEDIUM",), "Creates a database, user, login or role."),
    "sql-drop-object": ("sql", ("HIGH",), "Drops whole tables, databases, users, logins or roles."),
    "unknown-command": ("coverage", ("LOW", "HIGH"), "Command meaning is outside the supported models (LOW), or command-position text suggests a quoting or parsing issue (HIGH)."),
    "unknown-option": ("coverage", ("LOW",), "An option is not supported by the invocation model."),
    "unresolved-value": ("coverage", ("LOW",), "A runtime-dependent argument or path cannot be resolved."),
    "unsupported-syntax": ("coverage", ("LOW",), "Syntax is malformed or outside the implemented semantic subset."),
    "analysis-unavailable": ("coverage", ("LOW",), "The selected shell frontend is unavailable."),
    "unreadable-payload": ("content", ("HIGH",), "An inspection nesting or size budget was exceeded."),
    "obfuscated-payload": ("content", ("HIGH",), "An argument is an encoded or self-evaluating payload that cannot be reviewed by reading it."),
}


RULES.update({rule: ("system", (level,), description) for rule, (level, description) in ADMIN_RULES.items()})
RULES['trusted-script-invoked'] = ('execution', ('LOW',), 'Invokes an explicitly trusted script; source inspection is skipped.')
RULES['environment-value-output'] = ('content', ('LOW',), 'Outputs a caller-supplied environment variable not unconditionally replaced locally.')
NEW_RULES_1_2 = {"write-variable-unresolved", "publish-risk", "git-history-rewrite", "docker-change"}
NEW_RULES_1_3 = {rule for rule in RULES if rule.startswith("sql-")}
NEW_RULES_1_4 = {"package-change", "system-settings-change", "filesystem-selection-delete", "runtime-code-loading", "delete-recursion-unresolved"}
NEW_RULES_1_6 = {"command-via-path", "executable-via-path", "execute-target-missing", "execute-target-not-executable"}

def rule_catalog() -> dict:
    return {"version": CATALOG_VERSION, "schema_version": SCHEMA_VERSION, "rules": [
        {"rule": rule, "type": kind, "levels": list(levels), "description": description,
         "data_schema": {"type": "object"}, "evidence_schema": {"type": "array", "items": {"type": "object"}},
         "introduced_in": "1.12.0" if rule in {"trusted-script-invoked", "environment-value-output"} else "1.10.0" if rule in {"credentials-exposed", "hardcoded-secret"} else "1.6.0" if rule in NEW_RULES_1_6 else "1.5.0" if rule == "tool-invoked" else "1.4.0" if rule in NEW_RULES_1_4 else "1.3.0" if rule in NEW_RULES_1_3 else "1.2.0" if rule in NEW_RULES_1_2 else "1.1.0" if rule in ADMIN_RULES else "1.0.0", "is_deprecated": False,
         "deprecated_in": None, "replaced_by": None}
        for rule, (kind, levels, description) in RULES.items()]}
