"""Explicit startup configuration. Analysis never discovers project config."""
from dataclasses import dataclass, field
from collections.abc import Mapping
from types import MappingProxyType
from pathlib import Path
from .paths import PathStyle
import tomllib

from .models import ConfigurationError
from .known_tools import KNOWN_TOOLS


@dataclass(frozen=True, slots=True)
class AnalyzerConfig:
    # Select a text dialect, independently of installed shells or the host OS.
    # Explicit None continues to require the caller to select a frontend.
    shell: str | None = "bash"
    additional_paths: tuple[str, ...] = ()
    protected_directories: tuple[str, ...] = (
        "/", "/etc", "/usr", "/bin", "/sbin", "/boot",
        "/system", "/system_ext", "/vendor", "/product", "/odm", "/apex", "/metadata", "/dev",
    )
    disabled_rules: frozenset[str] = frozenset()
    local_evidence: bool = True
    file_bytes: int = 524288
    total_read_bytes: int = 4194304
    directory_entries: int = 32768
    inline_depth: int = 3
    source_nodes: int = 65536
    wildcard_matches: int = 1024
    known_tools: Mapping[str, str] = field(default_factory=lambda: dict(KNOWN_TOOLS), hash=False)
    allowed_write_paths: tuple[str, ...] = ()
    possible_values: int = 16
    control_flow_steps: int = 256
    value_bytes: int = 524288

    def __post_init__(self):
        if self.shell is not None and not isinstance(self.shell, str):
            raise ConfigurationError("shell must be a string or None")
        for name in ("additional_paths", "protected_directories", "allowed_write_paths"):
            paths = getattr(self, name)
            if not isinstance(paths, (list, tuple)) or any(not isinstance(p, str) or "\x00" in p or not (PathStyle(False).absolute(p) or PathStyle(True).absolute(p)) for p in paths):
                raise ConfigurationError(f"{name} must contain absolute paths")
            object.__setattr__(self, name, tuple(paths))
        if not isinstance(self.local_evidence, bool):
            raise ConfigurationError("local_evidence must be boolean")
        if not isinstance(self.known_tools, Mapping) or any(
            not isinstance(name, str) or not name or any(c.isspace() or c in "/\\\x00" for c in name)
            or not isinstance(category, str) or not category.strip() or "\x00" in category
            for name, category in self.known_tools.items()
        ):
            raise ConfigurationError("known_tools must map command names to nonempty categories")
        object.__setattr__(self, "known_tools", MappingProxyType(dict(self.known_tools)))
        for name in ("file_bytes", "total_read_bytes", "directory_entries", "inline_depth", "source_nodes", "wildcard_matches", "possible_values", "control_flow_steps", "value_bytes"):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ConfigurationError(f"{name} must be a positive integer")
        from .catalog import RULES
        if not isinstance(self.disabled_rules, (set, frozenset)) or not self.disabled_rules <= RULES.keys():
            raise ConfigurationError("disabled_rules contains an unknown rule")
        object.__setattr__(self, "disabled_rules", frozenset(self.disabled_rules))

    @classmethod
    def from_mapping(cls, mapping: Mapping) -> "AnalyzerConfig":
        if not isinstance(mapping, Mapping):
            raise ConfigurationError("config must be a mapping")
        try:
            if set(mapping) - {"shell", "workspace", "protected", "rules", "limits", "local_evidence", "tools"}:
                raise ConfigurationError("unknown config field")
            workspace = mapping.get("workspace", {})
            protected = mapping.get("protected", {})
            rules = mapping.get("rules", {})
            limits = mapping.get("limits", {})
            tools = mapping.get("tools", {})
            if set(tools) - {"known"}:
                raise ConfigurationError("unknown tool configuration field")
            if set(workspace) - {"additional_paths", "allowed_write_paths"} or set(protected) - {"directories"}:
                raise ConfigurationError("unknown path configuration field")
            defaults = cls()
            directories = protected.get("directories", [])
            if any(set(d) - {"path", "match"} or d.get("match", "self") != "self" for d in directories):
                raise ConfigurationError("protected directories currently require match=self")
            for settings in rules.values():
                if set(settings) != {"enabled"} or type(settings["enabled"]) is not bool:
                    raise ConfigurationError("rule settings require a boolean enabled field")
            from .catalog import RULES
            if set(rules) - RULES.keys():
                raise ConfigurationError("unknown rule configuration")
            return cls(shell=mapping.get("shell", defaults.shell),
                       additional_paths=tuple(workspace.get("additional_paths", ())),
                       allowed_write_paths=workspace.get("allowed_write_paths", ()),
                       protected_directories=tuple(d["path"] for d in directories) if "directories" in protected else defaults.protected_directories,
                       disabled_rules=frozenset(k for k, v in rules.items() if not v["enabled"]),
                       local_evidence=mapping.get("local_evidence", True),
                       known_tools=tools.get("known", defaults.known_tools), **limits)
        except (TypeError, KeyError, AttributeError, ValueError) as exc:
            if isinstance(exc, ConfigurationError):
                raise
            raise ConfigurationError("invalid configuration structure") from None


def load_config(path: str | Path) -> AnalyzerConfig:
    with open(path, "rb") as stream:
        return AnalyzerConfig.from_mapping(tomllib.load(stream))
