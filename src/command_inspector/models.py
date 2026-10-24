"""Small immutable records shared by parsing, evidence, and reporting."""
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

ANALYZER_VERSION = "1.15.0"
SCHEMA_VERSION = "1.0.0"
CATALOG_VERSION = "1.15.0"


class InputError(ValueError):
    pass


class ConfigurationError(ValueError):
    pass


class AnalysisError(RuntimeError):
    pass


class Level(IntEnum):
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    BLOCK = 4


@dataclass(frozen=True, slots=True)
class Span:
    start: int
    end: int


@dataclass(frozen=True, slots=True)
class SyntaxNode:
    kind: str
    span: Span
    children: tuple["SyntaxNode", ...] = ()
    text: str = field(default="", repr=False)


@dataclass(frozen=True, slots=True)
class ParsedSource:
    root: SyntaxNode
    diagnostics: tuple[Span, ...]
    backend: str = "tree-sitter-bash"


@dataclass(frozen=True, slots=True)
class Value:
    text: str | None = field(repr=False)
    reason: str | None = None
    variables: tuple[str, ...] = ()
    pattern: bool = False
    pattern_text: str | None = field(default=None, repr=False)
    alternatives: tuple["Value", ...] = field(default=(), repr=False)
    fragments: tuple[str | None, ...] = field(default=(), repr=False)
    component_safe: bool = False
    local_definition: bool = False


@dataclass(frozen=True, slots=True)
class Fact:
    kind: str
    operation: str
    targets: tuple[str, ...] = ()
    values: tuple[Value, ...] = field(default=(), repr=False)
    flags: frozenset[str] = frozenset()
    payload: str | None = field(default=None, repr=False)
    guard: str = ""
    source: str = "command"
    context: str = "invoked_now"
    cwd: str | None = None
    bindings: tuple[tuple[str, str | Value], ...] = field(default=(), repr=False)
    shell: str = "bash"
    stdin_sources: tuple[Value, ...] = field(default=(), repr=False)
    stdin_payload: str | None = field(default=None, repr=False)
    transfer_sources: tuple[Value, ...] = field(default=(), repr=False)
    command_name: str | None = field(default=None, repr=False)
    unresolved_variables: tuple[str, ...] = field(default=(), repr=False)
    command_path: str | None = field(default=None, repr=False)
    possible_values: tuple[tuple[str, tuple[str, ...]], ...] = field(default=(), repr=False)
    choice_path: tuple[tuple[int, int], ...] = field(default=(), repr=False)
    choice_fallthrough: tuple[int, ...] = field(default=(), repr=False)
    sensitive_variables: frozenset[str] = field(default_factory=frozenset, repr=False)
    payload_value: Value | None = field(default=None, repr=False)
    choice_predecessors: tuple[tuple[int, tuple[int, ...]], ...] = field(default=(), repr=False)
    credential_values: tuple[Value, ...] = field(default=(), repr=False)
    python_bindings: tuple[tuple[str, Any], ...] = field(default=(), repr=False)
    stdin_payload_value: Value | None = field(default=None, repr=False)
    javascript_bindings: tuple[tuple[str, Any], ...] = field(default=(), repr=False)
    python_event: tuple[str, int] | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class Finding:
    rule: str
    level: Level
    type: str
    title: str
    detail: str
    data: dict[str, Any] = field(default_factory=dict, repr=False)
    evidence: tuple[dict[str, Any], ...] = field(default=(), repr=False)
    sensitive_variables: frozenset[str] = field(default_factory=frozenset, repr=False)

    def to_dict(self) -> dict[str, Any]:
        # Explicit serialization; never export internal source/payload records.
        from .reporting import redact
        return redact({"rule": self.rule, "level": self.level.name, "type": self.type,
                       "title": self.title, "detail": self.detail,
                       "data": self.data, "evidence": list(self.evidence)})


@dataclass(frozen=True, slots=True)
class AnalysisReport:
    findings: tuple[Finding, ...] = ()
    schema_version: str = SCHEMA_VERSION
    analyzer_version: str = ANALYZER_VERSION
    rule_catalog_version: str = CATALOG_VERSION

    @property
    def level(self) -> Level:
        return max((f.level for f in self.findings), default=Level.NONE)

    @property
    def num_findings(self) -> int:
        return len(self.findings)

    def to_dict(self) -> dict[str, Any]:
        if not self.findings:
            return {}
        return {"schema_version": self.schema_version, "analyzer_version": self.analyzer_version,
                "rule_catalog_version": self.rule_catalog_version, "level": self.level.name,
                "num_findings": self.num_findings,
                "findings": [f.to_dict() for f in self.findings]}
