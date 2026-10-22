"""Explicit, shell-aware command models. No plugin discovery or host lookup.

Models receive resolved argument values and describe facts, never findings or
filesystem evidence. An empty result is a modeled, quiet invocation; None from
the registry means that no model is registered for this name and shell.
"""
from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace
from types import MappingProxyType

from ..models import Fact, Value
from ..paths import style_for

SHELLS = frozenset({"bash", "powershell", "cmd"})


@dataclass(frozen=True, slots=True)
class CommandInvocation:
    name: str
    args: tuple[Value, ...]
    cwd: str | None
    shell: str


@dataclass(frozen=True, slots=True)
class CommandModel:
    names: frozenset[str]
    handler: Callable[[CommandInvocation], Iterable[Fact]]
    shells: frozenset[str] = SHELLS

    def __post_init__(self):
        if isinstance(self.names, str) or isinstance(self.shells, str):
            raise ValueError("Model names and shells must be collections")
        object.__setattr__(self, "names", frozenset(self.names))
        object.__setattr__(self, "shells", frozenset(self.shells))
        if (not self.names or any(not isinstance(name, str) or not name or "/" in name or "\\" in name
                                  for name in self.names)):
            raise ValueError("Model names must be nonempty command basenames")
        if not self.shells or not self.shells <= SHELLS:
            raise ValueError("Model shells must be bash, powershell or cmd")
        if not callable(self.handler):
            raise ValueError("Model handler must be callable")


class CommandRegistry:
    def __init__(self, models: Iterable[CommandModel]):
        self.models = tuple(models)
        entries = {}
        for model in self.models:
            for shell in model.shells:
                for name in model.names:
                    key = shell, name
                    if key in entries:
                        raise ValueError(f"Duplicate command model: {shell}/{name}")
                    entries[key] = model
        self._entries = MappingProxyType(entries)

    def supports(self, name: str, shell: str) -> bool:
        return (shell, name) in self._entries

    def describe(self, invocation: CommandInvocation, *, fallback_shell: str | None = None) -> list[Fact] | None:
        model = self._entries.get((invocation.shell, invocation.name))
        if model is None and fallback_shell is not None:
            model = self._entries.get((fallback_shell, invocation.name))
        if model is None:
            return None
        facts = list(model.handler(invocation))
        if any(not isinstance(fact, Fact) for fact in facts):
            raise TypeError("Command models must return Fact records")
        # Models can describe filesystem operands with Values alone. Resolve
        # their lexical targets centrally for adapters that trust model targets,
        # without discovering files or expanding patterns.
        paths = style_for(invocation.shell, invocation.cwd or ("/" if invocation.shell == "bash" else "C:\\"))
        return [replace(fact, targets=tuple(p for value in fact.values
                                          if (p := paths.resolve(value, invocation.cwd)) is not None))
                if fact.kind in {"read", "write", "delete"} and not fact.targets else fact
                for fact in facts]
