"""Bounded Python AST parsing. Submitted modules are never imported or run."""
import ast
from dataclasses import dataclass, field
import warnings

from ..models import Span
from ..bash.syntax import ParseBudgetExceeded


@dataclass(frozen=True, slots=True)
class ParsedPythonSource:
    root: ast.AST | None = field(repr=False)
    diagnostics: tuple[Span, ...] = ()
    backend: str = "python-ast"


class PythonFrontend:
    def parse(self, text: str, max_nodes: int = 65536, *, mode="exec") -> ParsedPythonSource:
        try:
            with warnings.catch_warnings():
                # Parser warnings can quote private submitted source. They are
                # not analyzer findings and must not escape to callers.
                warnings.simplefilter("ignore", SyntaxWarning)
                warnings.simplefilter("ignore", DeprecationWarning)
                root = ast.parse(text, mode=mode)
        except (SyntaxError, ValueError, RecursionError):
            return ParsedPythonSource(None, (Span(0, len(text)),))
        for count, _ in enumerate(ast.walk(root), 1):
            if count > max_nodes:
                raise ParseBudgetExceeded
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", SyntaxWarning)
                warnings.simplefilter("ignore", DeprecationWarning)
                # Compilation validates contextual syntax (e.g. return outside
                # a function). The resulting code object is never executed.
                compile(root, "<python source>", mode, dont_inherit=True)
        except (SyntaxError, ValueError, TypeError, RecursionError):
            return ParsedPythonSource(None, (Span(0, len(text)),))
        return ParsedPythonSource(root)
