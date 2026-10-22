"""Keep source credential values private for redaction, never report them."""
import re

from ..models import Fact, Value
from ..reporting import contains_secret


_CREDENTIAL_NAME = re.compile(
    r'(?:^|_)(?:password|passwd|api_?key|api_?token|access_?token|auth_?token|'
    r'client_?secret|secret(?:_?key)?|private_?key|token|authorization)$', re.I)


class SourceSecrets:
    def __init__(self, source, context, cwd, language):
        self.source, self.context, self.cwd, self.language = source, context, cwd, language
        self.matches = {}
        self.values = {}

    def add(self, text, line, column, name=''):
        if not text or not text.strip():
            return
        normalized = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', name).replace('-', '_')
        if not contains_secret(text) and not _CREDENTIAL_NAME.search(normalized):
            return
        names = self.matches.setdefault((line, column), set())
        self.values.setdefault((line, column), set()).add(text)
        if name:
            names.add(name)

    def facts(self):
        return [Fact('content', 'hardcoded-secret', targets=tuple(sorted(names)),
                     flags=frozenset({f'line:{line}', f'column:{column}'}),
                     source=self.source, context=self.context, cwd=self.cwd,
                     shell=self.language, sensitive_variables=frozenset(names),
                     credential_values=tuple(Value(value) for value in sorted(self.values[line, column])))
                for (line, column), names in sorted(self.matches.items())]
