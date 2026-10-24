"""Output shapes proved from syntax; no producer is executed."""
import re
from ..models import Value


def component(reason='numeric_runtime', variables=()):
    return Value(None, reason, variables, fragments=(None,), component_safe=True)


def runtime_output(text, shell):
    text = text.strip()
    if shell == 'bash':
        match = re.fullmatch(r'''date\s+\+(['"]?)([%YymdHMS_0-9-]+)\1''', text)
        if match and not re.search(r'%(?![YymdHMS])', match[2]):
            return component('formatted_timestamp')
        # Only the extracted digest is a safe component, not sha256sum's whole line.
        if re.fullmatch(r"sha256sum\s+[A-Za-z0-9_./-]+\s*\|\s*cut\s+-d\s*' '\s+-f\s*1", text):
            return component('hex_digest')
    if shell == 'powershell':
        match = re.fullmatch(r'''(?i:Get-Date\s+-Format)\s+(['"]?)([yMdHhmsf_0-9-]{2,})\1''', text)
        if match:
            return component('formatted_timestamp')
    return None


def path_scope(value, paths, cwd):
    """Return a lexical containing directory, never an invented concrete target.

    Empty runtime output is allowed. Restrict support to a final component with
    a literal non-dot character, so failure/empty output cannot name its parent.
    """
    if not value.component_safe or not value.fragments or value.pattern:
        return None
    before = ''.join(s for s in value.fragments[:value.fragments.index(None)] if s is not None) if None in value.fragments else ''
    separator = max(before.rfind('/'), before.rfind('\\') if paths.windows else -1)
    if separator < 0:
        base, prefix = '.', before
    else:
        base, prefix = before[:separator + 1], before[separator + 1:]
    tail = value.fragments[value.fragments.index(None):]
    literals = prefix + ''.join(s for s in tail if s is not None)
    if any(c in literals for c in ('/\\:*?[]' if paths.windows else '/*?[]')):
        return None
    if not any(c not in '. ' for c in literals):
        return None
    root = paths.resolve(Value(base), cwd)
    # Device namespaces require dedicated operation predicates, not ordinary
    # bounded file handling. Do not lower their unresolved-target coverage.
    if root and (root == '/dev' or root.startswith('/dev/') or root.startswith(('\\\\.\\', '\\\\?\\'))):
        return None
    return root


def language_hint(value):
    if value.text is not None:
        return value.text
    if value.fragments and value.fragments[-1] is not None:
        # Only a suffix after the last hole establishes an extension.
        suffix = ''.join(s for s in value.fragments[value.fragments.index(None) + 1:] if s is not None)
        if None in value.fragments:
            last = len(value.fragments) - 1 - value.fragments[::-1].index(None)
            suffix = ''.join(value.fragments[last + 1:])
        return suffix
    return None
