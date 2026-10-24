"""Bounded scalar alternatives, independent of shells and filesystem evidence.

Alternatives are choices, never an argv array or an expanded wildcard. Unknown
values absorb a join. Products are bounded too; no candidates are truncated.
"""
from dataclasses import dataclass, replace
from itertools import product

from ..models import Value


DEFAULT_LIMIT = 16
DEFAULT_BYTES = 524288


@dataclass(frozen=True, slots=True)
class ValueLimits:
    count: int = DEFAULT_LIMIT
    bytes: int = DEFAULT_BYTES


def limits(limit):
    return limit if isinstance(limit, ValueLimits) else ValueLimits(count=limit)


def bounded(binding, limit=DEFAULT_LIMIT):
    item = value(binding)
    budget = limits(limit).bytes
    if item.text is not None and (len(item.text) > budget or len(item.text.encode("utf-8", errors="surrogatepass")) > budget):
        return Value(None, "value_bytes_limit", item.variables)
    return item


def compose(parts, separator="", suffix="", limit=DEFAULT_LIMIT):
    parts = tuple(parts)
    variables = tuple(sorted({name for part in parts for name in part.variables}))
    if any(part.text is None for part in parts):
        fragments = []
        for index, part in enumerate(parts):
            if index:
                fragments.append(separator)
            fragments.extend((part.text,) if part.text is not None else part.fragments or (None,))
        fragments.append(suffix)
        if len(fragments) > limits(limit).bytes or sum(len((s or '').encode('utf-8', errors='surrogatepass')) for s in fragments) > limits(limit).bytes:
            return Value(None, 'value_bytes_limit', variables)
        return Value(None, next((part.reason for part in parts if part.reason), "unresolved_composition"), variables,
                     fragments=tuple(fragments), component_safe=all(p.text is not None or p.component_safe for p in parts))
    budget = limits(limit).bytes
    size = len(suffix.encode("utf-8", errors="surrogatepass")) + max(0, len(parts) - 1) * len(separator.encode("utf-8", errors="surrogatepass"))
    for part in parts:
        size += len(part.text) if len(part.text) > budget else len(part.text.encode("utf-8", errors="surrogatepass"))
        if size > budget:
            return Value(None, "value_bytes_limit", variables)
    return Value(separator.join(part.text for part in parts) + suffix, variables=variables)


def bounded_arguments(arguments, limit=DEFAULT_LIMIT):
    """Keep literal effects visible when expanded argv exceeds the byte budget."""
    arguments = tuple(arguments)
    budget = limits(limit).bytes
    size = max(0, len(arguments) - 1)
    for argument in arguments:
        if argument.text is not None:
            size += len(argument.text) if len(argument.text) > budget else len(argument.text.encode("utf-8", errors="surrogatepass"))
        if size > budget:
            break
    if size > budget:
        return tuple(Value(None, "value_bytes_limit", v.variables) if v.variables else v for v in arguments)
    return arguments


def value(binding):
    return binding if isinstance(binding, Value) else Value(binding)


def candidates(binding):
    item = value(binding)
    return item.alternatives or (item,)


def join(bindings, limit=DEFAULT_LIMIT, name=""):
    items = [bounded(binding, limit) for binding in bindings]
    if items and all(item == items[0] for item in items):
        if len(items[0].alternatives) > limits(limit).count:
            return Value(None, "possible_values_limit", items[0].variables or ((name,) if name else ()))
        if items[0].alternatives and any(bounded(v, limit).text is None for v in items[0].alternatives):
            return Value(None, "value_bytes_limit", items[0].variables)
        return items[0]
    variables = tuple(sorted({n for item in items for n in item.variables} | ({name} if name else set())))
    local = bool(items) and all(item.local_definition for item in items)
    if items and all(item.component_safe and item.fragments == items[0].fragments for item in items):
        return replace(items[0], variables=variables, local_definition=local)
    unique = {}
    for item in items:
        for candidate in candidates(item):
            candidate = bounded(candidate, limit)
            if candidate.text is None:
                return Value(None, candidate.reason or "missing_variable", variables)
            key = (candidate.text, candidate.pattern, candidate.pattern_text)
            unique.setdefault(key, replace(candidate, variables=()))
            if len(unique) > limits(limit).count:
                return Value(None, "possible_values_limit", variables)
    if not unique:
        return Value(None, "missing_variable", variables)
    if len(unique) == 1:
        return replace(next(iter(unique.values())), variables=variables, local_definition=local)
    return Value(None, variables=variables, alternatives=tuple(unique.values()), local_definition=local)


def join_maps(maps, limit=DEFAULT_LIMIT, *, strings=False):
    result = {}
    for name in set().union(*(mapping.keys() for mapping in maps)):
        merged = join((mapping.get(name) for mapping in maps), limit, name)
        result[name] = merged.text if strings and merged.text is not None else merged
    return result


def choices(bindings, names, limit=DEFAULT_LIMIT):
    selected = {name: value(bindings[name]) for name in sorted(set(names))
                if name in bindings and value(bindings[name]).alternatives}
    if not selected:
        return (), ()
    size = 1
    for item in selected.values():
        size *= len(item.alternatives)
        if size > limits(limit).count:
            return ({name: Value(None, "possible_values_limit", (name,)) for name in selected},), ()
    metadata = tuple((name, tuple(v.text for v in item.alternatives)) for name, item in selected.items())
    return tuple(dict(zip(selected, row)) for row in product(*(v.alternatives for v in selected.values()))), metadata


def evaluate(bindings, names, function, limit=DEFAULT_LIMIT):
    rows, _ = choices(bindings, names, limit)
    if not rows:
        return bounded(function(bindings), limit)
    return join((function(bindings | row) for row in rows), limit)


def mark(facts, metadata, group=None, case=0):
    if not metadata and group is None:
        return facts
    sensitive = set().union(*(fact.sensitive_variables for fact in facts))
    metadata = tuple((name, ("[REDACTED]",) if name in sensitive else values) for name, values in metadata)
    return [replace(fact, flags=fact.flags | ({"possible"} if metadata else set()),
                    sensitive_variables=fact.sensitive_variables | sensitive,
                    possible_values=tuple(dict((*fact.possible_values, *metadata)).items()),
                    choice_path=((group, case),) + fact.choice_path if group is not None else fact.choice_path) for fact in facts]


def expand_fact(fact, limit=DEFAULT_LIMIT, *, paths=None):
    """Lift remaining value-bearing facts (including redirects and pipe input)."""
    fields = ("values", "stdin_sources", "transfer_sources")
    bindings = {f"{field}:{i}": v for field in fields for i, v in enumerate(getattr(fact, field))}
    if fact.payload_value is not None:
        bindings["payload"] = fact.payload_value
    if fact.stdin_payload_value is not None:
        bindings["stdin_payload"] = fact.stdin_payload_value
    rows, _ = choices(bindings, bindings, limit)
    if not rows:
        return (fact,)
    metadata = {}
    for item in bindings.values():
        if item.alternatives:
            for name in item.variables:
                metadata[name] = tuple(v.text for v in item.alternatives)
    result = []
    for row in rows:
        changes = {field: tuple(row.get(f"{field}:{i}", v) for i, v in enumerate(getattr(fact, field))) for field in fields}
        if "payload" in row:
            changes.update(payload=row["payload"].text, payload_value=None)
        if "stdin_payload" in row:
            changes.update(stdin_payload=row["stdin_payload"].text, stdin_payload_value=None)
        candidate = replace(fact, **changes)
        if "values" in changes and fact.kind in {"read", "write", "delete", "invalidate", "path_invocation"}:
            from ..paths import style_for
            profile = paths if paths is not None else style_for(fact.shell, fact.cwd)
            candidate = replace(candidate, targets=tuple(p for v in candidate.values if (p := profile.resolve(v, fact.cwd)) is not None))
        if any(v.alternatives for v in bindings.values()) and all(v.text is not None for v in row.values()):
            candidate = replace(candidate, flags=candidate.flags | {"possible"}, possible_values=tuple(dict((*fact.possible_values, *metadata.items())).items()))
        result.append(candidate)
    return tuple(result)
