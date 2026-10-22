"""Visible interpreter stdin provenance; never read or evaluate source here."""
from dataclasses import replace


def execution_consumer(facts, depth=0):
    if any(f.kind == "execute" for f in facts):
        return True
    if depth < 3:
        from .commands import wrapped_facts
        return any(execution_consumer(wrapped_facts(f), depth + 1) for f in facts if f.kind == "invoke")
    return False


def file_stream_sources(facts):
    """Callers establish cat/Get-Content/TYPE identity; reject transformations."""
    reads = [f for f in facts if f.kind == "read" and f.operation == "ingest"]
    if len(reads) != 1 or reads[0].flags - {"output_to_pipe"}:
        return None
    return reads[0].values or None


def attach_execution_input(facts, *, values=None, payload=None, override=False, invocation=None, guard=None):
    result = []
    for fact in facts:
        selected = (fact.kind in {"execute", "invoke", "credential_input"}
                    and (guard is None or fact.guard == guard)
                    and (invocation is None or f"stdin_invocation:{invocation}" in fact.flags))
        if selected and (override or not fact.flags & {"stdin_source", "stdin_redirected"}):
            flags = fact.flags | {"stdin_source", "stdin_redirected" if override else "pipeline_stdin"}
            variables = set(fact.unresolved_variables) | {name for value in values or () if value.text is None for name in value.variables}
            result.append(replace(fact, flags=flags, stdin_sources=tuple(values or ()), stdin_payload=payload,
                                  unresolved_variables=tuple(sorted(variables))))
        else:
            result.append(fact)
    return result
