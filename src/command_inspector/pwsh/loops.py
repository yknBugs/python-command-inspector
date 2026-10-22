"""Bounded ForEach-Object body inspection, without enumerating pipeline items."""
from ..models import Value
from ..shared.value_flow import join, join_maps


UNAVAILABLE_SCRIPT = object()


def combine_blocks(groups):
    if groups and any(group is not None for group in groups):
        return tuple(block for group in groups
                     for block in ((UNAVAILABLE_SCRIPT,) if group is None else group))
    return None


def script_blocks(node):
    """Extract literal blocks; retain null/dynamic slots for phase boundaries."""
    if node.kind == "script_block_expression":
        return (node,)
    if node.kind == "variable" and node.text.strip().casefold() == "$null":
        return (None,)
    if node.kind == "array_expression":
        body = next((c for c in node.children if c.kind == "statement_list"), None)
        if body is None:
            return ()
        groups = [script_blocks(c) for c in body.children if c.kind != "empty_statement"]
        return combine_blocks(groups) if groups else ()
    children = [c for c in node.children if c.kind not in {",", "(", ")"}]
    if node.kind == "array_literal_expression" or len(children) == 1:
        groups = [script_blocks(c) for c in children]
        return combine_blocks(groups)
    return None


def merge_bindings(builder, variables, arrays, env, cwd):
    """Retain only values shared by the zero-iteration and inspected-body paths."""
    for name in variables.keys() | builder.variables.keys():
        if variables.get(name) != builder.variables.get(name):
            builder.variables[name] = join((variables.get(name), builder.variables.get(name)), builder.limit, name)
    builder.arrays = {k: v for k, v in arrays.items()
                      if builder.arrays.get(k) == v and builder.variables.get(k) == variables.get(k)}
    builder.env = join_maps([env, builder.env], builder.limit, strings=True)
    if builder.cwd != cwd:
        builder.cwd = None


def describe_foreach_object(builder, positional, bound, flags, guard):
    if "whatif" in flags:
        builder.unresolved("WhatIf previews the operation without performing it", "unresolved-value", guard)
        return
    before_variables, before_arrays = dict(builder.variables), dict(builder.arrays)
    before_env, before_cwd = dict(builder.env), builder.cwd
    before_failed, before_halted = set(builder.failed), builder.halted
    before_input = builder.pipeline_input
    incoming = builder.pipeline_values
    if "inputobject" in bound:
        incoming = tuple(v for node in bound["inputobject"] for v in builder.values(node))
    iteration = join(incoming, builder.limit) if incoming is not None else Value(None)
    if iteration.text is None and not iteration.alternatives:
        builder.unresolved("Loop iteration counts are not modeled", guard=guard)

    phases = {"begin": [], "process": [], "end": []}
    parallel = "parallel" in bound
    for key in ("begin", "process", "end", "remainingscripts", "parallel"):
        arguments = bound.get(key, ())
        if len(arguments) > 1:
            builder.unresolved("Repeated ForEach-Object parameter leaves binding unresolved", "unresolved-value", guard)
        for node in arguments:
            blocks = script_blocks(node)
            if blocks is None:
                builder.unresolved("ForEach-Object script content is unavailable", "execution-content-unavailable", guard)
                continue
            phases[key if key in phases else "process"].extend(blocks)
    for node in positional:
        blocks = script_blocks(node)
        if blocks is None:
            # The simplified member form can call methods, including mutators.
            # Receiver types and method dispatch are deliberately not inferred.
            builder.unresolved("ForEach-Object member or script argument is unresolved", "unresolved-value", guard)
        else:
            phases["process"].extend(blocks)
    if "membername" in bound:
        builder.unresolved("ForEach-Object member dispatch is unresolved", "unresolved-value", guard)
    if not positional and not bound.keys() & {"process", "parallel", "membername"}:
        builder.unresolved("ForEach-Object operation is missing", "unresolved-value", guard)

    processes = phases["process"]
    if not parallel and len(processes) > 1:
        if "begin" not in bound:
            phases["begin"].append(processes.pop(0))
        if "end" not in bound and len(processes) > 1:
            phases["end"].append(processes.pop())
    if parallel:
        builder.unresolved("Parallel scheduling and runspace state are not modeled", guard=guard)
        builder.variables = {k: v for k, v in before_variables.items() if k in {"home", "true", "false", "null"}}
        builder.arrays = {}
        builder.failed = set()

    builder.pipeline_input = None  # Incoming output is not the body command's stdin.
    for phase in ("begin", "process", "end"):
        phase_state = builder.snapshot()
        start = len(builder.facts)
        def inspect_blocks():
            for block in phases[phase]:
                if block is None:
                    continue
                if block is UNAVAILABLE_SCRIPT:
                    builder.unresolved("ForEach-Object script content is unavailable", "execution-content-unavailable", guard)
                    continue
                builder.halted = before_halted
                for name in ("_", "psitem"):
                    builder.variables[name] = join(incoming, builder.limit, name) if incoming is not None and phase == "process" else Value(None, "loop_variable_unresolved", (name,))
                    builder.arrays.pop(name, None)
                label = "if the loop body runs" if phase == "process" else "if the ForEach-Object " + phase + " block runs"
                builder.walk(block, (guard + "; " if guard else "") + label)
        if phase != "process":
            inspect_blocks()
            continue
        # Current-item bindings are re-established before each abstract pass.
        for name in ("_", "psitem"):
            builder.variables[name] = join(incoming, builder.limit, name) if incoming is not None else Value(None, "loop_variable_unresolved", (name,))
            builder.arrays.pop(name, None)
        seed = builder.snapshot()
        for _ in range(builder.flow_steps):
            previous = builder.snapshot()
            inspect_blocks()
            builder.merge_states([seed, previous, builder.snapshot()])
            if builder.snapshot() == previous:
                break
        else:
            builder.widen_loop()
            widened = builder.snapshot()
            inspect_blocks()
            builder.merge_states([widened, builder.snapshot()])
        builder.merge_states([phase_state, builder.snapshot()])
        builder.facts[start:] = list(dict.fromkeys(builder.facts[start:]))

    if parallel:
        # Ordinary assignments and Set-Location in a runspace do not bind the caller.
        builder.variables, builder.arrays = before_variables, before_arrays
        builder.cwd, builder.failed = before_cwd, before_failed
        builder.env = {k: v for k, v in before_env.items() if builder.env.get(k) == v}
    else:
        merge_bindings(builder, before_variables, before_arrays, before_env, before_cwd)
    builder.halted, builder.pipeline_input = before_halted, before_input
    # Success of this cmdlet does not prove an earlier piped Set-Location worked.
    builder.pending_cd = None
