"""Explicit .NET method allowlists and filesystem effects, without evaluation."""
from ..models import Value


def describe_method(builder, node, guard):
    receiver = node.children[0] if node.children else None
    member = next((c.text.casefold() for c in node.children if c.kind == 'member_name'), '')
    arguments = next((c for c in node.children if c.kind == 'argument_list'), None)
    items = []
    def collect(item):
        if item.kind == 'argument_expression':
            items.append(item)
        else:
            for child in item.children:
                collect(child)
    if arguments:
        collect(arguments)
        for item in items:
            builder.scan_subexpressions(item, guard)
    # Chained receivers can contain their own invocations/effects.
    if receiver and receiver.kind != 'type_literal':
        builder.scan_subexpressions(receiver, guard)
    values = tuple(builder.value(item) for item in items)
    type_name = receiver.text.strip('[]').casefold() if receiver and receiver.kind == 'type_literal' else None
    if type_name and type_name.startswith('system.'):
        type_name = type_name[7:]
    if type_name == 'regex':
        type_name = 'text.regularexpressions.regex'
    if member == 'frombase64string':
        builder.emit('content', 'encoded-command', guard=guard)
        builder.unresolved('Decoded method result is outside the supported subset', guard=guard)
        return
    pure_static = {
        'text.regularexpressions.regex': {'matches', 'match', 'ismatch'},
        'math': {'abs', 'round', 'floor', 'ceiling', 'min', 'max', 'pow', 'sqrt', 'sign', 'truncate', 'log', 'log10', 'exp', 'sin', 'cos', 'tan'},
        'string': {'isnullorempty', 'isnullorwhitespace', 'join', 'format', 'concat', 'compare', 'equals'},
        'io.path': {'combine', 'join', 'getfilename', 'getfilenamewithoutextension', 'getextension', 'getdirectoryname', 'getfullpath', 'ispathrooted', 'ispathfullyqualified', 'getrelativepath', 'changeextension', 'getinvalidfilenamechars', 'getinvalidpathchars'},
        'convert': {'toint32', 'toint64', 'tostring', 'toboolean', 'todouble', 'todecimal'},
    }
    if type_name in pure_static and member in pure_static[type_name]:
        return
    if type_name in {'io.file', 'io.directory'}:
        target = values[:1] or (Value(None, 'missing_method_argument'),)
        if member in {'exists', 'getcreationtime', 'getlastwritetime', 'getlastaccesstime', 'getattributes'}:
            builder.filesystem('read', 'list', target, guard=guard)
        elif type_name == 'io.file' and member in {'readalltext', 'readalllines', 'readallbytes', 'readlines', 'openread'}:
            builder.filesystem('read', 'ingest', target, guard=guard)
        elif type_name == 'io.directory' and member in {'getfiles', 'getdirectories', 'getfilesystementries', 'enumeratefiles', 'enumeratedirectories', 'enumeratefilesystementries'}:
            builder.filesystem('read', 'list', target, guard=guard)
        elif member == 'delete':
            recursive = type_name == 'io.directory' and len(values) > 1 and (values[1].text or '').casefold() == 'true'
            flags = {'-r', '-f'} if recursive else set()
            if {n for v in target for n in v.variables} & builder.failed:
                flags.add('failed_assignment')
                if any(v.text is None for v in target):
                    flags.add('failed_assignment_unknown')
            if type_name == 'io.directory' and len(values) > 1 and (values[1].text or '').casefold() not in {'true', 'false'}:
                flags.add('recursion_unresolved')
            unknown_variables = values[1].variables if 'recursion_unresolved' in flags and values[1].text is None else ()
            builder.filesystem('delete', 'delete', target, flags, guard=guard, unresolved_variables=unknown_variables)
        elif type_name == 'io.file' and member in {'writealltext', 'writealllines', 'writeallbytes', 'appendalltext', 'appendalllines'}:
            unknown_variables = values[1].variables if len(values) > 1 and values[1].text is None else ()
            builder.filesystem('write', 'append' if member.startswith('append') else 'overwrite', target, payload=values[1].text if len(values)>1 else None, guard=guard,
                               unresolved_variables=unknown_variables)
        elif type_name == 'io.directory' and member == 'createdirectory':
            builder.filesystem('write', 'create_directory', target, guard=guard)
        elif member in {'copy', 'move'}:
            builder.filesystem('read', 'list', target, guard=guard)
            builder.filesystem('write', member, values[1:2] or (Value(None),), guard=guard)
            if member == 'move':
                builder.emit('invalidate', 'move_source', target, guard=guard)
        elif member in {'create', 'createtext', 'openwrite', 'setattributes', 'setcreationtime', 'setlastwritetime', 'setlastaccesstime'}:
            builder.filesystem('write', 'transform', target, guard=guard)
        else:
            builder.unresolved('Unmodeled filesystem method: '+member, guard=guard)
        return
    if type_name == 'diagnostics.process' and member == 'start':
        builder.unresolved('Started process content is unavailable', 'execution-content-unavailable', guard, values=values)
        return
    pure_string = {'trim', 'trimstart', 'trimend', 'split', 'replace', 'toupper', 'tolower', 'toupperinvariant', 'tolowerinvariant', 'substring', 'contains', 'startswith', 'endswith', 'indexof', 'lastindexof', 'padleft', 'padright', 'tochararray', 'tostring', 'gettype'}
    # Display-oriented string transformations do not require a concrete value.
    # The result stays unresolved; path/execution consumers diagnose it there.
    # Receiver and argument effects have already been inspected above.
    if type_name is None and receiver and member in pure_string:
        return
    builder.unresolved('Method receiver or operation is unresolved: '+member, 'unresolved-value', guard,
                       values=(*values, builder.value(receiver)) if receiver else values)
