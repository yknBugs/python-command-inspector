"""GNU stat and file(1) inspection; no tool execution or generated output."""
from ..models import Fact, Value
from ..shared.options import CommandSpec, parse_options


SPECS = {
    'stat': CommandSpec('LfNt', ('--dereference', '--file-system', '--literal', '--terse', '--help', '--version'),
                        ('-c', '--format', '--printf', '--cached')),
    'file': CommandSpec('bcCdEhiklLnNprsSvzZ0',
                        ('--apple', '--brief', '--checking-printout', '--compile', '--debug',
                         '--error', '--extension', '--mime', '--mime-type', '--mime-encoding',
                         '--keep-going', '--list', '--dereference', '--no-dereference',
                         '--no-buffer', '--no-pad', '--preserve-date', '--raw', '--special-files',
                         '--version', '--uncompress', '--uncompress-noreport', '--print0',
                         '--help', '--no-sandbox'),
                        ('-e', '--exclude', '--exclude-quiet', '-f', '--files-from',
                         '-F', '--separator', '-m', '--magic-file', '-P', '--parameter')),
}


def model(call):
    operands, flags, bound, unknown = parse_options(call.args, SPECS[call.name])
    facts = [Fact('unresolved', 'unknown-option', payload=option) for option in unknown]
    if flags & {'--help', '--version'} or call.name == 'file' and '-v' in flags:
        return facts
    inputs = (Value(None, 'unknown_option_operand_binding'),) if unknown else operands
    if call.name == 'stat':
        # Unlike cat/file, stat treats '-' as a literal filename.
        if inputs:
            facts.append(Fact('read', 'list', values=inputs))
        else:
            facts.append(Fact('unresolved', 'unresolved-value', payload='stat requires a file operand'))
        return facts
    inputs = tuple(v for v in inputs if v.text != '-')
    if inputs:
        facts.append(Fact('read', 'list', values=inputs,
                          flags=frozenset({'probe_device_contents'}) if flags & {'-s', '--special-files'} else frozenset()))
    for key, value in bound.occurrences:
        if key in {'-f', '--files-from'}:
            if value.text != '-':
                facts.append(Fact('read', 'list', values=(value,)))
            facts.append(Fact('unresolved', 'unresolved-value', values=(value,),
                              payload='file input paths depend on an uninspected filename list'))
        elif key in {'-m', '--magic-file'}:
            paths = tuple(Value(p, variables=value.variables) for p in value.text.split(':') if p) if value.text is not None else (value,)
            facts.append(Fact('read', 'list', values=paths))
    if flags & {'-C', '--compile'}:
        # Magic databases/directories and implicit search paths can select the
        # generated filenames. Do not assume compilation is a read-only query.
        facts.extend((Fact('unresolved', 'file-operation-unresolved',
                           payload='file compiles magic databases; generated output paths are not modeled'),
                      Fact('invalidate', 'magic-compile', values=(Value(None),))))
    if flags & {'-z', '-Z', '--uncompress', '--uncompress-noreport'}:
        facts.append(Fact('unresolved', 'execution-content-unavailable',
                          payload='file may invoke external decompressors; decompressor behavior is not inspected'))
    if not operands and not bound.keys() & {'-f', '--files-from'} and not flags & {'-c', '--checking-printout', '-C', '--compile', '-l', '--list'}:
        facts.append(Fact('unresolved', 'unresolved-value', payload='file requires an input file or filename list'))
    return facts
