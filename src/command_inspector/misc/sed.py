"""Bounded sed programs. Recognise effects without running a sed interpreter."""
import re
from ..models import Fact, Value


def describe_sed(args, cwd):
    from ..shared.options import CommandSpec, parse_options
    from ..shared.commands import resolve_path
    facts, normalized, inplace, ended, valued_next = [], [], False, False, False
    for value in args:
        word = value.text or ''
        if ended or valued_next:
            normalized.append(value)
            valued_next = False
            continue
        if word == '--':
            ended = True
            normalized.append(value)
        elif word == '--in-place' or word.startswith('--in-place='):
            inplace = True
        else:
            # -ni combines quiet and in-place; letters after i are an optional
            # backup suffix. e/f consume their remaining text as a program/path.
            prefix = re.match(r'^-([nEzru]*)([ief])', word)
            if prefix and prefix[2] == 'i':
                inplace = True
                if prefix[1]:
                    normalized.append(Value('-'+prefix[1]))
            else:
                normalized.append(value)
                valued_next = word in {'-e', '--expression', '-f', '--file'} or bool(prefix and prefix[2] in {'e', 'f'} and len(word) == prefix.end())
    spec = CommandSpec('nEzru', ('--quiet', '--silent', '--regexp-extended', '--debug', '--posix', '--sandbox', '--unbuffered', '--help', '--version'), ('-e', '--expression', '-f', '--file'))
    operands, flags, bound, unknown = parse_options(tuple(normalized), spec)
    for option in unknown:
        facts.append(Fact('unresolved', 'unknown-option', payload=option))
    if flags & {'--help', '--version'}:
        return facts
    def emit(kind, operation, values=(), payload=None, extra_flags=()):
        facts.append(Fact(kind, operation, tuple(p for v in values if (p := resolve_path(v, cwd)) is not None), tuple(values), frozenset(extra_flags), payload))
    scripts = [v for k, v in bound.occurrences if k in {'-e', '--expression'}]
    script_files = [v for k, v in bound.occurrences if k in {'-f', '--file'}]
    if not scripts and not script_files:
        scripts, operands = list(operands[:1]), operands[1:]
    targets = (Value(None, 'unknown_option_operand_binding'),) if unknown else tuple(v for v in operands if v.text != '-')
    emit('read', 'ingest', targets, extra_flags={'selection_uncertain', 'output_consumed'} if inplace else {'selection_uncertain'})
    if inplace:
        emit('write', 'transform', targets)
    for value in script_files:
        emit('read', 'list', (value,))
        emit('unresolved', 'execution-content-unavailable', payload='Sed program file is not inspected')
    for script in scripts:
        if script.text is None:
            emit('unresolved', 'execution-content-unavailable', payload='Sed program is unresolved')
            continue
        # Split only outside substitutions: semicolons and letters inside their
        # regex/replacement are data, not commands. Escaped delimiters stay data.
        text, i = script.text, 0
        while i < len(text):
            while i < len(text) and text[i] in ' \t\r\n;{}':
                i += 1
            if i == len(text):
                break
            for address_index in range(2):
                address = re.match(r'(?:\d+(?:~\d+)?|\$|[+~]\d+)\s*', text[i:])
                if address:
                    i += len(address[0])
                elif i < len(text) and text[i] == '/':
                    end = _delimiter_end(text, i+1, '/')
                    if end is None:
                        emit('unresolved', 'execution-content-unavailable', payload='Sed address is unresolved'); i = len(text); break
                    i = end + 1
                else:
                    break
                while i < len(text) and text[i] in ' \t':
                    i += 1
                if address_index == 0 and i < len(text) and text[i] == ',':
                    i += 1
                    continue
                break
            while i < len(text) and text[i] in ' !\t':
                i += 1
            if i >= len(text):
                break
            command = text[i]; i += 1
            if command == '{':
                continue
            if command == 's' and i < len(text):
                delimiter = text[i]; i += 1
                first = _delimiter_end(text, i, delimiter)
                second = _delimiter_end(text, first + 1, delimiter) if first is not None else None
                if second is None:
                    emit('unresolved', 'unresolved-value', payload='Sed substitution is unresolved'); break
                i = second + 1
                end = re.search(r'[;\n}]', text[i:])
                stop = i + end.start() if end else len(text)
                suffix = text[i:stop].strip()
                if re.search(r'^[gIp\d\s]*e', suffix):
                    emit('unresolved', 'execution-content-unavailable', payload='Sed executes its transformed output as shell code')
                write = re.search(r'(?:^|\s|[gIp\d])w\s+(.+)', suffix)
                if write:
                    emit('write', 'transform', (Value(write[1].strip()),))
                elif suffix and not re.fullmatch(r'[gIpe\d\s]*', suffix):
                    emit('unresolved', 'execution-content-unavailable', payload='Sed substitution flags are unresolved')
                i = stop
            elif command in {'r', 'R', 'w', 'W', 'e'}:
                end = re.search(r'\n', text[i:])
                stop = i + end.start() if end else len(text)
                operand = text[i:stop].strip()
                if command == 'e':
                    emit('inline', 'shell', payload=operand) if operand else emit('unresolved', 'execution-content-unavailable', payload='Sed executes its pattern space')
                else:
                    emit('read' if command in {'r', 'R'} else 'write', 'ingest' if command in {'r', 'R'} else 'transform', (Value(operand) if operand else Value(None),))
                i = stop
            elif command in {'a', 'i', 'c', '#'}:
                # Inserted text/comments consume the rest of the physical line.
                end = text.find('\n', i)
                i = end if end >= 0 else len(text)
            elif command in 'pdDqQnNhHgGxyl=PbBtTz':
                if command in 'bBtT':
                    end = re.search(r'[;\n}]', text[i:]); i += end.start() if end else len(text)-i
                elif command in 'qQl':
                    number = re.match(r'\s*\d+', text[i:]); i += len(number[0]) if number else 0
                elif command == 'y':
                    emit('unresolved', 'execution-content-unavailable', payload='Sed transliteration is not modeled'); break
            else:
                emit('unresolved', 'execution-content-unavailable', payload='Sed program is outside the supported subset'); break
    return facts


def _delimiter_end(text, start, delimiter):
    escaped = False
    for index in range(start, len(text)):
        if escaped:
            escaped = False
        elif text[index] == '\\':
            escaped = True
        elif text[index] == delimiter:
            return index
    return None
