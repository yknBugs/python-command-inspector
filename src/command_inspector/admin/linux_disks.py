"""Static util-linux disk utility models; never probe or open devices.

Reference: util-linux wipefs(8), fdisk(8), lsblk(8). Interactive fdisk input
is deliberately not treated as a shell program or a confirmed disk write.
"""
from dataclasses import replace

from ..models import Fact, Value
from ..shared.options import CommandSpec, parse_options

COMMANDS = frozenset({'wipefs', 'fdisk', 'lsblk'})
SPECS = {
    'wipefs': CommandSpec('abfJinpqhV',
        ('--all', '--backup', '--force', '--json', '--noheadings', '--no-act',
         '--parsable', '--quiet', '--help', '--version', '--lock'),
        ('-o', '--offset', '-O', '--output', '-t', '--types')),
    'fdisk': CommandSpec('BclLnsuxhV',
        ('--protect-boot', '--compatibility', '--color', '--list', '--list-details',
         '--noauto-pt', '--getsz', '--units', '--bytes', '--lock', '--help', '--version'),
        ('-b', '--sector-size', '-o', '--output', '-t', '--type', '-C', '--cylinders',
         '-H', '--heads', '-S', '--sectors', '-w', '--wipe', '-W', '--wipe-partitions')),
    'lsblk': CommandSpec('AabHDdfiJlMmNvnOPprSsTtyzhV',
        ('--noempty', '--all', '--bytes', '--list-columns', '--discard', '--nodeps',
         '--fs', '--ascii', '--json', '--list', '--merge', '--perms', '--nvme',
         '--virtio', '--noheadings', '--output-all', '--pairs', '--paths', '--raw',
         '--scsi', '--inverse', '--tree', '--topology', '--shell', '--zoned',
         '--help', '--version', '--hyperlink'),
        ('-E', '--dedup', '-e', '--exclude', '-I', '--include', '-o', '--output',
         '-Q', '--filter', '--highlight', '--ct', '--ct-filter', '-w', '--width',
         '-x', '--sort', '--sysroot', '--properties-by')),
}
# Optional arguments must be attached: --backup /dev/sda does NOT consume sda.
OPTIONAL = {
    'wipefs': {'--backup', '--lock', '-b'},
    'fdisk': {'--compatibility', '--color', '--units', '--lock', '-c', '-L', '-u'},
    'lsblk': {'--tree', '--hyperlink', '-T'},
}


def model(invocation):
    name, args = invocation.name, invocation.args
    normalized, optional, ended, required_value = [], {}, False, False
    for value in args:
        text = value.text
        if ended or required_value or text is None:
            normalized.append(value)
            required_value = False
            continue
        if text == '--':
            ended = True
            normalized.append(value)
            continue
        key, sep, attached = text.partition('=')
        if key in OPTIONAL[name]:
            normalized.append(replace(value, text=key))
            if sep:
                optional[key] = replace(value, text=attached)
            continue
        if key in SPECS[name].takes_value:
            normalized.append(value)
            required_value = not sep
            continue
        if text.startswith('-') and not text.startswith('--'):
            for index, letter in enumerate(text[1:], 1):
                option = '-' + letter
                if option in SPECS[name].takes_value:
                    required_value = index == len(text) - 1
                    break
                if option in OPTIONAL[name]:
                    normalized.append(replace(value, text=text[:index + 1]))
                    if index + 1 < len(text):
                        optional[option] = replace(value, text=text[index + 1:].removeprefix('='))
                    break
            else:
                normalized.append(value)
                continue
            if option in OPTIONAL[name]:
                continue
        normalized.append(value)
    operands, flags, bound, unknown = parse_options(tuple(normalized), SPECS[name])
    facts = [Fact('unresolved', 'unknown-option', payload=option) for option in unknown]
    if unknown or flags & {'-h', '--help', '-V', '--version'}:
        return facts
    # An unknown word can introduce an option, an option argument, or a target.
    # Do not turn partially bound arguments into a confirmed destructive action.
    if any(value.text is None for value in args):
        return [Fact('unresolved', 'file-operation-unresolved', values=args,
                     payload=f'{name} arguments or targets are unresolved'),
                *([Fact('invalidate', name, values=(Value(None),))] if name != 'lsblk' else [])]
    if name == 'lsblk':
        if '--sysroot' in bound:
            facts.append(Fact('read', 'list', values=(bound['--sysroot'],)))
        return facts
    if name == 'fdisk':
        if flags & {'-l', '--list', '-x', '--list-details', '-s', '--getsz'}:
            return facts
        if len(operands) != 1 or not operands[0].text:
            return [Fact('unresolved', 'unresolved-value', values=operands,
                         payload='fdisk requires one concrete device or disk image')]
        return [Fact('unresolved', 'file-operation-unresolved', values=operands,
                     payload='fdisk may modify a partition table; its dialog commands are not modeled'),
                Fact('invalidate', 'partition-dialog', values=operands,
                     targets=tuple(p for v in operands if (p := _resolve(invocation, v)) is not None))]
    erasing = bool(flags & {'-a', '--all', '-o', '--offset'})
    if not operands:
        return [Fact('unresolved', 'unresolved-value', payload='wipefs device or disk image is missing')]
    if not erasing:
        return facts
    if not flags & {'-n', '--no-act'}:
        facts.append(Fact('write', 'transform', values=operands))
    if flags & {'-b', '--backup'}:
        # Backup basenames depend on discovered signature offsets. Do not read
        # ambient HOME or invent an exact output filename.
        directory = optional.get('--backup', optional.get('-b'))
        facts.append(Fact('unresolved', 'file-operation-unresolved',
                          values=(directory,) if directory else (),
                          payload='wipefs backup filenames depend on runtime signature offsets'))
        facts.append(Fact('invalidate', 'signature-backup', values=(Value(None),)))
    return facts


def _resolve(invocation, value):
    from ..paths import PathStyle
    return PathStyle().resolve(value, invocation.cwd)
