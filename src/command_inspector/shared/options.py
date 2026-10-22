"""Bounded option schemas and parsing for pure command models."""
from dataclasses import dataclass
from ..models import Value


@dataclass(frozen=True, slots=True)
class CommandSpec:
    short: str = ""
    long: tuple[str, ...] = ()
    takes_value: tuple[str, ...] = ()


def take_wrapper_options(values: tuple[Value, ...], spec: CommandSpec):
    """Split a transparent wrapper's own leading options from the wrapped command.

    Returns ``(unknown, index)``. ``index`` is the first token that is not one of
    the wrapper's own options; it is ``len(values)`` when the option run consumes
    the whole list (no explicit command operand), and ``None`` only when a token
    could not be resolved and the command position is therefore unknowable.
    """
    unknown: list[str] = []
    index = 0
    while index < len(values):
        text = values[index].text
        if text is None:
            return tuple(unknown), None
        if text == "--":
            return tuple(unknown), index + 1
        if not text.startswith("-") or text == "-":
            return tuple(unknown), index
        name, sep, _ = text.partition("=")
        if name in spec.takes_value:
            if not sep and index + 1 >= len(values):
                unknown.append(name)
                return tuple(unknown), None
            index += 1 if sep else 2
            continue
        if name in spec.long:
            index += 1
            continue
        if not text.startswith("--") and len(text) > 1:
            letters = text[1:]
            consumed = 1
            for offset, letter in enumerate(letters):
                option = "-" + letter
                if option in spec.takes_value:
                    # `-uroot` carries its value; `-u root` takes the next token.
                    consumed = 2 if offset + 1 == len(letters) else 1
                    break
                if letter not in spec.short:
                    consumed = None
                    break
            if consumed is not None:
                if consumed == 2 and index + 1 >= len(values):
                    unknown.append(option)
                    return tuple(unknown), None
                index += consumed
                continue
        unknown.append(name if text.startswith("--") else "-" + text[1])
        index += 1
    return tuple(unknown), len(values)


class OptionBindings(dict):
    """Last-value lookup plus all occurrences for cumulative upload options."""
    def __init__(self):
        super().__init__()
        self.occurrences = []

    def __setitem__(self, key, value):
        self.occurrences.append((key, value))
        super().__setitem__(key, value)


def parse_options(values: tuple[Value, ...], spec: CommandSpec):
    operands, flags, unknown = [], set(), []
    bound = OptionBindings()
    end = False
    i = 0
    while i < len(values):
        value = values[i]
        text = value.text
        if end or text is None or not text.startswith("-") or text == "-":
            operands.append(value)
        elif text == "--":
            end = True
        else:
            name, sep, attached = text.partition("=")
            if name in spec.takes_value:
                if sep:
                    bound[name] = Value(attached)
                elif i + 1 < len(values):
                    i += 1
                    bound[name] = values[i]
                else:
                    unknown.append(name)
                flags.add(name)
            elif name in spec.long:
                flags.add(name)
                if sep:
                    unknown.append(name)
            elif text.startswith("--"):
                unknown.append(name)
            else:
                for offset, letter in enumerate(text[1:], 1):
                    option = "-" + letter
                    if option in spec.takes_value:
                        if offset + 1 < len(text):
                            bound[option] = Value(text[offset + 1:])
                        elif i + 1 < len(values):
                            i += 1
                            bound[option] = values[i]
                        else:
                            unknown.append(option)
                        flags.add(option)
                        break
                    if letter in spec.short:
                        flags.add(option)
                    else:
                        unknown.append(option)
        i += 1
    return tuple(operands), frozenset(flags), bound, tuple(unknown)

