"""Private authentication operands retained across native command lowering."""
import re
from .options import CommandSpec, take_wrapper_options


AUTH_TEXT = re.compile(r"(?i)(?:\b(?:proxy-)?authorization\s*:|https?://[^/@\s]+:[^/@\s]+@)")


def authentication_values(name, args):
    """Recognize auth with command-specific short options and named secrets.

    Keep the complete operand and its provenance private. Inline source may
    already have expanded variables when it reaches the native command model.
    """
    name = name.replace("\\", "/").rsplit("/", 1)[-1].lower().removesuffix(".exe")
    options = {"--password", "--passwd", "--proxy-password", "--http-password", "--ftp-password"}
    value_options = set(options)
    if name == "curl":
        options |= {"-u", "-U", "--user", "--proxy-user", "--oauth2-bearer", "--pass"}
    elif name == "wget":
        options |= {"--user", "--http-user", "--ftp-user", "--proxy-user"}
    elif name in {"docker", "podman"}:
        from ..misc.docker import GLOBAL_VALUES, GLOBAL_FLAGS
        _, index = take_wrapper_options(args, CommandSpec("D", tuple(GLOBAL_FLAGS), tuple(GLOBAL_VALUES)))
        if index is not None and index < len(args) and args[index].text == "login":
            args = args[index + 1:]
            options.add("-p")
    if name in {"curl", "wget"}:
        from ..misc.common import SPECS
        value_options.update(SPECS[name].takes_value)
    value_options.update(options)
    credentials = []
    pending = None
    for argument in args:
        text = argument.text or ""
        if pending is not None:
            if pending or AUTH_TEXT.search(text):
                credentials.append(argument)
            pending = None
            continue
        if text == "--":
            break
        if AUTH_TEXT.search(text):
            credentials.append(argument)
        key, sep, _ = text.partition("=")
        if key in value_options:
            if sep and key in options:
                credentials.append(argument)
            elif not sep:
                pending = key in options
        elif text.startswith("-") and not text.startswith("--"):
            for offset, letter in enumerate(text[1:], 1):
                option = "-" + letter
                if option in value_options:
                    if offset + 1 < len(text):
                        if option in options:
                            credentials.append(argument)
                    else:
                        pending = option in options
                    break
    return tuple(credentials)
