"""Known discard devices, independent of the host filesystem."""


def is_null_device(path, paths):
    if path is None:
        return False
    if not paths.windows:
        return paths.key(path) == "/dev/null"
    # Preserve verbatim/device namespace paths rather than assuming DOS aliases.
    if path.startswith(("\\\\?\\", "\\\\.\\")):
        return False
    return paths.module.basename(path).casefold() == "nul"
