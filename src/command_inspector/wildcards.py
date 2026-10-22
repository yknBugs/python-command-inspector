"""Pure, component-wise wildcard profiles. No filesystem access or shell calls."""
import fnmatch
import re
from dataclasses import dataclass

from .models import Value
from .paths import PathStyle


def literal_pattern(text: str) -> str:
    return text.replace("[", "[[]").replace("*", "[*]").replace("?", "[?]")


@dataclass(frozen=True, slots=True)
class PatternSelection:
    base: str
    pattern: str
    profile: str
    windows: bool


def selection_for(value: Value, cwd: str | None, shell: str, paths: PathStyle):
    """Resolve only the literal prefix; never normalize away a wildcard/.. pair."""
    text = value.pattern_text or value.text
    if not value.pattern or not text or "\x00" in text or text.startswith("~"):
        return None
    if paths.windows:
        text = text.replace("\\", "/")
    parts = text.split("/")
    index = next((i for i, p in enumerate(parts) if any(c in p for c in "*?[")), None)
    if index is None:
        return None
    prefix = "/".join(parts[:index])
    if index and not prefix:
        prefix = "/"
    if paths.windows and re.fullmatch(r"[A-Za-z]:", prefix) and index > 0:
        prefix += "/"
    base = paths.resolve(Value(prefix or "."), cwd)
    if base is None:
        return None
    profile = shell
    if shell == "python":
        profile = "python-pathlib" if value.reason == "python_pathlib_glob" else "python-glob"
        if paths.windows:
            profile += "-windows"
    return PatternSelection(base, "/".join(parts[index:]), profile, paths.windows)


def unsupported_pattern(pattern: str, profile: str) -> str | None:
    parts = pattern.rstrip("/").split("/")
    if not pattern or any(p in {"", ".", ".."} for p in parts):
        return "unsupported_pattern_component"
    if any("**" in p for p in parts):
        return "globstar_not_modeled"
    if profile not in {"bash", "powershell", "cmd", "python-glob", "python-pathlib", "python-glob-windows", "python-pathlib-windows"}:
        return "unsupported_pattern_profile"
    if profile == "bash" and any(token in pattern for token in ("[:", "[.", "[=")):
        return "locale_pattern_not_modeled"
    if profile == "cmd" and (len(parts) != 1 or any(c in pattern for c in "?+")):
        return "cmd_wildcard_semantics_unavailable"
    if profile == "powershell" and ("?" in pattern or re.search(r"\[(?:!|\^)", pattern)):
        return "powershell_filesystem_wildcard_semantics_unavailable"
    return None


def component_matches(name: str, pattern: str, profile: str) -> bool:
    if profile in {"bash", "python-glob", "python-glob-windows"} and name.startswith(".") and not pattern.startswith("."):
        return False
    if profile == "cmd" and pattern == "*.*":
        pattern = "*"
    if profile in {"powershell", "cmd", "python-glob-windows", "python-pathlib-windows"}:
        name, pattern = name.casefold(), pattern.casefold()
    if profile == "powershell":
        # Single-quoted PowerShell paths retain wildcard escape backticks.
        pattern = re.sub(r"`(.)", lambda m: literal_pattern(m[1]), pattern)
    return fnmatch.fnmatchcase(name, pattern)
