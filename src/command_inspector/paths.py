"""Lexical path semantics, independent of the OS running fixture tests."""
import ntpath
import posixpath
import re
from dataclasses import dataclass
from .models import Value


@dataclass(frozen=True, slots=True)
class PathStyle:
    windows: bool = False

    @property
    def module(self):
        return ntpath if self.windows else posixpath

    def absolute(self, path):
        if self.windows:
            drive, tail = ntpath.splitdrive(path)
            return bool(drive) and (tail.startswith(("\\", "/")) or drive.startswith("\\\\") and not tail)
        return posixpath.isabs(path)

    def norm(self, path):
        return self.module.normpath(path)

    def key(self, path):
        normalized = self.norm(path)
        return normalized.casefold() if self.windows else normalized

    def inside(self, path, root):
        try:
            return self.module.commonpath((self.key(path), self.key(root))) == self.key(root)
        except ValueError:
            return False

    def resolve(self, value: Value, cwd: str | None):
        text = value.text
        if text is None or value.pattern or text.startswith("~") or "\x00" in text:
            return None
        if self.windows:
            if re.match(r"^[A-Za-z]+:", text) and not re.match(r"^[A-Za-z]:", text):
                return None  # PowerShell provider paths are not filesystem paths.
            drive, tail = ntpath.splitdrive(text)
            if drive and not tail.startswith(("\\", "/")) and not drive.startswith("\\\\"):
                if cwd is None or ntpath.splitdrive(cwd)[0].casefold() != drive.casefold():
                    return None  # No ambient per-drive cwd discovery.
                text = tail
            if not drive and text.startswith(("\\", "/")):
                if cwd is None:
                    return None
                text = ntpath.splitdrive(cwd)[0] + text
        if cwd is None and not self.absolute(text):
            return None
        return self.norm(self.module.join(cwd or "", text))


def style_for(shell, cwd):
    # With no selected frontend, accept either absolute cwd dialect so the API
    # can report missing selection consistently, including on Windows hosts.
    return PathStyle(shell == "cmd" or shell in {"powershell", "python", "javascript", None} and bool(ntpath.splitdrive(cwd or "")[0]))
