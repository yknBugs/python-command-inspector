"""Pull-based, bounded, read-only evidence. No command execution or findings."""
from dataclasses import dataclass, field, replace
from contextlib import contextmanager
from enum import Enum
from typing import Protocol
from pathlib import PurePath
import os
import ntpath
import stat
from .evidence_paths import match_targets, summarize_deletion
from .paths import PathStyle
from .effort import EvidenceEffort, evidence_effort


class EvidenceStatus(str, Enum):
    AVAILABLE = "available"
    MISSING = "missing"
    UNAVAILABLE = "unavailable"
    TRUNCATED = "truncated"


@dataclass(frozen=True, slots=True)
class StatTarget:
    path: str
    execution_profile: str | None = None


@dataclass(frozen=True, slots=True)
class ReadFile:
    path: str
    max_bytes: int


@dataclass(frozen=True, slots=True)
class SummarizeDeletion:
    path: str
    max_entries: int
    recursive: bool = True
    files_only: bool = False
    max_paths: int = 1024


@dataclass(frozen=True, slots=True)
class MatchTargets:
    base: str
    pattern: str
    max_entries: int
    max_matches: int = 1024
    profile: str = "bash"
    windows: bool = False
    recursive: bool = False
    files_only: bool = False


EvidenceRequest = StatTarget | ReadFile | SummarizeDeletion | MatchTargets


@dataclass(frozen=True, slots=True)
class EvidenceAnswer:
    status: EvidenceStatus
    data: dict = field(default_factory=dict, repr=False)
    reason: str | None = None
    complete: bool = True


class EvidenceProvider(Protocol):
    def answer(self, request: EvidenceRequest) -> EvidenceAnswer: ...


class DisabledEvidenceProvider:
    def answer(self, request: EvidenceRequest) -> EvidenceAnswer:
        return EvidenceAnswer(EvidenceStatus.UNAVAILABLE, reason="evidence_disabled", complete=False)


class LocalEvidenceProvider:
    @staticmethod
    def info(path):
        info = os.lstat(path)
        reparse = getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        kind = ("symlink" if stat.S_ISLNK(info.st_mode) or reparse else
                "file" if stat.S_ISREG(info.st_mode) else "directory" if stat.S_ISDIR(info.st_mode) else "special")
        return kind, info.st_size

    @staticmethod
    @contextmanager
    def children(path):
        with os.scandir(path) as entries:
            yield ((entry.path, entry.name) for entry in entries)

    def answer(self, request: EvidenceRequest) -> EvidenceAnswer:
        path = request.base if isinstance(request, MatchTargets) else request.path
        prefix_entries = 0
        if not os.path.isabs(path) or path.startswith(("//", "\\\\")):
            return EvidenceAnswer(EvidenceStatus.UNAVAILABLE, reason="nonlocal_or_unresolved_path", complete=False)
        try:
            if isinstance(request, MatchTargets):
                if request.windows != (os.name == "nt"):
                    return EvidenceAnswer(EvidenceStatus.UNAVAILABLE, reason="host_path_style_mismatch", complete=False)
                # Check from the root down, so a symlink to a remote directory
                # is rejected before even probing a descendant through it.
                parent = ""
                for part in PurePath(path).parts:
                    if prefix_entries >= request.max_entries:
                        return EvidenceAnswer(EvidenceStatus.TRUNCATED, {"paths": [], "match_count": 0,
                                              "examined_entries": prefix_entries}, reason="entry_limit", complete=False)
                    prefix_entries += 1
                    parent = os.path.join(parent, part)
                    if self.info(parent)[0] == "symlink":
                        return EvidenceAnswer(EvidenceStatus.UNAVAILABLE, {"examined_entries": prefix_entries},
                                              reason="directory_link_not_followed", complete=False)
                data, complete, reason = match_targets(self, replace(request, max_entries=request.max_entries - prefix_entries))
                data["examined_entries"] += prefix_entries
                if complete and request.profile == "cmd" and request.pattern not in {"*", "*.*"}:
                    # Native CMD can also match 8.3 aliases; lstat/scandir provide
                    # only long names. Preserve observed matches without claiming
                    # that the unobserved alias selection is complete.
                    complete, reason = False, "cmd_short_name_matching_unavailable"
                data.update({"base": path, "pattern": request.pattern, "profile": request.profile})
                status = (EvidenceStatus.AVAILABLE if complete else EvidenceStatus.UNAVAILABLE
                          if data["examined_entries"] == prefix_entries and reason != "entry_limit" else EvidenceStatus.TRUNCATED)
                return EvidenceAnswer(status,
                                      data, reason=reason, complete=complete)
            info = os.lstat(path)
            reparse = getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
            kind = ("symlink" if reparse else "file" if stat.S_ISREG(info.st_mode) else "directory" if stat.S_ISDIR(info.st_mode)
                    else "symlink" if stat.S_ISLNK(info.st_mode) else "special")
            if isinstance(request, StatTarget):
                data = {"kind": kind, "exists": True, "size": info.st_size}
                if request.execution_profile:
                    data["executable"] = (False if kind in {"directory", "special"} else
                                          os.access(path, os.X_OK) if kind == "file" and request.execution_profile == "posix" and os.name != "nt" else None)
                return EvidenceAnswer(EvidenceStatus.AVAILABLE, data)
            if isinstance(request, ReadFile):
                if kind != "file":
                    return EvidenceAnswer(EvidenceStatus.UNAVAILABLE, reason="not_regular_file", complete=False)
                # Nonblocking + no-follow keeps a concurrent replacement by a FIFO or
                # symlink from turning this read into an unbounded operation.
                flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
                fd = os.open(path, flags)
                with os.fdopen(fd, "rb") as stream:
                    current = os.fstat(stream.fileno())
                    if not stat.S_ISREG(current.st_mode):
                        return EvidenceAnswer(EvidenceStatus.UNAVAILABLE, reason="not_regular_file", complete=False)
                    content = stream.read(request.max_bytes + 1)
                complete = len(content) <= request.max_bytes
                return EvidenceAnswer(EvidenceStatus.AVAILABLE if complete else EvidenceStatus.TRUNCATED,
                                      {"bytes": content[:request.max_bytes]}, complete=complete)
            data, complete, reason = summarize_deletion(self, request)
            status = (EvidenceStatus.AVAILABLE if complete else EvidenceStatus.UNAVAILABLE
                      if data["examined_entries"] == 0 else EvidenceStatus.TRUNCATED)
            return EvidenceAnswer(status,
                                  data, reason=reason, complete=complete)
        except FileNotFoundError:
            return EvidenceAnswer(EvidenceStatus.MISSING, {"examined_entries": prefix_entries} if isinstance(request, MatchTargets) else {})
        except OSError:
            return EvidenceAnswer(EvidenceStatus.UNAVAILABLE, {"examined_entries": prefix_entries} if isinstance(request, MatchTargets) else {},
                                  reason="filesystem_access_failed", complete=False)


class MemoryEvidenceProvider:
    """Fixture files and a query log; never falls back to disk."""
    def __init__(self, files: dict[str, str | bytes] | None = None,
                 answers: dict[EvidenceRequest, EvidenceAnswer] | None = None):
        self.files = dict(files or {})
        self.answers = dict(answers or {})
        self.queries: list[EvidenceRequest] = []

    def answer(self, request: EvidenceRequest) -> EvidenceAnswer:
        self.queries.append(request)
        if request in self.answers:
            return self.answers[request]
        if isinstance(request, (MatchTargets, SummarizeDeletion)):
            style = PathStyle(request.windows if isinstance(request, MatchTargets) else bool(ntpath.splitdrive(request.path)[0]))
            tree = _MemoryTree(self.files, style)
            path = request.base if isinstance(request, MatchTargets) else request.path
            if style.key(path) not in tree.nodes:
                return EvidenceAnswer(EvidenceStatus.MISSING)
            data, complete, reason = (match_targets(tree, request) if isinstance(request, MatchTargets)
                                      else summarize_deletion(tree, request))
            if isinstance(request, MatchTargets):
                data.update({"base": path, "pattern": request.pattern, "profile": request.profile})
            status = (EvidenceStatus.AVAILABLE if complete else EvidenceStatus.UNAVAILABLE
                      if data["examined_entries"] == 0 else EvidenceStatus.TRUNCATED)
            return EvidenceAnswer(status,
                                  data, reason=reason, complete=complete)
        path = request.path
        if path not in self.files and ntpath.splitdrive(path)[0]:
            # Windows fixture evidence follows the selected platform's lexical
            # identity even when these tests run on a case-sensitive host.
            key = ntpath.normpath(path).casefold()
            path = next((p for p in self.files if ntpath.normpath(p).casefold() == key), path)
        if path not in self.files:
            tree = _MemoryTree(self.files, PathStyle(bool(ntpath.splitdrive(path)[0])))
            if isinstance(request, StatTarget) and tree.style.key(path) in tree.nodes:
                return EvidenceAnswer(EvidenceStatus.AVAILABLE, {"kind": "directory", "exists": True, "size": 0})
            return EvidenceAnswer(EvidenceStatus.MISSING)
        content = self.files[path]
        raw = content.encode() if isinstance(content, str) else content
        if isinstance(request, StatTarget):
            return EvidenceAnswer(EvidenceStatus.AVAILABLE, {"kind": "file", "exists": True, "size": len(raw)})
        if isinstance(request, ReadFile):
            complete = len(raw) <= request.max_bytes
            return EvidenceAnswer(EvidenceStatus.AVAILABLE if complete else EvidenceStatus.TRUNCATED,
                                  {"bytes": raw[:request.max_bytes]}, complete=complete)


class CachedEvidenceProvider:
    """A new accessor per call; byte and enumeration budgets are shared."""
    def __init__(self, provider: EvidenceProvider, total_read_bytes: int, total_entries: int | None = None):
        self.provider = provider
        self.remaining = total_read_bytes
        self.remaining_entries = total_entries
        self.cache: dict[EvidenceRequest, EvidenceAnswer] = {}

    def answer(self, request: EvidenceRequest, *, effort=EvidenceEffort.FULL) -> EvidenceAnswer:
        effort = evidence_effort(effort)
        if effort is EvidenceEffort.NONE or effort is EvidenceEffort.PARTIAL and isinstance(request, ReadFile):
            return EvidenceAnswer(EvidenceStatus.UNAVAILABLE, reason="effort_" + effort.value.casefold(), complete=False)
        answer = self._answer(request)
        if effort is EvidenceEffort.PARTIAL:
            # Do not leak content/size from a richer cached or custom answer.
            allowed = ({"kind", "exists", "executable", "mode"} if isinstance(request, StatTarget) else
                       {"paths", "match_count", "examined_entries", "base", "pattern", "profile"} if isinstance(request, MatchTargets) else
                       {"files", "directories", "examined_entries", "affected_paths", "affected_paths_complete"})
            answer = replace(answer, data={k: v for k, v in answer.data.items() if k in allowed})
        return answer

    def _answer(self, request: EvidenceRequest) -> EvidenceAnswer:
        if request not in self.cache:
            if isinstance(request, ReadFile) and request.max_bytes > self.remaining:
                answer = EvidenceAnswer(EvidenceStatus.UNAVAILABLE, reason="total_read_budget", complete=False)
            elif isinstance(request, (MatchTargets, SummarizeDeletion)) and self.remaining_entries == 0:
                answer = EvidenceAnswer(EvidenceStatus.UNAVAILABLE, reason="total_entry_budget", complete=False)
            else:
                bounded = request
                if isinstance(request, (MatchTargets, SummarizeDeletion)) and self.remaining_entries is not None:
                    bounded = replace(request, max_entries=min(request.max_entries, self.remaining_entries))
                answer = self.provider.answer(bounded)
                if isinstance(request, ReadFile):
                    self.remaining -= len(answer.data.get("bytes", b""))
                if isinstance(request, (MatchTargets, SummarizeDeletion)) and self.remaining_entries is not None:
                    self.remaining_entries = max(0, self.remaining_entries - answer.data.get("examined_entries", 0))
            self.cache[request] = answer
        return self.cache[request]


class _MemoryTree:
    """Derive fixture directories without ever falling back to the host disk."""
    def __init__(self, files, style):
        self.style, self.nodes, self.entries = style, {}, {}
        for path, content in files.items():
            raw = content.encode() if isinstance(content, str) else content
            self.nodes[style.key(path)] = ("file", len(raw))
            child = style.norm(path)
            while True:
                parent = style.module.dirname(child)
                if not parent or parent == child:
                    break
                self.nodes.setdefault(style.key(parent), ("directory", 0))
                self.entries.setdefault(style.key(parent), {})[style.key(child)] = (child, style.module.basename(child))
                child = parent

    def info(self, path):
        try:
            return self.nodes[self.style.key(path)]
        except KeyError:
            raise FileNotFoundError(path) from None

    @contextmanager
    def children(self, path):
        yield iter(sorted(self.entries.get(self.style.key(path), {}).values()))
