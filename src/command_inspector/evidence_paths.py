"""Bounded metadata traversal shared by local and fixture evidence providers."""
from .wildcards import component_matches, unsupported_pattern


def match_targets(tree, request):
    paths, examined, complete, reason = [], 0, True, None
    problem = unsupported_pattern(request.pattern, request.profile)
    if problem:
        return {"paths": [], "match_count": 0, "examined_entries": 0}, False, problem
    directories_only = request.pattern.endswith("/")
    parts = request.pattern.rstrip("/").split("/")
    pending = [(request.base, 0)]
    while pending:
        directory, index = pending.pop()
        if examined >= request.max_entries:
            complete, reason = False, "entry_limit"
            break
        examined += 1
        try:
            kind, _ = tree.info(directory)
            if kind != "directory":
                if kind == "symlink":
                    complete, reason = False, "directory_link_not_followed"
                continue
            with tree.children(directory) as entries:
                for path, name in entries:
                    if examined >= request.max_entries:
                        complete, reason = False, "entry_limit"
                        break
                    examined += 1
                    try:
                        kind, _ = tree.info(path)
                    except OSError:
                        complete, reason = False, "filesystem_access_failed"
                        continue
                    matches = component_matches(name, parts[index], request.profile)
                    if index == len(parts) - 1:
                        if matches and directories_only and kind == "symlink":
                            complete, reason = False, "directory_link_not_followed"
                        if matches and (not request.files_only or kind != "directory") and (not directories_only or kind == "directory"):
                            if len(paths) >= request.max_matches:
                                complete, reason = False, "match_limit"
                                break
                            paths.append(path)
                        if request.recursive and kind == "directory":
                            pending.append((path, index))
                        elif request.recursive and kind == "symlink":
                            complete, reason = False, "directory_link_not_followed"
                    elif matches and kind == "directory":
                        pending.append((path, index + 1))
                    elif matches and kind == "symlink":
                        complete, reason = False, "directory_link_not_followed"
                    if len(pending) > request.max_entries - examined:
                        pending = pending[:max(0, request.max_entries - examined)]
                        complete, reason = False, "entry_limit"
        except FileNotFoundError:
            # A vanished child is not proof of a complete empty selection.
            complete, reason = False, "filesystem_changed"
        except OSError:
            complete, reason = False, "filesystem_access_failed"
        if reason == "match_limit":
            break
    key = (lambda p: p.casefold()) if request.windows else (lambda p: p)
    return {"paths": sorted(paths, key=key), "match_count": len(paths),
            "examined_entries": examined}, complete, reason


def summarize_deletion(tree, request):
    files = directories = size = examined = 0
    paths, pending = [], [(request.path, 0)]
    complete, paths_complete, reason = True, True, None
    while pending:
        if examined >= request.max_entries:
            complete, reason = False, "entry_limit"
            break
        path, depth = pending.pop()
        examined += 1
        try:
            kind, length = tree.info(path)
            selected = kind != "directory" or not request.files_only
            if selected:
                if kind == "directory":
                    directories += 1
                else:
                    files += 1
                    size += length if kind == "file" else 0
                if len(paths) < request.max_paths:
                    paths.append(path)
                else:
                    paths_complete = False
            if kind == "directory" and (request.recursive or request.files_only and depth == 0):
                with tree.children(path) as entries:
                    for child, _ in entries:
                        if examined + len(pending) >= request.max_entries:
                            complete, reason = False, "entry_limit"
                            break
                        pending.append((child, depth + 1))
            if kind == "directory" and not request.recursive:
                if not request.files_only:
                    # The command might reject a nonempty directory or prompt.
                    complete, reason = False, "directory_deletion_not_established"
        except OSError:
            complete, reason = False, "filesystem_access_failed"
    return {"files": files, "directories": directories, "logical_bytes": size,
            "affected_paths": sorted(paths), "affected_paths_complete": paths_complete and complete,
            "examined_entries": examined}, complete, reason
