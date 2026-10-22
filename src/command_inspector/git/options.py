"""Shared Git flag recognition for the static Git behavior model."""
import re


#: Flags accepted by the shared Git command profile.
_GIT_FLAGS = {
    "--show-current", "--check", "--write-tree", "-r",
    "--hard", "--soft", "--mixed", "--keep", "--merge", "--rebase", "--autostash", "--no-edit",
    "--get", "--get-all", "--get-regexp", "--get-url", "--list", "-l", "--global", "--local", "--system",
    "--unset", "--unset-all", "--add", "--replace-all", "--remove-section", "--rename-section",
    "--short", "--porcelain", "--long", "--add", "--all", "-A", "-u", "--set-upstream", "--track", "-t",
    "--force", "-f", "--force-with-lease", "--force-if-includes", "--delete", "-d", "--tags", "--no-tags",
    "--follow-tags", "--atomic", "--signed", "--dry-run", "-n", "--prune", "-p", "--patch", "-N",
    "--intent-to-add", "--amend", "--no-verify", "-m", "-a", "--author", "--date", "--allow-empty",
    "--allow-empty-message", "--no-ff", "--squash", "--signoff", "-s", "--file", "-F", "--cached",
    "--staged", "--worktree", "--stash", "--graph", "--oneline", "--decorate", "--stat", "--name-only",
    "--name-status", "--follow", "--since", "--until", "--tree-filter", "--msg-filter", "--index-filter",
    "--subdirectory-filter", "--prune-empty", "--set-url", "--set-head", "--set-branches", "--origin",
    "--branch", "-b", "-B", "-M", "--move", "-c", "-C", "--orphan", "--detach", "--remote", "-v",
    "--verbose", "-q", "--quiet", "-g", "-G", "-4", "-6", "--no-pager", "--no-commit", "--reset-author",
    "--ff", "--ff-only", "--no-ff", "--no-rebase", "--rebase-merges", "--depth", "--shallow-since",
    "--unshallow", "--jobs", "-j", "--recurse-submodules", "--no-recurse-submodules", "--auto-stash",
    "--prune-tags", "--ipv4", "--ipv6", "--no-write-fetch-head", "--filter", "--also-filter-submodules",
}


#: `git log -20` and friends accept a bare count shorthand.
_GIT_COUNT = re.compile(r"^-\d+$")


def git_flag_known(word: str) -> bool:
    return word.split("=")[0] in _GIT_FLAGS or bool(_GIT_COUNT.match(word))
