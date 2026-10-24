"""Built-in command registration. Add a pure handler and declare its shells here."""
from functools import lru_cache

from .registry import CommandModel, CommandRegistry, SHELLS


def git(invocation):
    from ..git.semantics import describe_git
    from ..git.options import git_flag_known
    return describe_git(invocation.args, invocation.cwd, git_flag_known, shell=invocation.shell)


def docker(invocation):
    from ..misc.docker import describe_docker
    return describe_docker(invocation.args)


def sql(invocation):
    from ..sql.clients import describe_sql
    return describe_sql(invocation.name, invocation.args, invocation.cwd)


def sed(invocation):
    from ..misc.sed import describe_sed
    return describe_sed(invocation.args, invocation.cwd)


def find(invocation):
    from ..misc.find import describe_find
    return describe_find(invocation.args, invocation.cwd)


def su(invocation):
    from ..admin.su import describe_su
    return describe_su(invocation.args)


def packages(invocation):
    from ..misc.packages import describe_packages
    return describe_packages(invocation.name, invocation.args, invocation.cwd)


def tools(invocation):
    from ..misc.tools import describe_tool
    return describe_tool(invocation.name, invocation.args, invocation.cwd)


def common(invocation):
    from ..misc.common import describe_common
    return describe_common(invocation.name, invocation.args, invocation.cwd, shell=invocation.shell)


def read_tools(invocation):
    from ..misc.read_tools import model
    return model(invocation)


def linux_disks(invocation):
    from ..admin.linux_disks import model
    return model(invocation)


def inspection_tools(invocation):
    from ..misc.inspection_tools import model
    return model(invocation)


def compiler(invocation):
    from ..misc.compiler import model
    return model(invocation)


@lru_cache(maxsize=1)
def command_registry() -> CommandRegistry:
    from ..misc.common import SPECS
    from .commands import INTERPRETERS, TASKS, NETWORK_SINKS
    from ..sql.clients import SQL_CLIENTS
    from ..misc.compiler import COMPILERS
    bash = frozenset({"bash"})
    windows = SHELLS - bash
    # Keep shell support explicit: recognizing a Unix builtin does not make it
    # available as a native command in a Windows shell.
    common_names = (set(SPECS) | INTERPRETERS | TASKS | NETWORK_SINKS |
                    {"test", "[", "echo", "printf", "true", "false", ":", "reboot", "shutdown", "poweroff", "halt", "umount", "scp", "rsync", "dd"})
    native_common = {"npm", "pnpm", "yarn", "twine", "pip", "pip3", "pytest", "make", "python", "python3", "node", "curl", "wget", "scp", "rsync", *NETWORK_SINKS}
    return CommandRegistry((
        CommandModel({"git"}, git),
        CommandModel({"docker"}, docker),
        CommandModel(SQL_CLIENTS, sql),
        CommandModel({"su"}, su),
        CommandModel({"wipefs", "fdisk", "lsblk"}, linux_disks, bash),
        CommandModel({"sed"}, sed, bash),
        CommandModel({"find"}, find, bash),
        CommandModel({"stat", "file"}, inspection_tools, bash),
        CommandModel({"diff", "sort", "date", "uniq", "sha256sum"}, read_tools, bash),
        CommandModel(COMPILERS, compiler, bash),
        CommandModel({"conda", "dotnet"}, packages),
        CommandModel({"pacman", "paru"}, packages, bash),
        CommandModel({"javap", "nvidia-smi"}, tools),
        CommandModel({"source", ".", "timeout", "xargs", "sudo", "env", "head", "tail", "nl", "cut",
                      "du", "df", "which", "sleep", "ps", "free", "ss", "netstat", "journalctl", "systemctl"}, tools, bash),
        CommandModel(common_names, common, bash),
        CommandModel(native_common, common, windows),
        CommandModel({"npx"}, common, frozenset({"cmd"})),
    ))


def supports_native_command(name: str, shell: str) -> bool:
    return command_registry().supports(name, shell)
