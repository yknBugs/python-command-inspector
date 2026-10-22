"""Software recognised by name but not modelled by behaviour.

Why this exists: modelling every third-party tool's behaviour does not converge. There is no
afternoon in which `apt`, `yum`, `dnf`, `apk`, `pacman`, `brew`, `winget`, `choco`, `scoop`,
`cargo`, `go`, `gem` and their successors are all modelled. So a command that cannot be modelled
by what it DOES is still judged by WHAT IT IS: recognising `ufw` or `crontab` by name is cheap,
and "you are invoking the firewall controller" is worth a look whatever the argument says.

This is a different question from `unknown-command`, and both are kept:

* `tool-invoked` — the name is on this list. The reader learns WHICH software is being invoked,
  which is frequently enough to judge the call (`ufw disable` vs `ufw status` — even the name
  alone tells a reviewer to look).
* `unknown-command` — behavior is unmodeled and the name has no fallback category,
  or a modeled application's operation is unsupported. Known command names remain
  concrete in the report; only dynamic, unresolved names lack an identity.

Neither is silent, and neither is a guess: the name comes from the syntax tree's command
position, so `echo ufw` and `grep ufw file` do not match.

Adding a name here is deliberately a one-line change. The list is ordered for reading, not
matched in order.
"""

from __future__ import annotations

#: command name -> short English category, used in the finding's payload.
#:
#: Membership rule: the name identifies real software whose invocation can change system or
#: project state, and whose flags matter. A tool that only READS without a state-changing mode
#: belongs here too if reading it is itself worth a look (credential stores, process tables).
KNOWN_TOOLS: dict[str, str] = {
    # package managers — install code, run post-install scripts
    "apt": "package manager",
    "apt-get": "package manager",
    "aptitude": "package manager",
    "yum": "package manager",
    "dnf": "package manager",
    "rpm": "package manager",
    "dpkg": "package manager",
    "zypper": "package manager",
    "apk": "package manager",
    "pacman": "package manager",
    "brew": "package manager",
    "port": "package manager",
    "nix": "package manager",
    "nix-env": "package manager",
    "winget": "package manager",
    "choco": "package manager",
    "scoop": "package manager",
    "snap": "package manager",
    "flatpak": "package manager",
    "pip": "package manager",
    "pip3": "package manager",
    "poetry": "package manager",
    "uv": "package manager",
    "conda": "package manager",
    "mamba": "package manager",
    "npm": "package manager",
    "npx": "package manager",
    "yarn": "package manager",
    "pnpm": "package manager",
    "bun": "package manager",
    "cargo": "package manager",
    "rustup": "package manager",
    "go": "package manager",
    "gem": "package manager",
    "bundler": "package manager",
    "bundle": "package manager",
    "composer": "package manager",
    "nuget": "package manager",
    "dotnet": "package manager",
    "mvn": "package manager",
    "gradle": "package manager",
    "luarocks": "package manager",
    "cpan": "package manager",
    "opkg": "package manager",
    # firewalls, routing, packet filtering — a wrong flag opens or closes the host
    "ufw": "firewall controller",
    "iptables": "firewall controller",
    "ip6tables": "firewall controller",
    "nft": "firewall controller",
    "nftables": "firewall controller",
    "firewall-cmd": "firewall controller",
    "firewalld": "firewall controller",
    "pfctl": "firewall controller",
    "netsh": "network and firewall configuration",
    "route": "routing table",
    "ip": "network interface and routing",
    "ifconfig": "network interface",
    "iwconfig": "wireless interface",
    "nmcli": "network manager",
    "ethtool": "network interface",
    "tc": "traffic control",
    "sysctl": "kernel parameters",
    "modprobe": "kernel module",
    "insmod": "kernel module",
    "rmmod": "kernel module",
    # accounts, authentication, privileges
    "useradd": "account management",
    "adduser": "account management",
    "usermod": "account management",
    "userdel": "account management",
    "deluser": "account management",
    "groupadd": "group management",
    "groupmod": "group management",
    "groupdel": "group management",
    "passwd": "credential management",
    "chpasswd": "credential management",
    "chage": "credential management",
    "visudo": "privilege configuration",
    "sudoers": "privilege configuration",
    "su": "privilege change",
    "runas": "privilege change",
    "setfacl": "access control",
    "getfacl": "access control",
    "icacls": "access control",
    "cacls": "access control",
    "takeown": "ownership change",
    "chown": "ownership change",
    "chgrp": "ownership change",
    "sssd": "identity service",
    "realm": "identity service",
    "pam-auth-update": "authentication configuration",
    "ssh-keygen": "key material",
    "ssh-copy-id": "key material",
    "gpg": "key material",
    "openssl": "key and certificate material",
    "certutil": "certificate material",
    "keytool": "key material",
    # scheduling and services
    "crontab": "scheduled tasks",
    "cron": "scheduled tasks",
    "at": "scheduled tasks",
    "systemd-run": "scheduled tasks",
    "schtasks": "scheduled tasks",
    "launchctl": "service management",
    "systemctl": "service management",
    "journalctl": "log access",
    "service": "service management",
    "update-rc.d": "service management",
    "initctl": "service management",
    "supervisorctl": "service management",
    "pm2": "process manager",
    # disks, filesystems, and their destruction
    "mkfs": "filesystem creation",
    "mkfs.ext4": "filesystem creation",
    "mkfs.xfs": "filesystem creation",
    "mkswap": "swap creation",
    "sfdisk": "partition table",
    "parted": "partition table",
    "gdisk": "partition table",
    "diskpart": "partition table",
    "mount": "filesystem mounting",
    "umount": "filesystem unmounting",
    "swapoff": "swap control",
    "swapon": "swap control",
    "mdadm": "RAID configuration",
    "lvm": "volume management",
    "pvcreate": "volume management",
    "vgcreate": "volume management",
    "lvcreate": "volume management",
    "btrfs": "filesystem management",
    "zfs": "filesystem management",
    "zpool": "filesystem management",
    "fsck": "filesystem repair",
    "e2fsck": "filesystem repair",
    "xfs_repair": "filesystem repair",
    "chkdsk": "filesystem repair",
    "defrag": "filesystem maintenance",
    "tar": "archive extraction",
    "unzip": "archive extraction",
    "7z": "archive extraction",
    "expand": "archive extraction",
    "shred": "irreversible deletion",
    "wipe": "irreversible deletion",
    "srm": "irreversible deletion",
    "truncate": "in-place file truncation",
    "fallocate": "space allocation",
    "attrib": "file attributes",
    "chattr": "file attributes",
    "lsattr": "file attributes",
    # remote access, tunnelling, and transfer
    "ssh": "remote shell",
    "scp": "remote transfer",
    "sftp": "remote transfer",
    "telnet": "remote shell",
    # `nc`/`netcat`/`ncat`/`socat` and `rsync` are deliberately absent: this package already models
    # them (network sinks and transfers), and a name with a behaviour model is judged by that
    # model — listing it here would be dead weight that misleads the next reader of the list.
    "wireshark": "packet capture",
    "tshark": "packet capture",
    "tcpdump": "packet capture",
    "psexec": "remote execution",
    "winrs": "remote execution",
    "wmic": "remote execution",
    "curl": "network transfer",
    "wget": "network transfer",
    # processes, boot, and hardware
    "kill": "signal delivery",
    "killall": "signal delivery",
    "pkill": "signal delivery",
    "renice": "process priority",
    "nice": "process priority",
    "ulimit": "resource limits",
    "systemd-nspawn": "container runtime",
    "reboot": "machine power state",
    "shutdown": "machine power state",
    "halt": "machine power state",
    "poweroff": "machine power state",
    "bcdedit": "boot configuration",
    "bootctl": "boot configuration",
    "grub-install": "boot configuration",
    "update-grub": "boot configuration",
    "fwupd": "firmware",
    "dmidecode": "hardware inventory",
    "smartctl": "disk health",
    # virtualisation, containers, orchestration, cloud
    "docker": "container runtime",
    "podman": "container runtime",
    "nerdctl": "container runtime",
    "kubectl": "orchestration",
    "helm": "orchestration",
    "kubeadm": "orchestration",
    "minikube": "orchestration",
    "kind": "orchestration",
    "vagrant": "virtual machine",
    "virsh": "virtual machine",
    "qemu-img": "virtual machine",
    "VBoxManage": "virtual machine",
    "aws": "cloud control plane",
    "gcloud": "cloud control plane",
    "az": "cloud control plane",
    "terraform": "infrastructure as code",
    "tofu": "infrastructure as code",
    "pulumi": "infrastructure as code",
    "ansible": "configuration management",
    "ansible-playbook": "configuration management",
    "puppet": "configuration management",
    "chef-client": "configuration management",
    "salt-call": "configuration management",
    "cfengine": "configuration management",
    # version control, beyond the modelled git subset
    "hg": "version control",
    "svn": "version control",
    "bzr": "version control",
    "perforce": "version control",
    "p4": "version control",
    # logging and audit
    "wevtutil": "event log",
    "auditctl": "audit configuration",
    "ausearch": "audit records",
    "logrotate": "log rotation",
    "rsyslogd": "logging service",
    # databases, beyond the modelled SQL clients
    "mysqldump": "database dump",
    "pg_dump": "database dump",
    "pg_restore": "database restore",
    "mongodump": "database dump",
    "mongorestore": "database restore",
    "redis-cli": "data store",
    "influx": "time-series store",
    "sqlite3": "database file",
    "sqlcmd": "database client",
    "sqlplus": "database client",
    # misc that can erase or expose
    "history": "shell history",
    "xargs": "command pipelining",
    "find": "filesystem search with actions",
    "eval": "dynamic evaluation",
    "env": "environment manipulation",
    "export": "environment manipulation",
    "set": "option manipulation",
    "alias": "shell indirection",
    "source": "shell inclusion",
}


def category_for(name: str) -> str | None:
    """The English category for a tool name, or None when it is not on the list.

    Lookup is exact: this is fed the name the parser found in COMMAND POSITION, so there is no
    substring matching and `udfw` or `ufw-helper` do not match `ufw`.
    """
    return KNOWN_TOOLS.get(name)


def fallback_category(name: str, configured, *, windows=False) -> str | None:
    """Recognize an unmodeled application by its command-position name.

    Behavior models always take precedence, even when this dialect cannot bind
    an invocation. Descriptor probing is pure and performs no host lookup.
    """
    from .shared.commands import describe
    from .shared.builtins import command_registry
    from .models import Fact
    from .pwsh.semantics import PS_OPTIONS, PS_ALIASES
    from .admin.windows import ADMIN_COMMANDS
    from .cmd.semantics import CMD_MODELED_COMMANDS
    normalized = name.casefold().removesuffix('.exe') if windows else name
    category = next((category for tool, category in configured.items()
                     if tool.casefold().removesuffix('.exe') == normalized), None) if windows else configured.get(normalized)
    if category is None:
        return None
    if any(command_registry().supports(normalized, shell) for shell in ("bash", "powershell", "cmd")):
        return None
    if normalized in PS_OPTIONS or normalized in PS_ALIASES or normalized in ADMIN_COMMANDS or normalized in CMD_MODELED_COMMANDS:
        return None
    if normalized in {"read", "break", "continue", "export", "readonly", "declare", "typeset", "local", "unset", "set"}:
        return None
    described = describe(normalized, (), None)
    if described != [Fact('unresolved', 'unknown-command', payload=normalized, command_name=normalized)]:
        return None
    return category
