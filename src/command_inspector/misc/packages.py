"""Static command facts; no execution or filesystem access."""
import re
from dataclasses import replace
from ..models import Fact, Value


def describe_packages(name, args, cwd):
    from ..shared.commands import resolve_path
    words = [v.text for v in args]
    facts = []
    def effect(operation, payload=None):
        facts.append(Fact("system", operation, payload=payload))
    def unknown():
        facts.append(Fact("unresolved", "unknown-command", payload="Unsupported " + name + " operation"))
    if words and words[0] in {"--help", "-h", "--version", "-V"}:
        return facts
    # Explicit subcommand dispatch: recognising an executable does not make
    # future/unknown subcommands silently safe.
    operation = next((w for w in words if w and not w.startswith("-")), None)
    if name in {"pacman", "paru"}:
        if any(w in {"--help", "-h", "--version", "-V"} for w in words):
            return facts
        long_flags = {'--query': 'Q', '--sync': 'S', '--remove': 'R', '--upgrade': 'U', '--search': 's', '--info': 'i', '--list': 'l', '--refresh': 'y', '--sysupgrade': 'u', '--clean': 'c'}
        flags = "".join(w[1:] for w in words if w and w.startswith("-") and not w.startswith("--")) + ''.join(long_flags.get(w, '') for w in words)
        if '--print' in words:
            return facts
        if "R" in flags or "S" in flags and "c" in flags:
            effect("package-change", "Removes packages or cached packages")
        elif "U" in flags or "S" in flags and (not set(flags) & {"s", "i", "l"} or "y" in flags or "u" in flags):
            effect("package-install")
        elif "Q" not in flags and not ("S" in flags and set(flags) & {"s", "i", "l"}):
            unknown()
    elif name == "conda":
        if operation in {"list", "info", "search", "help"} or operation == "env" and "list" in words:
            pass
        elif operation == "config" and any(w in {"--show", "--show-sources", "--describe", "--get", "--validate"} for w in words) and not set(words) & {"--set", "--add", "--append", "--prepend", "--remove", "--remove-key", "--write-default"}:
            pass
        elif operation == "run":
            from ..shared.options import CommandSpec, take_wrapper_options, parse_options
            index = words.index("run") + 1
            spec = CommandSpec("v", ("--no-capture-output", "--live-stream", "--dev", '--help'), ("-n", "--name", "-p", "--prefix", "--cwd"))
            errors, consumed = take_wrapper_options(args[index:], spec)
            if errors or consumed is None:
                facts.extend(Fact('unresolved', 'unknown-option', payload=error) for error in errors)
                facts.append(Fact("unresolved", "execution-content-unavailable", payload="Conda run command binding is unresolved"))
            else:
                _, run_flags, run_bound, _ = parse_options(args[index:index+consumed], spec)
                if '--help' in run_flags:
                    return facts
                tail = args[index + consumed:]
                directory = run_bound.get('--cwd')
                facts.append(Fact("invoke", tail[0].text, values=tail[1:], flags=frozenset({'override_cwd'}) if directory is not None else frozenset(), payload=directory.text if directory is not None else None) if tail and tail[0].text else Fact("unresolved", "execution-content-unavailable"))
        elif operation in {"install", "create", "update", "upgrade"} or operation == "env" and set(words) & {"create", "update"}:
            effect("package-install")
        elif operation in {"remove", "uninstall", "clean", "config", "activate", "deactivate"} or operation == "env" and "remove" in words:
            effect("package-change", "Changes packages, environments or package configuration")
        else:
            unknown()
    else:
        if words and words[0] in {"--info", "--list-sdks", "--list-runtimes"} or operation in {"build", "test", "help", "list", "sln"}:
            if operation == "sln" and not any(w in {"list", "--help"} for w in words):
                effect("package-change", "Changes solution membership")
        elif operation in {"restore", "add", "remove"} or operation == "tool" and set(words) & {"install", "update", "uninstall", "restore"}:
            effect("package-change", "Changes .NET packages or tools")
        elif operation == "tool" and "list" in words or operation == "nuget" and "list" in words:
            pass
        elif operation in {"run", "exec"} or operation == "tool" and "run" in words:
            facts.append(Fact("unresolved", "execution-content-unavailable", payload=".NET executable content is unavailable"))
        elif operation == "nuget" and "push" in words:
            facts.append(Fact("network", "publish", flags=frozenset({"local_file_payload"})))
        elif operation == 'nuget' and set(words) & {'add', 'remove', 'update', 'enable', 'disable', 'delete'} or operation == 'workload' and set(words) & {'install', 'uninstall', 'update', 'restore', 'repair', 'clean'}:
            effect('package-change', 'Changes .NET package sources, packages or workloads')
        elif operation == 'workload' and set(words) & {'list', 'search'}:
            pass
        elif operation in {'publish', 'pack'}:
            output = next((args[i+1] for i, w in enumerate(words[:-1]) if w in {'-o', '--output'}), None)
            if output is None:
                output = next((Value(w.split('=', 1)[1]) for w in words if w and w.startswith('--output=')), Value(None, 'generated_files'))
            resolved = resolve_path(output, cwd)
            facts.append(Fact('write', 'create_directory', (resolved,) if resolved is not None else (), values=(output,)))
        elif operation == "new":
            facts.append(Fact("write", "transform", values=(Value(None, "generated_files"),)))
        elif operation == "format":
            if '--verify-no-changes' not in words:
                facts.append(Fact("write", "transform", values=(Value(None, "formatted_files"),)))
        else:
            unknown()
    if name == 'conda' and operation == 'run':
        return facts  # subsequent arguments belong to the wrapped command
    accepted = {
        'conda': {'--envs', '--all', '--json', '--offline', '--override-channels', '--show', '--show-sources', '--describe', '--get', '--validate', '--set', '--add', '--append', '--prepend', '--remove', '--remove-key', '--write-default', '--file', '--name', '--prefix', '--channel', '--yes', '--quiet', '--verbose', '--dry-run', '--force', '--force-reinstall', '--no-deps', '--update-deps', '--freeze-installed', '--revision', '--solver', '--repodata-fn', '--clobber', '--insecure', '--copy', '--download-only', '--explicit', '--export', '--revisions', '--packages', '--tarballs', '--index-cache', '--tempfiles', '--logfiles', '--force-pkgs-dirs', '--system', '--env'},
        'dotnet': {'--info', '--list-sdks', '--list-runtimes', '--configuration', '--framework', '--runtime', '--output', '--verbosity', '--no-restore', '--no-build', '--force', '--interactive', '--no-logo', '--nologo', '--source', '--version', '--global', '--local', '--tool-path', '--tool-manifest', '--add-source', '--ignore-failed-sources', '--prerelease', '--api-key', '--symbol-api-key', '--symbol-source', '--skip-duplicate', '--disable-buffering', '--timeout', '--serviceable', '--self-contained', '--no-self-contained', '--use-current-runtime', '--use-lock-file', '--locked-mode', '--configfile', '--name', '--include-source', '--include-symbols', '--filter', '--logger', '--results-directory', '--collect', '--settings', '--arch', '--os', '--verify-no-changes'},
        'pacman': {'--query', '--sync', '--remove', '--upgrade', '--database', '--files', '--deptest', '--refresh', '--sysupgrade', '--search', '--info', '--list', '--groups', '--check', '--owns', '--clean', '--recursive', '--nosave', '--unneeded', '--noconfirm', '--needed', '--downloadonly', '--print', '--print-format', '--quiet', '--verbose', '--dbpath', '--root', '--sysroot', '--config', '--cachedir', '--gpgdir', '--logfile', '--overwrite', '--ignore', '--ignoregroup', '--color', '--noprogressbar', '--noconfirm', '--nodeps', '--assume-installed', '--asdeps', '--asexplicit'},
    }
    accepted['paru'] = accepted['pacman'] | {'--devel', '--skipreview', '--norebuild', '--rebuild', '--sudoloop', '--aur', '--repo'}
    shorts = {'conda': 'npyqvcfk', 'dotnet': 'cfrovnsa', 'pacman': 'QSRUDFTVsyuilqcgkpobdnrvh', 'paru': 'QSRUDFTVsyuilqcgkpobdnrvha'}
    for word in words:
        if word == '--':
            break
        if not word or not word.startswith('-'):
            continue
        key = word.partition('=')[0]
        if key in {'--help', '-h', '--version', '-V'}:
            continue
        known = key in accepted[name] or not word.startswith('--') and all(c in shorts[name] for c in word[1:])
        if name == 'dotnet' and re.match(r'^-(?:p|property|m|maxcpucount|bl|binarylogger|t|target|verbosity|v)[:=]', word, re.I):
            known = True
        if not known:
            facts.append(Fact('unresolved', 'unknown-option', payload=key))
    return facts

