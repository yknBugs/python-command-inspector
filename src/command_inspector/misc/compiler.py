"""Shared bounded GCC/Clang driver facts; never compile or inspect C/C++ code."""
import posixpath
import re

from ..models import Fact, Value


COMPILERS = frozenset({"gcc", "g++", "cc", "c++", "clang", "clang++"})
VALUED = {
    "-o", "--output", "-I", "-L", "-l", "-D", "-U", "-x", "--language", "-include", "-imacros",
    "-isystem", "-iquote", "-idirafter", "-isysroot", "--sysroot", "-target", "--target",
    "-arch", "-B", "-MF", "-MT", "-MQ", "-MJ", "-fplugin", "-specs", "--config",
    "-Xclang", "-Xpreprocessor", "-Xassembler", "-Xlinker", "-wrapper",
}
FLAGS = {
    "-c", "--compile", "-S", "--assemble", "-E", "--preprocess", "-fsyntax-only",
    "-shared", "-static", "-pie", "-no-pie", "-pthread", "-pipe", "-v", "-w", "-ansi", "-pedantic",
    "-pedantic-errors", "-fPIC", "-fpic", "-fPIE", "-fpie", "-fno-pic", "-fno-pie", "-fno-PIE",
    "-fno-omit-frame-pointer", "-fomit-frame-pointer", "-fno-exceptions", "-fexceptions",
    "-fno-rtti", "-frtti", "-ffreestanding", "-fno-builtin", "-fvisibility=hidden",
    "-fvisibility=default", "-m32", "-m64", "-nostdinc", "-nostdinc++", "-nostdlib", "-nodefaultlibs",
    "-nostartfiles", "-emit-llvm", "-M", "-MM", "-MD", "-MMD", "-MP", "-MG",
    "--help", "--version", "-dumpversion", "-dumpfullversion", "-dumpmachine", "-print-search-dirs",
    "-print-libgcc-file-name", "-###",
}
PURE_QUERY = {"--help", "--version", "-dumpversion", "-dumpfullversion", "-dumpmachine", "-print-search-dirs", "-print-libgcc-file-name", "-###"}
SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".C", ".m", ".mm", ".i", ".ii", ".s", ".S"}


def model(call):
    facts, inputs, flags, bound, unknown = [], [], set(), {}, []
    index, ended, hidden = 0, False, False
    while index < len(call.args):
        value = call.args[index]
        text = value.text
        index += 1
        if ended:
            inputs.append(value)
            continue
        if text == "--":
            ended = True
            continue
        if text is None or text == "-" or not text.startswith("-"):
            if text is None:
                hidden = True
            if text and text.startswith("@"):
                facts.append(Fact("read", "list", values=(Value(text[1:], variables=value.variables),)))
                facts.append(Fact("unresolved", "unresolved-value", payload="Compiler arguments depend on an uninspected response file"))
                hidden = True
            else:
                inputs.append(value)
            continue
        key, sep, attached = text.partition("=")
        if key not in VALUED:
            # GCC/Clang attach values to these short options; longer options
            # such as -include must match exactly before considering a prefix.
            prefix = next((k for k in ("-MF", "-MT", "-MQ", "-MJ", "-o", "-I", "-L", "-l", "-D", "-U", "-x", "-B")
                           if text.startswith(k) and len(text) > len(k)), None)
            if prefix:
                key, attached, sep = prefix, text[len(prefix):], "attached"
        if key in VALUED:
            if sep:
                argument = Value(attached, variables=value.variables)
            elif index < len(call.args):
                argument = call.args[index]
                index += 1
            else:
                unknown.append(key)
                argument = Value(None, "missing_option_value")
            flags.add(key)
            bound[key] = argument
            if key in {"-B", "-fplugin", "-specs", "--config", "-wrapper", "-Xclang", "-Xpreprocessor", "-Xassembler", "-Xlinker"}:
                hidden = True
                facts.append(Fact("unresolved", "execution-content-unavailable", values=(argument,),
                                  payload="Compiler plugin, configuration, tool search path or forwarded arguments are not inspected"))
            if key in {"-include", "-imacros", "-fplugin", "-specs", "--config"}:
                facts.append(Fact("read", "list", values=(argument,)))
        elif text.startswith(("-Wl,", "-Wa,", "-Wp,")):
            hidden = True
            facts.append(Fact("unresolved", "execution-content-unavailable", values=(value,),
                              payload="Compiler forwards uninspected arguments to another executable"))
        elif text in FLAGS or re.fullmatch(r"-(?:O(?:[0-3gsz]|fast)?|g(?:[0-3]|gdb[0-3]?|line-tables-only)?|W(?:all|extra|error(?:=[\w-]+)?|pedantic|no-[\w-]+)|std=[\w+.-]+|stdlib=[\w+.-]+|march=[\w+.-]+|mcpu=[\w+.-]+|mtune=[\w+.-]+|f(?:no-)?sanitize=[\w,-]+)", text):
            flags.add(text)
        else:
            unknown.append(key)
            hidden = True
    facts.extend(Fact("unresolved", "unknown-option", payload=option) for option in unknown)
    if flags & PURE_QUERY:
        return facts
    # Ordinary compilation consumes code; preprocessing can expose source text.
    source_values = tuple(v for v in inputs if v.text != "-")
    if source_values:
        exposed = bool(flags & {"-E", "--preprocess"}) and not flags & {"-M", "-MM", "-o", "--output"}
        facts.append(Fact("read", "ingest" if exposed else "list", values=source_values,
                          flags=frozenset({"selection_uncertain"}) if exposed else frozenset()))
    outputs = [bound[key] for key in ("-o", "--output") if key in bound]
    no_primary = bool(flags & {"-fsyntax-only", "-E", "--preprocess", "-M", "-MM"})
    if "-fsyntax-only" in flags:
        outputs = []
    if not outputs and inputs and not no_primary:
        if any(v.text is None for v in inputs):
            outputs.append(Value(None, "unresolved_compiler_output", tuple(sorted({n for v in inputs if v.text is None for n in v.variables}))))
        elif flags & {"-c", "--compile", "-S", "--assemble"}:
            suffix = ".s" if flags & {"-S", "--assemble"} else ".o"
            language = bound.get("-x", bound.get("--language", Value("none"))).text
            for value in inputs:
                if value.pattern or language is None or language.endswith("header"):
                    hidden = True
                    outputs.append(Value(None, "unresolved_compiler_output", value.variables))
                elif value.text and value.text != "-" and (posixpath.splitext(value.text)[1] in SOURCE_SUFFIXES or language != "none"):
                    filename = posixpath.splitext(posixpath.basename(value.text))[0] + suffix
                    outputs.append(Value(filename, variables=value.variables))
                elif value.text is None or value.text == "-":
                    outputs.append(Value(None, "unresolved_compiler_output"))
                elif posixpath.splitext(value.text)[1] not in {".o", ".a", ".so"}:
                    hidden = True
        elif any(value.text and posixpath.splitext(value.text)[1] in {".h", ".hpp", ".hh"} for value in inputs):
            hidden = True
        else:
            outputs.append(Value("a.out"))
    if flags & {"-M", "-MM", "-MD", "-MMD"} and "-MF" in bound:
        outputs.append(bound["-MF"])
    if "-MJ" in bound:
        outputs.append(bound["-MJ"])
    if flags & {"-MD", "-MMD"} and "-MF" not in bound:
        facts.append(Fact("unresolved", "unresolved-value", payload="Implicit compiler dependency output paths are not modeled"))
        hidden = True
    for value in outputs:
        if value.text != "-":
            facts.append(Fact("write", "overwrite", values=(value,), flags=frozenset({"runtime_output"})))
    if hidden:
        # Response files, plugins, forwarded/unknown options and implicit outputs
        # can mutate targets beyond the primary output. Do not reuse stale data.
        facts.append(Fact("invalidate", "compiler-effects-unresolved", values=(Value(None),)))
        facts.append(Fact("unresolved", "unresolved-value", payload="Compiler effects beyond explicit outputs cannot be bounded"))
    return facts
