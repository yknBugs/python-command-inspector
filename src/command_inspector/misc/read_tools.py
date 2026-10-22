"""Bounded common text/calculation tools, including their effectful forms.

No transformation is executed. Text-producing reads remain conservative;
hashes, date queries and brief/status-only comparisons consume file content
without exposing it as command output, so they request metadata only.
"""
import re

from ..models import Fact, Value
from ..shared.options import CommandSpec, parse_options


SPECS = {
    "diff": CommandSpec("abBdeiNpqrsStTuwyZ", (
        "--text", "--ignore-space-change", "--ignore-all-space", "--ignore-blank-lines",
        "--ignore-case", "--minimal", "--new-file", "--brief", "--recursive",
        "--report-identical-files", "--initial-tab", "--expand-tabs", "--side-by-side",
        "--suppress-common-lines", "--left-column", "--strip-trailing-cr", "--help", "--version",
    ), ("-C", "--context", "-U", "--unified", "-I", "--ignore-matching-lines",
        "-L", "--label", "-F", "--show-function-line", "-W", "--width", "-x", "--exclude",
        "-X", "--exclude-from", "-S", "--starting-file", "--from-file", "--to-file",
        "--line-format", "--old-line-format", "--new-line-format", "--unchanged-line-format",
        "--old-group-format", "--new-group-format", "--changed-group-format", "--unchanged-group-format")),
    "sort": CommandSpec("bCcdfghimMnRrsuVz", (
        "--ignore-leading-blanks", "--dictionary-order", "--ignore-case", "--general-numeric-sort",
        "--human-numeric-sort", "--ignore-nonprinting", "--month-sort", "--numeric-sort",
        "--random-sort", "--reverse", "--stable", "--unique", "--version-sort",
        "--merge", "--zero-terminated", "--debug", "--check", "--help", "--version",
    ), ("-k", "--key", "-t", "--field-separator", "-o", "--output", "-T", "--temporary-directory",
        "-S", "--buffer-size", "--parallel", "--batch-size", "--sort", "--random-source",
        "--files0-from", "--compress-program")),
    "uniq": CommandSpec("cdiuzD", (
        "--count", "--repeated", "--ignore-case", "--unique", "--zero-terminated",
        "--all-repeated", "--group", "--help", "--version",
    ), ("-f", "--skip-fields", "-s", "--skip-chars", "-w", "--check-chars")),
    "date": CommandSpec("uR", (
        "--utc", "--universal", "--rfc-email", "--debug", "--iso-8601", "--help", "--version",
    ), ("-d", "--date", "-f", "--file", "-r", "--reference", "-s", "--set", "--rfc-3339")),
    "sha256sum": CommandSpec("bctwz", (
        "--binary", "--check", "--text", "--warn", "--zero", "--tag", "--ignore-missing",
        "--quiet", "--status", "--strict", "--help", "--version",
    )),
}


def _normalize(name, args):
    normalized = []
    ended = False
    for value in args:
        text = value.text or ""
        if ended:
            normalized.append(value)
            continue
        if text == "--":
            ended = True
        # Optional arguments are accepted only in their attached forms. Never
        # swallow the next positional file as a separator/format/check mode.
        optional = (
            name == "sort" and re.fullmatch(r"--check=(?:diagnose-first|quiet|silent)", text)
            or name == "uniq" and re.fullmatch(r"--all-repeated=(?:none|prepend|separate)", text)
            or name == "uniq" and re.fullmatch(r"--group=(?:separate|prepend|append|both)", text)
            or name == "date" and re.fullmatch(r"--iso-8601=(?:date|hours|minutes|seconds|ns)", text)
        )
        if optional:
            normalized_text = "-C" if name == "sort" and text in {"--check=quiet", "--check=silent"} else text.split("=", 1)[0]
            value = Value(normalized_text, variables=value.variables)
        elif name == "date" and re.fullmatch(r"-I(?:date|hours|minutes|seconds|ns)?", text):
            value = Value("--iso-8601", variables=value.variables)
        elif name == "diff" and text in {"-c", "-u", "--context", "--unified"}:
            # Short/long context switches have optional counts, attached only
            # for long forms. -U/-C always take a count.
            value = Value("-u", variables=value.variables)
        normalized.append(value)
    return tuple(normalized)


def model(call):
    operands, flags, bound, unknown = parse_options(_normalize(call.name, call.args), SPECS[call.name])
    facts = [Fact("unresolved", "unknown-option", payload=o) for o in unknown]
    if flags & {"--help", "--version"}:
        return facts

    def read(values, *, exposed=False, recursive=False):
        values = tuple(v for v in values if v.text != "-")
        if values:
            read_flags = {"selection_uncertain"} if exposed else set()
            if recursive and exposed:
                read_flags.add("search_recursive")
            facts.append(Fact("read", "ingest" if exposed else "list", values=values, flags=frozenset(read_flags)))

    def write(value):
        if value.text != "-":
            facts.append(Fact("write", "overwrite", values=(value,), flags=frozenset({"runtime_output"})))

    inputs = (Value(None, "unknown_option_operand_binding"),) if unknown else operands
    if call.name == "diff":
        source = bound.get("--from-file", bound.get("--to-file"))
        if source is not None:
            inputs = (source, *inputs)
        read(inputs, exposed=not bool(flags & {"-q", "--brief"}), recursive=bool(flags & {"-r", "--recursive"}))
        read([v for k, v in bound.occurrences if k in {"-X", "--exclude-from"}])
    elif call.name == "sort":
        # Diagnostic checking (-c/--check) can expose the first disordered line.
        read(inputs, exposed="-C" not in flags and not unknown)
        for key in ("-o", "--output"):
            if key in bound:
                write(bound[key])
        read([v for k, v in bound.occurrences if k in {"--random-source", "--files0-from"}])
        if "--files0-from" in bound:
            facts.append(Fact("unresolved", "unresolved-value", payload="Sort input paths depend on an uninspected NUL-separated file list"))
        if "--compress-program" in bound:
            program = bound["--compress-program"]
            if program.text and not any(c.isspace() for c in program.text):
                facts.append(Fact("invoke", program.text))
            else:
                facts.append(Fact("unresolved", "execution-content-unavailable", values=(program,), payload="Sort compression program is unresolved"))
    elif call.name == "uniq":
        if unknown:
            read(inputs)
            facts.append(Fact("write", "overwrite", values=(Value(None, "unknown_option_operand_binding"),)))
        else:
            read(inputs[:1], exposed=True)
            if len(inputs) > 1:
                write(inputs[1])
            if len(inputs) > 2:
                facts.append(Fact("unresolved", "unresolved-value", payload="Uniq has more than two file operands"))
    elif call.name == "sha256sum":
        read(inputs)
        if flags & {"-c", "--check"}:
            facts.append(Fact("unresolved", "unresolved-value", payload="Checksum target paths depend on an uninspected checksum manifest"))
    else:
        read([v for k, v in bound.occurrences if k in {"-r", "--reference", "-f", "--file"}])
        setters = [v for k, v in bound.occurrences if k in {"-s", "--set"}]
        # The traditional numeric operand sets the clock too; +FORMAT is a
        # display request, while an unknown operand could be a setting.
        setters.extend(v for v in inputs if v.text is None or re.fullmatch(r"\d{8}(?:\d{2}){0,2}(?:\.\d{2})?", v.text or ""))
        if any(v.text and not v.text.startswith("+") and not re.fullmatch(r"\d{8}(?:\d{2}){0,2}(?:\.\d{2})?", v.text) for v in inputs):
            facts.append(Fact("unresolved", "unresolved-value", payload="Date positional operand is outside the supported format/set-time forms"))
        if setters:
            title = "May set the system date/time from an unresolved operand" if any(v.text is None for v in setters) and not bound.keys() & {"-s", "--set"} else "Sets the system date/time"
            facts.append(Fact("system", "system-settings-change", values=tuple(setters), payload=title))
    return facts
