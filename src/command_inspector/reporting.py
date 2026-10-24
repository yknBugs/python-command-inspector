"""Explicit redaction, same-rule grouping, and derived report aggregation."""
from dataclasses import replace
import re
from .models import AnalysisReport, Finding

SECRET_PATTERNS = (
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"sk-[A-Za-z0-9_-]{14,}"),
    re.compile(r"(?i)\b(?:password|passwd|api[_-]?key|access[_-]?token|secret)\s*[:=]\s*['\"]?([^\s'\";,]+)"),
    re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9+/=_-]{8,}"),
)
INJECTION = re.compile(r"(?i)(ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions|"
                       r"(?:system|developer)\s+(?:prompt|message)\s*[:=]|"
                       r"(?:assistant|agent)[,:].{0,40}(?:override|disregard|ignore))")


def contains_secret(text: str) -> bool:
    return any(pattern.search(text) for pattern in SECRET_PATTERNS) or "-----BEGIN" in text and "PRIVATE KEY-----" in text


def redact(value, *, literals=()):
    if isinstance(value, str):
        for literal in literals:
            # Long tokens can be embedded in URLs/paths. For short passwords,
            # preserve unrelated words while hiding exact values/components.
            if len(literal) >= 8:
                value = value.replace(literal, "[REDACTED]")
            else:
                value = re.sub(r'(?<!\w)' + re.escape(literal) + r'(?!\w)', '[REDACTED]', value)
        for pattern in SECRET_PATTERNS:
            value = pattern.sub("[REDACTED]", value)
        value = re.sub(r"-----BEGIN[^\n]*PRIVATE KEY-----[\s\S]*?(?:-----END[^\n]*PRIVATE KEY-----|$)", "[REDACTED PRIVATE KEY]", value)
        # URL userinfo and command-auth fields must not survive normal reports.
        value = re.sub(r"(https?://)[^/@\s]+:[^/@\s]+@", r"\1[REDACTED]@", value)
        return value
    if isinstance(value, dict):
        return {k: redact(v, literals=literals) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v, literals=literals) for v in value]
    return value


def aggregate(findings: list[Finding], disabled: frozenset[str], *, sensitive_literals=()) -> AnalysisReport:
    # Candidate provenance can recur on earlier environment findings. Once a
    # name is known to carry authentication data, hide its candidate list in
    # every finding of this report, including when the auth rule is disabled.
    sensitive = set().union(*(f.sensitive_variables for f in findings))
    findings = [replace(f, data={**f.data, "possible_values": {
        name: ["[REDACTED]"] if name in sensitive else values
        for name, values in f.data["possible_values"].items()}})
        if "possible_values" in f.data else f for f in findings]
    grouped: dict[tuple, Finding] = {}
    for finding in findings:
        if finding.rule in disabled:
            continue
        interpreter_context = "written_content" if finding.data.get("context") == "written_content" else "execution"
        # System titles/details can carry actions and guards beyond the common
        # data fields. Retain distinct effects while preserving coverage grouping.
        key = (finding.rule, interpreter_context) if finding.rule == "uses-interpreter" else (finding.rule, repr(finding.data))
        if finding.type == "system":
            key += (finding.title, finding.detail)
        if key in grouped:
            previous = grouped[key]
            if finding.rule == "uses-interpreter":
                names = sorted(set(previous.data["interpreters"] + finding.data["interpreters"]))
                sources = list(dict.fromkeys(previous.data.get("sources", [previous.data.get("source", "command")]) + [finding.data.get("source", "command")]))
                prefix = "Written script contains: " if interpreter_context == "written_content" else ""
                data = {**previous.data, "interpreters": names, "sources": sources}
                if "variables" in previous.data or "variables" in finding.data:
                    data["variables"] = sorted(set(previous.data.get("variables", ())) | set(finding.data.get("variables", ())))
                if previous.data.get("possible") or finding.data.get("possible"):
                    data["possible"] = True
                if "possible_values" in previous.data or "possible_values" in finding.data:
                    possibilities = {}
                    for item in (previous.data, finding.data):
                        for name, values in item.get("possible_values", {}).items():
                            possibilities[name] = list(dict.fromkeys(possibilities.get(name, []) + list(values)))
                    data["possible_values"] = possibilities
                grouped[key] = replace(previous, title=prefix + "Invokes " + ", ".join(names),
                                       data=data)
            elif finding.level > previous.level:
                grouped[key] = finding
        else:
            grouped[key] = finding
    literals = sorted(set(sensitive_literals), key=lambda text: (-len(text), text))
    safe = [replace(f, title=redact(f.title, literals=literals), detail=redact(f.detail, literals=literals),
                    data=redact(f.data, literals=literals), evidence=tuple(redact(f.evidence, literals=literals)))
            for f in grouped.values()]
    return AnalysisReport(tuple(sorted(safe, key=lambda f: -f.level)))
