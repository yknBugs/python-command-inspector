# Command Inspector

**English** | [简体中文](README.zh-CN.md)

**Explainable, read-only pre-execution review for shell commands and small source snippets.**

`command-inspector` takes a command you are *about to run* — plus the working directory,
environment, and shell dialect — and returns a structured list of findings describing what
that text would do. It never runs the command, never evaluates code, and never touches the
network.

The library is aimed at AI coding agents and the approval prompts around them: a reviewer
(human or program) can ask "what is this line going to touch?" before it gets a chance to do
it. It is not a sandbox and not a vulnerability scanner for deployed code — see
[Why this exists](#why-this-exists) for the threat model behind that scope.

```python
>>> from command_inspector import Analyzer
>>> Analyzer().analyze("git push --force origin main", "/work/project", shell="bash")["level"]
'HIGH'
```

---

## Contents

- [Why this exists](#why-this-exists)
- [What it looks at](#what-it-looks-at)
- [Runtime output, provenance and trusted scripts](#runtime-output-provenance-and-trusted-scripts)
- [Install](#install)
- [Quick start](#quick-start)
- [Report format](#report-format)
- [Finding levels and rule families](#finding-levels-and-rule-families)
- [Configuration](#configuration)
- [Local evidence and effort](#local-evidence-and-effort)
- [API reference](#api-reference)
- [Supported frontends](#supported-frontends)
- [Design constraints](#design-constraints)
- [Development](#development)
- [Project layout](#project-layout)
- [Security notes](#security-notes)

## Why this exists

This project was built to review what an AI coding agent is about to do, and to extract the
handful of points in those commands that genuinely deserve a user's attention. In a long
programming session a person's attention is finite: once an agent has run dozens of commands,
reading every one closely is no longer realistic. An external tool can summarize the actions
and reduce review to the few decisions that matter.

The threat model is deliberately narrow:

- **The agent is honest but fallible.** It may hallucinate malformed quoting, the wrong flag,
  or a destructive path and thereby damage the user's system. Malformed syntax that a frontend
  cannot parse is surfaced as a coverage finding rather than assumed benign. The agent does not
  deliberately obfuscate its own commands, evade review, or choose to perform a dangerous
  operation. The analyzer therefore takes commands at face value: `cd` is `cd`, and a shell
  alias or function that quietly redefines a builtin is out of scope. This also means the
  checker is **not** intended for reviewing human-written or adversarial code.
- **Execution is one-shot.** Agent frameworks typically run a command, capture the result, and
  discard the process. There is no long-lived session or database connection to hijack, so the
  persistent-state injection surface that tools like Bandit focus on does not apply here.
  SQL findings in this project are about blast radius (`DROP`, `TRUNCATE`), not SQL injection.
- **Attention is the scarce resource.** Findings are ranked by how much they matter to a human
  reviewer, not by abstract severity.

Two hazards remain in scope without weakening that assumption: the agent may ingest adversarial
text from a file or dependency (prompt injection), and it may reproduce an encoded command it
did not author. Both are reported as abnormalities rather than treated as deliberate evasion.

This is the main difference from tools such as Bandit: Bandit audits a codebase for latent
vulnerabilities before deployment; `command-inspector` audits the *next action* for operational
consequences, under the assumption that its author is not an attacker.

Non-goals: sandboxing, malware analysis, exploit detection, and reviewing code that will be
deployed to a hostile environment.

## What it looks at

| Area | Examples |
| --- | --- |
| Destructive filesystem operations | `rm -rf /`, `Remove-Item -Recurse -Force C:\`, `shutil.rmtree`, `rd /s /q` |
| Writes and redirections | `Set-Content`, `> file`, `sed -i`, `os.truncate` |
| Execution and privilege | `sudo`, `su`, `Start-Process -Verb RunAs`, interpreter invocations |
| Network and data movement | `curl`, `wget`, `Invoke-WebRequest`, `scp`, `rsync`, clones |
| Credentials | `--password`, `Authorization:` headers, URL userinfo, secret-shaped literals |
| Git | force-push, history rewrites, sensitive config keys |
| Packages, services, disks, power | installs, `systemctl`, `crontab`, raw devices, shutdown/reboot |
| SQL | DDL/DML severity without executing anything |
| Content inspection | prompt-injection text read from files, obfuscated payloads |
| Runtime output and provenance | timestamps, digests, counters; caller-supplied environment values; redirect destinations |

Three things make the output useful rather than noisy:

1. **Semantics, not string matching.** Commands are parsed with tree-sitter (or Python's
   `ast` / `sqlglot`), and native commands are modelled per-flag. `echo ufw` is not reported as
   a firewall change; `git config --global core.sshCommand ...` is classified by key and scope.
2. **Bounded value tracking.** Variables, `$VAR`, PowerShell interpolation, arrays, and simple
   branches are followed within explicit limits, so `X=/etc; rm -rf "$X"` resolves. Anything the
   model cannot bound becomes an explicit `unresolved-value` notice instead of a guess.
3. **Read-only local evidence.** When enabled, the analyzer stats targets, reads file headers,
   and expands bounded globs to distinguish "deletes `/etc`" from "deletes a missing file".
   Budgets cap every read and traversal, and the result is cached per call.

## Runtime output, provenance and trusted scripts

Runtime output is never executed or evaluated. The analyzer still recognizes a small set of
output shapes that are provably bounded — a formatted timestamp (`date +…`, `Get-Date -Format …`),
a hex digest (`sha256sum … | cut …`), a numeric loop counter or range — and keeps only the
**containing directory** as the target. `… > "/work/doc_$STAMP.txt"` is therefore a write inside
`/work`, not an invented filename; `$MISSING` stays `unresolved-value`, unsafe date formats stay
unbounded, and device namespaces are never downgraded to ordinary files.

Output provenance is tracked separately from the output destination. Printing a caller-supplied
environment value that was not unconditionally replaced locally is `environment-value-output`
(LOW). Credential-shaped content and credential-named variables are still `credentials-exposed`
even when the output is redirected to a file or `/dev/null`/`$null`/`NUL`. The name-based quiet
lists — `quiet_output_variables` (default `PIPESTATUS`) and `quiet_environment_variables`
(default `PYTHONIOENCODING`, `PYTHONUTF8`) — suppress ordinary noise only; they never suppress
credential-shaped content, and `PATH` is not exempt.

`trusted_scripts` is an explicit list of **absolute** script paths. Invoking one is reported as
`trusted-script-invoked` (LOW) without reading its source. Trust skips source inspection only:
writes to the script are still inspected, trust is exact-path rather than basename matching, and
the parent's variables and working directory become unresolved after the call instead of being
assumed unchanged.

## Install

Requires **Python 3.11+**. The core package has no mandatory runtime dependencies; parsers are
optional extras so that each shell only pulls in what it needs.

```bash
# Everything, plus the test toolchain
pip install -e ".[bash,windows,javascript,sql,dev]"
```

Or with Conda:

```bash
conda env create -f environment.yml
conda activate command-inspector
```

Extras:

| Extra | Enables | Dependency |
| --- | --- | --- |
| `bash` | Bash parsing | `tree-sitter-bash` |
| `windows` | PowerShell parsing | `tree-sitter-powershell` |
| `javascript` | JavaScript parsing | `tree-sitter-javascript` |
| `sql` | SQL analysis | `sqlglot` |
| `dev` | Test suite | `pytest`, `jsonschema` |

The CMD and Python frontends are always available and need no extra. A missing parser does not
crash the analyzer: the call reports `analysis-unavailable` and `Analyzer.capabilities()` tells
you which frontends are installed.

## Quick start

### Analyze a command

```python
from command_inspector import Analyzer

analyzer = Analyzer()
report = analyzer.analyze(
    "rm -rf /",
    "/home/me/project",   # absolute cwd in the selected shell's path dialect
    shell="bash",
    env={"HOME": "/home/me"},
)

if report["level"] in {"HIGH", "BLOCK"}:
    print(report["level"], [f["rule"] for f in report["findings"]])
# BLOCK ['delete-protected-root']
```

`workspace_root` defaults to `cwd`. Pass it explicitly when the project root differs from the
directory the command will run in; it is what "inside the workspace" means for read/write
findings.

### Analyze source directly

```python
from command_inspector import Analyzer

analyzer = Analyzer()

analyzer.analyze_python('import shutil\nshutil.rmtree("/etc")\n', "/work")["level"]
# 'BLOCK'

analyzer.analyze_javascript('require("fs").writeFileSync("/etc/passwd", "x")', "/work")
analyzer.analyze_sql("DROP TABLE users", dialect="postgres")["level"]
# 'HIGH'
```

`dialect=None` lets `sqlglot` use its generic dialect; unknown or unsupported SQL degrades to a
`sql-unresolved` coverage notice instead of a false clean result.

### Get JSON

`analyze_json`, `analyze_python_json`, `analyze_javascript_json`, and `analyze_sql_json` return
a JSON string instead of a dict:

```python
wire = analyzer.analyze_json("git push --force origin main", "/work/project", shell="bash")
```

### Handle the "nothing found" case

A clean analysis returns an **empty object**, not an object with empty findings. The schema is
deliberately `oneOf [ {}, report ]`, so existence of `findings` means something was reported:

```python
report = analyzer.analyze("ls", "/work/project", shell="bash")
assert report == {}
```

### Per-call effort

Filesystem inspection can be turned down without changing parsing:

```python
analyzer.analyze(cmd, cwd, shell="bash", effort="None")     # no filesystem access
analyzer.analyze(cmd, cwd, shell="bash", effort="Partial")  # metadata only, no content
```

`"Full"` is the default. Names are case-insensitive.

## Report format

Every non-empty report conforms to the bundled `schemas/report.json` (JSON Schema 2020-12):

```json
{
  "schema_version": "1.0.0",
  "analyzer_version": "1.15.0",
  "rule_catalog_version": "1.15.0",
  "level": "HIGH",
  "num_findings": 1,
  "findings": [
    {
      "rule": "git-history-rewrite",
      "level": "HIGH",
      "type": "git",
      "title": "Rewrites or deletes remote Git refs",
      "detail": "Rewrites or deletes remote Git refs",
      "data": {
        "operation": "git-history-rewrite",
        "source": "command",
        "context": "invoked_now",
        "targets": ["origin"],
        "history_scope": "remote",
        "refspecs": ["main"],
        "options": ["--force"]
      },
      "evidence": []
    }
  ]
}
```

- `level` is the maximum finding level; `findings` are sorted from most to least severe.
- `data` carries rule-specific facts (targets, destinations, options, unresolved names, …).
- `evidence` records what local inspection contributed, including unavailable or truncated
  evidence, so a low-confidence result is visible as such.
- Reports are redacted before serialization: credential-shaped literals, `Bearer`/`Basic`
  values, URL userinfo, and private-key blocks are replaced with `[REDACTED]`.

## Finding levels and rule families

The catalog contains **79 rules across 9 types** (`content`, `coverage`, `environment`,
`execution`, `filesystem`, `git`, `network`, `sql`, `system`). Version 1.13.0 adds
`trusted-script-invoked` and `environment-value-output`, both `LOW`; 1.15.0 adds
`git-commit` (`LOW`) and reports `git commit --amend` as a `MEDIUM` local history rewrite.

| Level | Meaning |
| --- | --- |
| `LOW` | Worth knowing, not necessarily dangerous (e.g., reading a file outside the workspace) |
| `MEDIUM` | Not necessarily dangerous, but it changes critical state and the user should know and consent (e.g., deleting a file outside the workspace) |
| `HIGH` | An operation that almost never appears in a normal programming task (e.g., unmounting a filesystem) |
| `BLOCK` | Obviously dangerous, almost certain to cause destructive consequences (e.g., deleting system files) |

Levels are fixed per rule (a few rules can emit two levels depending on context). They express
review priority, not CVSS-style vulnerability severity. `unknown-command` is the notable two-level
rule: it is `LOW` for a command that is genuinely unknown, and `HIGH` when the command-position
text does not look like a command name (`"print(hello)"`, `"llama cpp"`). The latter usually means
a quote closed early and the rest was parsed as a command; the finding carries
`reason: suspicious_command_name` and a `name_pattern` category. That is a warning about the
command text itself, not just a coverage notice. Rules can be disabled by id through
configuration. The full catalog, including descriptions and the version a rule was introduced
in, is available programmatically:

```python
catalog = analyzer.rule_catalog()
[c["rule"] for c in catalog["rules"]]
```

## Configuration

Configuration is explicit — the analyzer never discovers project files on its own.

```python
from command_inspector import Analyzer, AnalyzerConfig

config = AnalyzerConfig(
    shell="bash",
    protected_directories=("/", "/etc", "/usr", "/srv/data"),
    allowed_write_paths=("/work/build",),
    trusted_scripts=("/work/init.sh",),
    quiet_output_variables=("PIPESTATUS",),
    quiet_environment_variables=("PYTHONIOENCODING", "PYTHONUTF8"),
    disabled_rules=frozenset({"git-push"}),
    local_evidence=True,
    possible_values=16,
    control_flow_steps=256,
)
analyzer = Analyzer(config)
```

The same structure can be loaded from TOML:

```toml
shell = "bash"
local_evidence = true
trusted_scripts = ["/work/init.sh"]
quiet_output_variables = ["PIPESTATUS"]
quiet_environment_variables = ["PYTHONIOENCODING", "PYTHONUTF8"]

[workspace]
additional_paths = ["/opt/tools"]
allowed_write_paths = ["/work/build"]

[protected]
directories = [{ path = "/srv/data" }]

[rules]
"git-push" = { enabled = false }
"unknown-option" = { enabled = false }

[limits]
file_bytes = 524288
total_read_bytes = 4194304
directory_entries = 32768
inline_depth = 3
source_nodes = 65536
wildcard_matches = 1024
possible_values = 16
control_flow_steps = 256
value_bytes = 524288

[tools.known]
"deployctl" = "deployment tool"
```

```python
from command_inspector import Analyzer, load_config

analyzer = Analyzer(load_config("command-inspector.toml"))
```

Notes:

- Unknown top-level fields, unknown rule ids, and non-boolean `enabled` values are rejected with
  `ConfigurationError`.
- `trusted_scripts` entries must be absolute paths; trust is matched against the normalized full
  path, never against a basename. Supplying the list is the only way to opt in — there is no
  project-file discovery.
- `quiet_output_variables` and `quiet_environment_variables` accept shell variable names. They are
  name-based noise suppression, not a way to hide credential-shaped values; the analyzer still
  reports those by content.
- Supplying `[tools.known]` **replaces** the built-in known-tool map; merge with
  `AnalyzerConfig().known_tools` yourself if you only want to add names.
- `protected.directories` currently requires `match = "self"` (the default), i.e. the exact
  directory and its contents, not a glob.
- `AnalyzerConfig.from_mapping()` accepts the same dictionary shape if you already have parsed
  configuration.

## Local evidence and effort

Local evidence is what lets the analyzer say *"this deletes an existing 4 GB directory"* instead
of *"this deletes `$X`"*. It is strictly read-only and happens through a provider:

| Provider | Purpose |
| --- | --- |
| `LocalEvidenceProvider` | Default. `lstat`, bounded file reads, directory listings |
| `DisabledEvidenceProvider` | No filesystem access at all |
| `MemoryEvidenceProvider` | In-memory fixtures; never falls back to disk (useful in tests) |
| `CachedEvidenceProvider` | Wraps another provider with per-call read/entry budgets and a cache |

```python
from command_inspector import Analyzer
from command_inspector.local_evidence import DisabledEvidenceProvider

analyzer = Analyzer(evidence=DisabledEvidenceProvider())
```

Effort levels:

- **Full** — metadata, file content, glob expansion, deletion summaries.
- **Partial** — metadata only; content and byte counts are withheld even if a custom provider
  returned them.
- **None** — no provider calls.

Budgets (`file_bytes`, `total_read_bytes`, `directory_entries`, `wildcard_matches`, …) bound
every operation, and any truncation is reported as incomplete evidence rather than silently
treated as a complete answer.

## API reference

| Call | Returns |
| --- | --- |
| `Analyzer(config=None, *, evidence=None)` | Reusable, serial-use analyzer facade |
| `analyzer.analyze(command, cwd, *, shell=None, env=None, effort=..., workspace_root=None)` | `dict` |
| `analyzer.analyze_report(...)` | `AnalysisReport` (immutable, `.to_dict()`) |
| `analyzer.analyze_json(...)` | JSON `str` |
| `analyzer.analyze_python(source, cwd, ...)` / `..._javascript(...)` | `dict` |
| `analyzer.analyze_sql(sql, *, dialect=None, ...)` | `dict` |
| `analyzer.parse(command, *, shell=None)` | Parsed syntax tree |
| `analyzer.capabilities()` | Versions, available frontends, limits |
| `analyzer.rule_catalog()` | Rule metadata |
| `analyzer.report_schema()` | Bundled JSON Schema |

Module-level convenience functions mirror the common calls: `analyze`, `analyze_json`,
`analyze_python`, `analyze_python_json`, `analyze_javascript`, `analyze_javascript_json`,
`analyze_sql`, `analyze_sql_json`. They construct a fresh `Analyzer` per call (and therefore
rebuild parser frontends), which is convenient for one-off checks but wasteful in a loop.

Input validation raises `InputError` (a `ValueError`); internal failures surface as
`AnalysisError` rather than leaking parser exceptions. Configuration problems raise
`ConfigurationError`.

An `Analyzer` keeps no cross-call shell state and each call gets a fresh evidence cache, but it
is a **serial-use** facade — don't share one instance across threads without external locking.

## Supported frontends

| Shell / language | Parser | Notes |
| --- | --- | --- |
| Bash | `tree-sitter-bash` | Pipelines, redirections, substitutions, heredocs, loops, functions |
| PowerShell | `tree-sitter-powershell` | Cmdlets, providers, splatting, script blocks, loops |
| CMD | built-in | Common built-ins and native tools; conservative subset |
| Python | `ast` | Calls, assignments, file I/O, subprocess, deletion, secret literals |
| JavaScript | `tree-sitter-javascript` | Node built-ins, `fetch`, `child_process`, file writes |
| SQL | `sqlglot` | DDL/DML severity and structure, multiple dialects |

Wildcard matching is implemented for Bash, PowerShell, CMD, and Python. Value tracking is bounded
for all five executable frontends.

## Design constraints

The analyzer intentionally prefers an explicit coverage notice over a confident guess. These
limits are part of the contract and are exposed by `Analyzer.capabilities()["limitations"]`:

- Conditions, runtime loop inputs, and arithmetic counters are not evaluated; general CMD
  `CALL` reparsing and `cmd /v:on` are unsupported.
- Variable alternatives are tracked independently, so differing `cwd` values and changed array
  shapes remain `unresolved`.
- Python joins assignment and call events without execution order or reachability; unsupported
  objects, dynamic imports, and third-party call behavior are not modelled.
- JavaScript models bounded Node built-ins and assignment/call events; modules, arbitrary
  objects, handles, and runtime results are not evaluated.
- SQL analysis is syntax-only: database state, procedural bodies, dynamic SQL, and
  client-side includes are not inspected.
- Wildcard matching is bounded and does not follow directory links; advanced provider patterns
  remain unresolved.
- Runtime output is bounded only for the recognized timestamp, digest, counter and range shapes.
  Everything else remains `unresolved-value`; a constrained scope is a containing directory, not a
  concrete filename.
- Configured trusted scripts skip source inspection by design. The analyzer does not claim to know
  their effects or to preserve the caller's state across the call.
- The Windows models are conservative and have not been validated against native Windows
  execution of every modelled command.

This is a review aid, not a sandbox. Findings describe what the text *may* do; absence of
findings is not proof that a command is safe.

## Development

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# POSIX:   source .venv/bin/activate

pip install -e ".[bash,windows,javascript,sql,dev]"
python -m pytest -q
```

The suite runs fully offline: commands are input data, and filesystem evidence is supplied
either through temporary directories or `MemoryEvidenceProvider`. It covers parser recovery,
path dialects, redaction, evidence budgets, report-schema conformance, and a hand-reviewed
legacy corpus.

```bash
python -m pytest tests/misc/test_review_contract.py -q   # contract-level regressions
python -m pytest -q -k redaction                          # security-focused subset
```

## Project layout

```
src/command_inspector/
├── api.py              # Analyzer facade and module-level helpers
├── catalog.py          # rule ids, types, levels, descriptions
├── config.py           # AnalyzerConfig + TOML loading
├── detectors.py        # shared detectors and evidence requests
├── local_evidence.py   # read-only providers, budgets, caching
├── reporting.py        # grouping, aggregation, redaction
├── paths.py            # POSIX/Windows lexical path semantics
├── models.py           # Fact, Finding, AnalysisReport, levels
├── shared/runtime_values.py  # bounded runtime output, path scope, language hints
├── bash/  pwsh/  cmd/  python/  javascript/  sql/   # frontends + semantics
├── admin/  git/  misc/  shared/                     # domain models
└── schemas/report.json # JSON Schema for reports
tests/                  # offline pytest suite and fixtures
```

## Security notes

- **No execution.** The package contains no subprocess, `eval`, or `exec` call. Python source is
  parsed with `ast` and compiled only to validate contextual syntax; the resulting code object is
  never executed. "subprocess" in the detectors refers to modelled facts about code being
  analyzed, not something the analyzer runs.
- **No network.** URL parsing uses `urllib.parse` only; nothing opens a connection.
- **Read-only evidence.** Local evidence performs `lstat`, bounded reads, and directory
  listings. It never writes, renames, or deletes.
- **Redaction is defense in depth, not a guarantee.** Reports replace credential-shaped values
  and private keys, but paths, command text, and finding details can still be sensitive. Treat
  reports as confidential when analyzing production commands.
- **Untrusted input is data.** Parsing is bounded (`source_nodes`, `file_bytes`, recursion
  limits), and malformed or hostile input degrades to a coverage finding rather than executing
  anything.
