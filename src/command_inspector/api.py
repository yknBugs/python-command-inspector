"""Serial-use facade. Every call has independent shell state and evidence cache."""
from importlib import metadata, resources
import json
from .catalog import rule_catalog
from .config import AnalyzerConfig
from .detectors import DetectorContext
from .local_evidence import CachedEvidenceProvider, DisabledEvidenceProvider, LocalEvidenceProvider
from .models import ANALYZER_VERSION, CATALOG_VERSION, SCHEMA_VERSION, AnalysisError, Fact, InputError
from .reporting import aggregate
from .bash.semantics import SemanticBuilder
from .paths import style_for
from .pwsh.syntax import PowerShellFrontend
from .cmd.syntax import CmdFrontend
from .pwsh.semantics import PowerShellBuilder
from .cmd.semantics import CmdBuilder
from .javascript.syntax import JavaScriptFrontend
from .javascript.semantics import JavaScriptBuilder
from .python.syntax import PythonFrontend
from .python.semantics import PythonBuilder
from .bash.syntax import BashFrontend, FrontendUnavailable, ParseBudgetExceeded
from .effort import EvidenceEffort, evidence_effort


class Analyzer:
    def __init__(self, config: AnalyzerConfig | None = None, *, evidence=None):
        self.config = config if config is not None else AnalyzerConfig()
        if not isinstance(self.config, AnalyzerConfig):
            from .models import ConfigurationError
            raise ConfigurationError("config must be AnalyzerConfig")
        self.evidence = evidence if evidence is not None else LocalEvidenceProvider() if self.config.local_evidence else DisabledEvidenceProvider()
        try:
            self.frontend = BashFrontend()
        except FrontendUnavailable:
            self.frontend = None
        try:
            self.powershell_frontend = PowerShellFrontend()
        except FrontendUnavailable:
            self.powershell_frontend = None
        self.cmd_frontend = CmdFrontend()
        self.python_frontend = PythonFrontend()
        try:
            self.javascript_frontend = JavaScriptFrontend()
        except FrontendUnavailable:
            self.javascript_frontend = None

    def _frontend(self, shell):
        return {"bash": self.frontend, "powershell": self.powershell_frontend, "cmd": self.cmd_frontend, "python": self.python_frontend, "javascript": self.javascript_frontend}.get(shell)

    def analyze_report(self, command: str, cwd: str, *, shell=None, env=None, effort=EvidenceEffort.FULL, workspace_root=None):
        effort = evidence_effort(effort)
        if not isinstance(command, str) or "\x00" in command:
            raise InputError("command must be a string without NUL bytes")
        if shell is not None and not isinstance(shell, str):
            raise InputError("shell must be a string or None")
        if env is not None and (not isinstance(env, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in env.items())):
            raise InputError("env must map strings to strings")
        try:
            command.encode("utf-8")
        except UnicodeError:
            raise InputError("command must be valid Unicode") from None
        selected = shell if shell is not None else self.config.shell
        paths = style_for(selected, cwd if isinstance(cwd, str) else "")
        if not isinstance(cwd, str) or not paths.absolute(cwd) or "\x00" in cwd:
            raise InputError("cwd must be an absolute path for the selected shell")
        cwd = paths.norm(cwd)
        if workspace_root is None:
            workspace_root = cwd
        if not isinstance(workspace_root, str) or not paths.absolute(workspace_root) or "\x00" in workspace_root:
            raise InputError("workspace_root must be an absolute path for the selected shell")
        workspace_root = paths.norm(workspace_root)
        frontend = self._frontend(selected)
        provider = CachedEvidenceProvider(self.evidence, self.config.total_read_bytes, self.config.directory_entries)
        context = DetectorContext(self.config, cwd, dict(env or {}), provider, self.frontend,
                                  command, shell=selected, effort=effort, workspace_root=workspace_root,
                                  frontends={"powershell": self.powershell_frontend, "cmd": self.cmd_frontend, "javascript": self.javascript_frontend})
        if frontend is None:
            context.emit("analysis-unavailable", "Selected shell frontend is unavailable", Fact("unresolved", "analyze"),
                         {"shell": selected, "reason": "missing_parser" if selected in {"bash", "powershell", "cmd", "javascript"} else "unsupported_shell"})
        elif len(command.encode()) > self.config.file_bytes:
            context.emit("unreadable-payload", "Command exceeds the configured source-byte budget", Fact("content", "analyze"))
        else:
            try:
                parsed = frontend.parse(command, self.config.source_nodes)
                if parsed.diagnostics:
                    context.emit("unsupported-syntax", "Command syntax could not be parsed completely", Fact("unresolved", "parse"))
                builder = {"bash": SemanticBuilder, "powershell": PowerShellBuilder, "cmd": CmdBuilder, "python": PythonBuilder, "javascript": JavaScriptBuilder}[selected]
                kwargs = {"paths": paths} if selected in {"python", "javascript"} else {}
                facts = builder(cwd, dict(env or {}), possible_values=self.config.possible_values, control_flow_steps=self.config.control_flow_steps, value_bytes=self.config.value_bytes, **kwargs).build(parsed.root) if parsed.root is not None else ()
                context.run(facts, cwd)
            except (ParseBudgetExceeded, RecursionError):
                context.emit("unreadable-payload", "Command exceeds the configured parsing or nesting budget", Fact("content", "analyze"))
            except Exception:
                raise AnalysisError("Command analysis failed internally") from None
        return aggregate(context.findings, self.config.disabled_rules, sensitive_literals=context.secret_literals)

    def analyze(self, command, cwd, *, shell=None, env=None, effort=EvidenceEffort.FULL, workspace_root=None):
        return self.analyze_report(command, cwd, shell=shell, env=env, effort=effort, workspace_root=workspace_root).to_dict()

    def analyze_json(self, command, cwd, *, shell=None, env=None, effort=EvidenceEffort.FULL, workspace_root=None):
        return json.dumps(self.analyze(command, cwd, shell=shell, env=env, effort=effort, workspace_root=workspace_root), ensure_ascii=False)

    def analyze_python_report(self, source, cwd, *, env=None, effort=EvidenceEffort.FULL, workspace_root=None):
        return self.analyze_report(source, cwd, shell="python", env=env, effort=effort, workspace_root=workspace_root)

    def analyze_python(self, source, cwd, *, env=None, effort=EvidenceEffort.FULL, workspace_root=None):
        return self.analyze_python_report(source, cwd, env=env, effort=effort, workspace_root=workspace_root).to_dict()

    def analyze_python_json(self, source, cwd, *, env=None, effort=EvidenceEffort.FULL, workspace_root=None):
        return json.dumps(self.analyze_python(source, cwd, env=env, effort=effort, workspace_root=workspace_root), ensure_ascii=False)

    def analyze_javascript_report(self, source, cwd, *, env=None, effort=EvidenceEffort.FULL, workspace_root=None):
        return self.analyze_report(source, cwd, shell="javascript", env=env, effort=effort, workspace_root=workspace_root)

    def analyze_javascript(self, source, cwd, *, env=None, effort=EvidenceEffort.FULL, workspace_root=None):
        return self.analyze_javascript_report(source, cwd, env=env, effort=effort, workspace_root=workspace_root).to_dict()

    def analyze_javascript_json(self, source, cwd, *, env=None, effort=EvidenceEffort.FULL, workspace_root=None):
        return json.dumps(self.analyze_javascript(source, cwd, env=env, effort=effort, workspace_root=workspace_root), ensure_ascii=False)

    def analyze_sql_report(self, sql: str, *, dialect=None, effort=EvidenceEffort.FULL):
        effort = evidence_effort(effort)
        if not isinstance(sql, str) or "\x00" in sql:
            raise InputError("sql must be a string without NUL bytes")
        if dialect is not None and not isinstance(dialect, str):
            raise InputError("dialect must be a string or None")
        try:
            sql.encode("utf-8")
        except UnicodeError:
            raise InputError("sql must be valid Unicode") from None
        # Standalone SQL needs neither workspace classification nor local evidence.
        provider = CachedEvidenceProvider(DisabledEvidenceProvider(), self.config.total_read_bytes, self.config.directory_entries)
        context = DetectorContext(self.config, "/", {}, provider, self.frontend, effort=effort)
        try:
            context.inspect_sql(sql, dialect, Fact("sql_source", dialect or "generic", source="sql"))
        except Exception:
            raise AnalysisError("SQL analysis failed internally") from None
        return aggregate(context.findings, self.config.disabled_rules, sensitive_literals=context.secret_literals)

    def analyze_sql(self, sql, *, dialect=None, effort=EvidenceEffort.FULL):
        return self.analyze_sql_report(sql, dialect=dialect, effort=effort).to_dict()

    def analyze_sql_json(self, sql, *, dialect=None, effort=EvidenceEffort.FULL):
        return json.dumps(self.analyze_sql(sql, dialect=dialect, effort=effort), ensure_ascii=False)

    def parse(self, command, *, shell=None):
        if shell is not None and not isinstance(shell, str):
            raise InputError("shell must be a string or None")
        frontend = self._frontend(shell if shell is not None else self.config.shell)
        if frontend is None:
            raise InputError("shell frontend unavailable; consult capabilities")
        if not isinstance(command, str):
            raise InputError("command must be a string")
        if len(command.encode()) > self.config.file_bytes:
            raise InputError("command exceeds parse byte budget")
        return frontend.parse(command, self.config.source_nodes)

    def capabilities(self):
        return {"analyzer_version": ANALYZER_VERSION, "schema_version": SCHEMA_VERSION,
                "rule_catalog_version": CATALOG_VERSION, "frontends": {"bash": self.frontend is not None, "powershell": self.powershell_frontend is not None, "cmd": True, "python": True, "javascript": self.javascript_frontend is not None},
                "source_languages": ["shell", "powershell", "cmd", "python", "javascript", "sql"],
                "sql_parser_available": self._version("sqlglot") is not None,
                "evidence_provider": type(self.evidence).__name__,
                "evidence_efforts": [e.value for e in EvidenceEffort],
                "wildcard_matching": ["bash", "powershell", "cmd", "python"],
                "bounded_value_tracking": ["bash", "powershell", "cmd", "python", "javascript"],
                "control_flow_limits": {"possible_values": self.config.possible_values,
                                        "control_flow_steps": self.config.control_flow_steps,
                                        "value_bytes": self.config.value_bytes},
                "limitations": ["Windows models are a conservative subset; native Windows execution has not been validated", "Conditions, runtime loop inputs and arithmetic counters are not evaluated; general CMD CALL reparsing and launcher /v:on remain unsupported", "Variable choices are independent; differing cwd and changed array shapes remain unresolved", "Python joins assignment and call events without execution order or reachability; unsupported objects, imports and third-party call behavior are not evaluated", "No audited Git state reader", "JavaScript models bounded Node built-ins and assignment/call events; modules, arbitrary objects, handles and runtime results are not evaluated", "SQL uses syntax only; database state, procedural bodies, dynamic SQL and transitive/client includes are not inspected", "Wildcard matching is bounded and does not follow directory links; advanced shell/provider patterns remain unresolved"],
                "parser_versions": {name: self._version(name) for name in ("tree-sitter", "tree-sitter-bash", "tree-sitter-powershell", "tree-sitter-javascript", "sqlglot")}}

    @staticmethod
    def _version(name):
        try:
            return metadata.version(name)
        except metadata.PackageNotFoundError:
            return None

    @staticmethod
    def rule_catalog():
        return rule_catalog()

    @staticmethod
    def report_schema():
        return json.loads(resources.files("command_inspector").joinpath("schemas/report.json").read_text(encoding="utf-8"))


def analyze(command, cwd, *, shell, env=None, config=None, effort=EvidenceEffort.FULL, workspace_root=None):
    return Analyzer(config).analyze(command, cwd, shell=shell, env=env, effort=effort, workspace_root=workspace_root)


def analyze_json(command, cwd, *, shell, env=None, config=None, effort=EvidenceEffort.FULL, workspace_root=None):
    return Analyzer(config).analyze_json(command, cwd, shell=shell, env=env, effort=effort, workspace_root=workspace_root)


def analyze_sql(sql, *, dialect=None, config=None, effort=EvidenceEffort.FULL):
    return Analyzer(config).analyze_sql(sql, dialect=dialect, effort=effort)


def analyze_sql_json(sql, *, dialect=None, config=None, effort=EvidenceEffort.FULL):
    return Analyzer(config).analyze_sql_json(sql, dialect=dialect, effort=effort)


def analyze_python(source, cwd, *, env=None, config=None, effort=EvidenceEffort.FULL, workspace_root=None):
    return Analyzer(config).analyze_python(source, cwd, env=env, effort=effort, workspace_root=workspace_root)


def analyze_python_json(source, cwd, *, env=None, config=None, effort=EvidenceEffort.FULL, workspace_root=None):
    return Analyzer(config).analyze_python_json(source, cwd, env=env, effort=effort, workspace_root=workspace_root)


def analyze_javascript(source, cwd, *, env=None, config=None, effort=EvidenceEffort.FULL, workspace_root=None):
    return Analyzer(config).analyze_javascript(source, cwd, env=env, effort=effort, workspace_root=workspace_root)


def analyze_javascript_json(source, cwd, *, env=None, config=None, effort=EvidenceEffort.FULL, workspace_root=None):
    return Analyzer(config).analyze_javascript_json(source, cwd, env=env, effort=effort, workspace_root=workspace_root)
