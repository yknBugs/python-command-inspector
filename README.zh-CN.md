# Command Inspector

[English](README.md) | **简体中文**

**可解释、只读的执行前检查工具，面向 shell 命令和小段源码。**

`command-inspector` 接收一条你**即将执行**的命令，以及工作目录、环境变量和 shell 方言，
返回一组结构化“发现项”（finding），说明这段文本将会做什么。它不会执行命令，不会求值代码，
也不会访问网络。

这个库面向 AI 编程 Agent 以及围绕它们的审批流程：审查者（人或程序）可以在命令真正生效
之前先问“这一行会碰到什么？”。它不是沙箱，也不是针对已部署代码的漏洞扫描器——范围背后的
威胁模型见 [项目缘起](#项目缘起)。

```python
>>> from command_inspector import Analyzer
>>> Analyzer().analyze("git push --force origin main", "/work/project", shell="bash")["level"]
'HIGH'
```

---

## 目录

- [项目缘起](#项目缘起)
- [它能分析什么](#它能分析什么)
- [安装](#安装)
- [快速开始](#快速开始)
- [报告格式](#报告格式)
- [发现等级与规则家族](#发现等级与规则家族)
- [配置](#配置)
- [本地证据与检查力度](#本地证据与检查力度)
- [API 速查](#api-速查)
- [支持的前端](#支持的前端)
- [设计边界](#设计边界)
- [开发](#开发)
- [项目结构](#项目结构)
- [安全说明](#安全说明)

## 项目缘起

这个项目诞生的直接目的，是审查辅助编程的 AI Agent 即将执行的操作，并从中提取出真正值得
用户关注的点。

在长流程的编程任务里，人的注意力是有限资源：当 Agent 已经连续执行了几十条命令，再要求
用户逐条仔细阅读并不现实。外置工具的价值，就是把命令总结成少量需要用户做决定的事项，
降低审查负担。

项目的威胁模型很窄，也很明确：

- **Agent 诚实但会犯错。** 它可能因为幻觉生成错误闭合的引号、写错参数或拼出破坏性的路径，
  从而损坏用户的系统；前端无法完整解析的畸形语法会作为覆盖提示报告，而不是被当成无害。
  但它不会故意混淆自己的命令、刻意绕过审查，或主动选择执行危险操作。因此检查器按字面理解
  命令：`cd` 就是 `cd`，通过 shell alias 或函数把 `cd` 重定义成 `rm -rf` 这类情况不在
  考虑范围内。这也意味着它**不适合**审查人类编写或对抗性构造的代码。
- **执行是一次性的。** 绝大多数 AI Agent 框架执行一条命令、拿到结果后就丢弃进程，
  不存在可被长期利用的会话或数据库连接。因此 Bandit 这类工具所针对的、依赖持久状态的
  注入攻击面在这里并不成立；本项目的 SQL 分析关注的是 `DROP`、`TRUNCATE` 这类操作的
  影响范围，而不是 SQL 注入。
- **注意力才是稀缺资源。** 发现项的等级按“对审查者有多重要”划分，而不是按抽象的安全评分。

有两个风险不需要推翻这个假设：Agent 可能从文件或依赖中读到对抗性文本（提示注入），也可能
照抄一段并非自己编写的编码命令。两者都会被当作异常报告，而不是被当成 Agent 的刻意规避。

这也是它与 Bandit 等工具的主要区别：Bandit 在部署前审计代码库里潜在的漏洞；
`command-inspector` 在 Agent 执行下一步动作之前，审计这条命令的实际后果，前提是它的
作者并非攻击者。

非目标：沙箱、恶意软件分析、漏洞利用检测，以及审查将要部署到敌对环境的代码。

## 它能分析什么

| 领域 | 示例 |
| --- | --- |
| 破坏性文件操作 | `rm -rf /`、`Remove-Item -Recurse -Force C:\`、`shutil.rmtree`、`rd /s /q` |
| 写入与重定向 | `Set-Content`、`> file`、`sed -i`、`os.truncate` |
| 执行与提权 | `sudo`、`su`、`Start-Process -Verb RunAs`、解释器调用 |
| 网络与数据传输 | `curl`、`wget`、`Invoke-WebRequest`、`scp`、`rsync`、clone |
| 凭据 | `--password`、`Authorization:` 头、URL userinfo、凭据形态的字面量 |
| Git | force-push、历史重写、敏感配置键 |
| 软件包、服务、磁盘、电源 | 安装、`systemctl`、`crontab`、裸设备、关机/重启 |
| SQL | 在不执行的前提下判断 DDL/DML 的影响等级 |
| 内容检查 | 从文件中读到的提示注入文本、混淆载荷 |

让输出“有用而不是噪音”的三件事：

1. **看语义，而不是匹配字符串。** 命令由 tree-sitter 解析（Python 用 `ast`，SQL 用
   `sqlglot`），原生命令按参数建模。`echo ufw` 不会被当成修改防火墙；
   `git config --global core.sshCommand ...` 会按键和生效范围分类。
2. **有界值追踪。** 变量、`$VAR`、PowerShell 插值、数组和简单分支都会在明确上限内跟踪，
   因此 `X=/etc; rm -rf "$X"` 能解析出来。模型无法确定的值会变成显式的
   `unresolved-value` 提示，而不是猜测。
3. **只读的本地证据。** 启用后，分析器会对目标做 stat、读取文件头部、展开有界通配符，
   从而区分“删除 `/etc`”和“删除一个不存在的文件”。每次读取和遍历都有预算限制，
   结果按调用缓存。

## 安装

要求 **Python 3.11+**。核心包没有必需的运行时依赖；解析器按 shell 拆成可选 extras，
用什么装什么。

```bash
# 全部安装，并带上测试工具链
pip install -e ".[bash,windows,javascript,sql,dev]"
```

或者用 Conda：

```bash
conda env create -f environment.yml
conda activate command-inspector
```

Extras 说明：

| Extra | 启用的能力 | 依赖 |
| --- | --- | --- |
| `bash` | Bash 解析 | `tree-sitter-bash` |
| `windows` | PowerShell 解析 | `tree-sitter-powershell` |
| `javascript` | JavaScript 解析 | `tree-sitter-javascript` |
| `sql` | SQL 分析 | `sqlglot` |
| `dev` | 测试套件 | `pytest`、`jsonschema` |

CMD 和 Python 前端始终可用，不需要额外依赖。缺少某个解析器不会让分析器崩溃：
该次调用会报告 `analysis-unavailable`，而 `Analyzer.capabilities()` 会告诉你哪些前端已安装。

## 快速开始

### 分析一条命令

```python
from command_inspector import Analyzer

analyzer = Analyzer()
report = analyzer.analyze(
    "rm -rf /",
    "/home/me/project",   # 绝对 cwd，使用所选 shell 的路径方言
    shell="bash",
    env={"HOME": "/home/me"},
)

if report["level"] in {"HIGH", "BLOCK"}:
    print(report["level"], [f["rule"] for f in report["findings"]])
# BLOCK ['delete-protected-root']
```

`workspace_root` 默认等于 `cwd`。当项目根目录与命令实际运行目录不同时，请显式传入；
读写类发现项就是用它来判断“是否在工作区内”。

### 直接分析源码

```python
from command_inspector import Analyzer

analyzer = Analyzer()

analyzer.analyze_python('import shutil\nshutil.rmtree("/etc")\n', "/work")["level"]
# 'BLOCK'

analyzer.analyze_javascript('require("fs").writeFileSync("/etc/passwd", "x")', "/work")
analyzer.analyze_sql("DROP TABLE users", dialect="postgres")["level"]
# 'HIGH'
```

`dialect=None` 表示交给 `sqlglot` 使用通用方言；无法识别或不支持的 SQL 会退化为
`sql-unresolved` 覆盖提示，而不是假装“没有问题”。

### 获取 JSON

`analyze_json`、`analyze_python_json`、`analyze_javascript_json` 和 `analyze_sql_json`
返回 JSON 字符串，而不是 dict：

```python
wire = analyzer.analyze_json("git push --force origin main", "/work/project", shell="bash")
```

### 处理“无发现”的情况

分析结果干净时返回的是**空对象**，而不是一个 `findings` 为空的报告。schema 特意写成
`oneOf [ {}, report ]`，所以只要报告里出现 `findings`，就说明确实发现了东西：

```python
report = analyzer.analyze("ls", "/work/project", shell="bash")
assert report == {}
```

### 单次调用的检查力度

可以在不改变解析行为的前提下降低文件系统检查力度：

```python
analyzer.analyze(cmd, cwd, shell="bash", effort="None")     # 完全不访问文件系统
analyzer.analyze(cmd, cwd, shell="bash", effort="Partial")  # 只看元数据，不读内容
```

默认是 `"Full"`，名称不区分大小写。

## 报告格式

每个非空报告都符合随包提供的 `schemas/report.json`（JSON Schema 2020-12）。下面是真实输出示例：

```json
{
  "schema_version": "1.0.0",
  "analyzer_version": "1.10.0",
  "rule_catalog_version": "1.10.0",
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

- `level` 是所有发现项中的最高等级；`findings` 按严重程度从高到低排序。
- `data` 存放与规则相关的事实（目标、目的地址、选项、未解析名称等）。
- `evidence` 记录本地检查贡献了什么，包括不可用或被截断的证据，让低置信度结果显式可见。
- 报告在序列化前会脱敏：凭据形态的字面量、`Bearer`/`Basic` 值、URL userinfo 和私钥块
  会被替换为 `[REDACTED]`。

## 发现等级与规则家族

规则目录共 **76 条规则、9 个类型**（`content`、`coverage`、`environment`、`execution`、
`filesystem`、`git`、`network`、`sql`、`system`）。

| 等级 | 含义 |
| --- | --- |
| `LOW` | 不一定危险，但值得用户了解（例如读取工作区外的文件） |
| `MEDIUM` | 不一定危险，但涉及关键状态变更，用户应当知情并同意（例如删除工作区外的文件） |
| `HIGH` | 正常编程任务中几乎不会出现的操作（例如卸载文件系统） |
| `BLOCK` | 明显危险、几乎必然造成破坏性后果的操作（例如删除系统文件） |

每条规则的等级基本固定（少数规则会依上下文输出两个等级）。等级表达的是审查优先级，
而不是 CVSS 式的漏洞严重度。规则可以通过配置按 id 禁用。完整规则目录（含描述和引入版本）
可以在代码中获取：

```python
catalog = analyzer.rule_catalog()
[c["rule"] for c in catalog["rules"]]
```

## 配置

配置必须显式提供——分析器不会自己去发现项目配置文件。

```python
from command_inspector import Analyzer, AnalyzerConfig

config = AnalyzerConfig(
    shell="bash",
    protected_directories=("/", "/etc", "/usr", "/srv/data"),
    allowed_write_paths=("/work/build",),
    disabled_rules=frozenset({"git-push"}),
    local_evidence=True,
    possible_values=16,
    control_flow_steps=256,
)
analyzer = Analyzer(config)
```

同样的结构也可以从 TOML 加载：

```toml
shell = "bash"
local_evidence = true

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

说明：

- 未知的顶层字段、未知规则 id、非布尔值的 `enabled` 都会抛出 `ConfigurationError`。
- 提供 `[tools.known]` 会**替换**内置的已知工具表，而不是追加；只想新增名字时，
  请自行与 `AnalyzerConfig().known_tools` 合并。
- `protected.directories` 目前要求 `match = "self"`（默认值），即精确匹配该目录及其内容，
  不支持通配符。
- 如果你已经有解析好的配置字典，`AnalyzerConfig.from_mapping()` 接受同样的结构。

## 本地证据与检查力度

本地证据让分析器能够说 *“这会删除一个已存在的 4 GB 目录”*，而不是 *“这会删除 `$X`”*。
它严格只读，并且通过 provider 完成：

| Provider | 用途 |
| --- | --- |
| `LocalEvidenceProvider` | 默认。`lstat`、有界文件读取、目录列举 |
| `DisabledEvidenceProvider` | 完全不访问文件系统 |
| `MemoryEvidenceProvider` | 内存中的 fixture，绝不回退到磁盘（测试常用） |
| `CachedEvidenceProvider` | 包装另一个 provider，提供单次调用的读取/条目预算和缓存 |

```python
from command_inspector import Analyzer
from command_inspector.local_evidence import DisabledEvidenceProvider

analyzer = Analyzer(evidence=DisabledEvidenceProvider())
```

检查力度：

- **Full** —— 元数据、文件内容、通配符展开、删除摘要。
- **Partial** —— 只看元数据；即使自定义 provider 返回了内容或字节数，也会被过滤掉。
- **None** —— 不调用 provider。

预算（`file_bytes`、`total_read_bytes`、`directory_entries`、`wildcard_matches` 等）会限制
每一次操作；任何截断都会作为“不完整证据”报告，而不会被悄悄当成完整答案。

## API 速查

| 调用 | 返回 |
| --- | --- |
| `Analyzer(config=None, *, evidence=None)` | 可复用、串行使用的分析器门面 |
| `analyzer.analyze(command, cwd, *, shell=None, env=None, effort=..., workspace_root=None)` | `dict` |
| `analyzer.analyze_report(...)` | `AnalysisReport`（不可变，`.to_dict()`） |
| `analyzer.analyze_json(...)` | JSON `str` |
| `analyzer.analyze_python(source, cwd, ...)` / `..._javascript(...)` | `dict` |
| `analyzer.analyze_sql(sql, *, dialect=None, ...)` | `dict` |
| `analyzer.parse(command, *, shell=None)` | 解析后的语法树 |
| `analyzer.capabilities()` | 版本、可用前端、限制 |
| `analyzer.rule_catalog()` | 规则元数据 |
| `analyzer.report_schema()` | 随包提供的 JSON Schema |

模块级便捷函数覆盖常见调用：`analyze`、`analyze_json`、`analyze_python`、
`analyze_python_json`、`analyze_javascript`、`analyze_javascript_json`、`analyze_sql`、
`analyze_sql_json`。它们每次调用都会新建一个 `Analyzer`（也就重建解析器前端），
适合一次性检查，但不适合放进循环。

输入校验失败抛 `InputError`（`ValueError` 的子类）；内部失败会转为 `AnalysisError`，
不会把解析器异常直接泄漏给调用方。配置问题抛 `ConfigurationError`。

`Analyzer` 不保留跨调用的 shell 状态，每次调用都有独立的证据缓存；但它是**串行使用**的
门面——不要在多线程里共享同一个实例而不加锁。

## 支持的前端

| Shell / 语言 | 解析器 | 说明 |
| --- | --- | --- |
| Bash | `tree-sitter-bash` | 管道、重定向、替换、heredoc、循环、函数 |
| PowerShell | `tree-sitter-powershell` | Cmdlet、provider、splatting、脚本块、循环 |
| CMD | 内置 | 常见内建命令和原生工具；保守子集 |
| Python | `ast` | 调用、赋值、文件 I/O、subprocess、删除、凭据字面量 |
| JavaScript | `tree-sitter-javascript` | Node 内置模块、`fetch`、`child_process`、文件写入 |
| SQL | `sqlglot` | DDL/DML 等级与结构，支持多种方言 |

通配符匹配已为 Bash、PowerShell、CMD 和 Python 实现；五个可执行前端都支持有界值追踪。

## 设计边界

分析器有意选择“显式覆盖提示”而不是“自信的猜测”。这些限制是契约的一部分，可通过
`Analyzer.capabilities()["limitations"]` 获取：

- 不评估条件、运行时循环输入和算术计数器；不支持通用 CMD `CALL` 重解析和 `cmd /v:on`。
- 变量候选独立跟踪，因此 `cwd` 不一致、数组形状变化仍会保持 `unresolved`。
- Python 把赋值和调用事件拼接起来，不考虑执行顺序或可达性；不支持的对象、动态导入和
  第三方调用行为不会被建模。
- JavaScript 只建模有界的 Node 内置模块和赋值/调用事件；模块、任意对象、句柄和运行时结果
  都不评估。
- SQL 仅做语法分析：数据库状态、过程体、动态 SQL 和客户端 include 都不会被检查。
- 通配符匹配有界，且不跟随目录链接；高级 provider 模式保持 `unresolved`。
- Windows 模型是保守子集，尚未针对所有已建模命令在原生 Windows 上的实际执行行为做验证。

这是审查辅助工具，不是沙箱。发现项描述的是文本**可能**做什么；没有发现不代表命令安全。

## 开发

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# POSIX:   source .venv/bin/activate

pip install -e ".[bash,windows,javascript,sql,dev]"
python -m pytest -q
```

测试套件完全离线：命令只是输入数据，文件系统证据来自临时目录或 `MemoryEvidenceProvider`。
覆盖范围包括解析器恢复、路径方言、脱敏、证据预算、报告 schema 一致性，以及一份人工审阅过的
历史语料。

```bash
python -m pytest tests/misc/test_review_contract.py -q   # 契约级回归
python -m pytest -q -k redaction                          # 安全相关子集
```

## 项目结构

```
src/command_inspector/
├── api.py              # Analyzer 门面与模块级函数
├── catalog.py          # 规则 id、类型、等级、描述
├── config.py           # AnalyzerConfig + TOML 加载
├── detectors.py        # 共享检测器与证据请求
├── local_evidence.py   # 只读 provider、预算、缓存
├── reporting.py        # 分组、聚合、脱敏
├── paths.py            # POSIX/Windows 词法路径语义
├── models.py           # Fact、Finding、AnalysisReport、等级
├── bash/  pwsh/  cmd/  python/  javascript/  sql/   # 前端与语义
├── admin/  git/  misc/  shared/                     # 领域模型
└── schemas/report.json # 报告的 JSON Schema
tests/                  # 离线 pytest 套件与 fixtures
```

## 安全说明

- **不执行。** 包内没有 subprocess、`eval` 或 `exec` 调用。Python 源码用 `ast` 解析，
  并仅为了校验上下文语法而 `compile`；得到的 code object 从不执行。检测器里的
  “subprocess” 指的是被分析代码中的事实，不是分析器自己会去运行进程。
- **不联网。** URL 解析只用 `urllib.parse`，不会建立任何连接。
- **证据只读。** 本地证据只做 `lstat`、有界读取和目录列举，绝不写入、重命名或删除。
- **脱敏是纵深防御，不是保证。** 报告会替换凭据形态的值和私钥，但路径、命令文本和发现项
  细节仍可能敏感。分析生产命令时，请把报告当作机密数据。
- **不可信输入只当数据。** 解析有预算限制（`source_nodes`、`file_bytes`、递归限制），
  畸形或恶意输入会退化为覆盖提示，而不是执行任何东西。
