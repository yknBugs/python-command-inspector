"""Static Node analysis: fixtures are parsed, never executed."""
import json
import shlex
import pytest

pytest.importorskip('tree_sitter_javascript')
from command_inspector import Analyzer, AnalyzerConfig, analyze_javascript_json
from command_inspector.bash.syntax import ParseBudgetExceeded
from command_inspector.javascript.syntax import JavaScriptFrontend
from command_inspector.javascript.semantics import JavaScriptBuilder
from command_inspector.local_evidence import DisabledEvidenceProvider, MemoryEvidenceProvider, ReadFile
from command_inspector.paths import PathStyle


def analyze(source, *, files=None, cwd='/work', env=None, config=None, effort='full'):
    provider = DisabledEvidenceProvider() if files is None else MemoryEvidenceProvider(files)
    return Analyzer(config, evidence=provider).analyze_javascript(source, cwd, env=env, effort=effort), provider


def rules(report):
    return {f['rule'] for f in report.get('findings', [])}


def findings(report, prefix):
    return [f for f in report.get('findings', []) if f['rule'].startswith(prefix)]


def facts(source, cwd='/work'):
    parsed = JavaScriptFrontend().parse(source)
    assert not parsed.diagnostics
    return JavaScriptBuilder(cwd, {}, paths=PathStyle(':' in cwd)).build(parsed.root)


@pytest.mark.parametrize('setup,call', [
    ('const fs=require("fs");', 'fs.rmSync'),
    ('const fs=require("node:fs");', 'fs.rm'),
    ('const {rmSync: remove}=require("fs");', 'remove'),
    ('const {rmSync}=require("fs");', 'rmSync'),
    ('import fs from "node:fs";', 'fs.rmSync'),
    ('import * as fs from "fs";', 'fs.rmSync'),
    ('import {rm as remove} from "node:fs/promises";', 'remove'),
    ('const fs=require("fs/promises");', 'fs.rm'),
    ('const fs=require("fs").promises;', 'fs.rm'),
    ('const fs=require("fs"); const remove=fs.rmSync;', 'remove'),
])
def test_builtin_import_and_alias_delete(setup, call):
    report, _ = analyze(setup + call + '("/etc", {recursive:true, force:true});')
    assert 'delete-protected-root' in rules(report)
    item = findings(report, 'delete-protected-root')[0]
    assert item['data']['recursive'] and item['data']['force']


@pytest.mark.parametrize('source,targets', [
    ('let p="a"; p="b"; fs.unlinkSync(p);', {'/work/a','/work/b'}),
    ('fs.unlinkSync(p); const p="a";', {'/work/a'}),
    ('const p=flag?"a":"b"; fs.unlinkSync(p);', {'/work/a','/work/b'}),
    ('let p="a"; if(flag) p="b"; fs.unlinkSync(p);', {'/work/a','/work/b'}),
    ('for(const p of ["a","b"]) fs.unlinkSync(p);', {'/work/a','/work/b'}),
    ('const p="a"; fs.unlinkSync(`${p}/x`);', {'/work/a/x'}),
    ('const p="a"; fs.unlinkSync(p+"/x");', {'/work/a/x'}),
    ('const p={x:"a"}; fs.unlinkSync(p.x);', {'/work/a'}),
    ('const p=["a","b"]; fs.unlinkSync(p[1]);', {'/work/b'}),
    ('function clean(p){fs.unlinkSync(p)} clean("a"); clean("b");', {'/work/a','/work/b'}),
    ('const clean=(p)=>fs.unlinkSync(p); clean("a");', {'/work/a'}),
    ('function name(){return "a"} fs.unlinkSync(name());', {'/work/a'}),
    ('function clean(p="a"){fs.unlinkSync(p)} clean();', {'/work/a'}),
    ('const p="a"; {const p="b"; fs.unlinkSync(p)} fs.unlinkSync(p);', {'/work/a','/work/b'}),
    ('const path=require("path"); fs.unlinkSync(path.join("a","b"));', {'/work/a/b'}),
    ('const path=require("path"); fs.unlinkSync(path.resolve("a","b"));', {'/work/a/b'}),
])
def test_possible_assignment_and_call_events(source, targets):
    report, _ = analyze('const fs=require("fs");' + source)
    assert {f['data']['target'] for f in findings(report, 'delete-inside')} == targets
    assert 'delete-variable-unresolved' not in rules(report)


@pytest.mark.parametrize('source', [
    'let p="a"; p=unknown(); fs.unlinkSync(p);',
    'for(let i=0;i<4;i++) fs.unlinkSync(i);',
    'for(const p of getFiles()) fs.unlinkSync(p);',
    'const p=["a"]; p.push("b"); fs.unlinkSync(p[0]);',
    'const p={x:"a"}; p.x="b"; fs.unlinkSync(p.x);',
    'const p={x:"a"}; const q=p; q.x="b"; fs.unlinkSync(p.x);',
    'const p=Buffer.from("a"); fs.unlinkSync(p);',
    'const p=[,"a"]; fs.unlinkSync(p[0]);',
    'fs.unlinkSync(process.env.MISSING);',
    'fs.unlinkSync(__dirname);',
])
def test_unknown_values_never_become_concrete_paths(source):
    report, _ = analyze('const fs=require("fs");' + source)
    assert 'delete-variable-unresolved' in rules(report)
    assert not findings(report, 'delete-inside')


@pytest.mark.parametrize('recursive,expected', [('true', True), ('false', False), ('flag', None)])
def test_delete_options(recursive, expected):
    report, _ = analyze('require("fs").rmSync("build",{recursive:' + recursive + '});')
    assert findings(report, 'delete-inside')[0]['data']['recursive'] is expected
    assert ('delete-recursion-unresolved' in rules(report)) == (expected is None)


@pytest.mark.parametrize('call,kind,operation', [
    ('readFileSync("data","utf8")', 'read','ingest'),
    ('statSync("data")','read','list'),
    ('readdirSync("data")','read','list'),
    ('mkdirSync("build")','write','create_directory'),
    ('writeFileSync("data","hello")','write','overwrite'),
    ('appendFileSync("data","hello")','write','append'),
    ('writeFileSync("data","hello",{flag:"a"})','write','append'),
    ('writeFileSync("data","hello",{flag:"r+"})','write','transform'),
    ('truncateSync("data",0)','write','overwrite'),
    ('truncateSync("data",5)','write','transform'),
    ('unlinkSync("data")','delete','remove'),
])
def test_filesystem_events(call, kind, operation):
    (fact,) = facts('require("fs").'+call)
    assert (fact.kind,fact.operation,fact.targets) == (kind,operation,('/work/data' if 'data' in call else '/work/build',))


@pytest.mark.parametrize('extension', ['js','mjs','cjs'])
def test_written_source_syntax_errors(extension):
    report, _ = analyze(f'require("fs").writeFileSync("bad.{extension}", "const x = ;");')
    assert rules(report) == {'written-source-syntax-error'}


@pytest.mark.parametrize('source', ['const = ;', 'let x = (', 'return 1;', 'break;', 'continue;'])
def test_syntax_diagnostics(source):
    parsed = JavaScriptFrontend().parse(source)
    assert parsed.diagnostics and parsed.root is None
    assert rules(analyze(source)[0]) == {'unsupported-syntax'}


def test_unicode_spans_and_budgets():
    parsed = JavaScriptFrontend().parse('const x="文字";')
    assert parsed.root.span.end == len('const x="文字";')
    with pytest.raises(ParseBudgetExceeded):
        JavaScriptFrontend().parse('const x="文字";', max_nodes=2)
    assert 'unreadable-payload' in rules(analyze('const x="文字";', config=AnalyzerConfig(source_nodes=2))[0])


@pytest.mark.parametrize('source', [
    'const cp=require("child_process"); cp.execSync("rm -rf /etc");',
    'const {exec}=require("node:child_process"); exec("rm -rf /etc");',
    'const cp=require("child_process"); cp.spawnSync("rm",["-rf","/etc"]);',
    'const cp=require("child_process"); cp.execFileSync("rm",["-rf","/etc"]);',
    'const cp=require("child_process"); cp.spawn("rm",["-rf","/etc"],{shell:true});',
    'eval("require(\\"fs\\").rmSync(\\"/etc\\",{recursive:true,force:true})");',
    'require("vm").runInThisContext("require(\\"fs\\").rmSync(\\"/etc\\",{recursive:true,force:true})");',
])
def test_execution_contents(source):
    assert 'delete-protected-root' in rules(analyze(source)[0])


def test_eval_inherits_bounded_values():
    report, _ = analyze('const p="/etc"; eval("require(\\"fs\\").rmSync(p,{recursive:true,force:true})");')
    assert 'delete-protected-root' in rules(report)


@pytest.mark.parametrize('source', [
    'eval(getCode())',
    'require("child_process").execSync(getCode())',
    'require("child_process").spawnSync(getExecutable(),["a"])',
    'require("child_process").spawnSync("sh",getArgs())',
    'require("child_process").spawnSync("sh",[],{shell:chooseShell()})',
])
def test_unknown_execution_is_visible(source):
    report, _ = analyze(source)
    assert rules(report) & {'execution-content-unavailable','unresolved-value'}


def test_argv_does_not_interpret_shell_metacharacters():
    report, _ = analyze('require("child_process").spawnSync("echo",["hello; rm -rf /etc"]);')
    assert not findings(report,'delete-')


@pytest.mark.parametrize('effort,checked', [('full',True),('partial',False),('none',False)])
def test_direct_script_evidence_effort(effort, checked):
    provider=MemoryEvidenceProvider({'/work/clean.js':b'require("fs").rmSync("/etc",{recursive:true,force:true});'})
    report=Analyzer(evidence=provider).analyze('node clean.js','/work',shell='bash',effort=effort)
    assert ('delete-protected-root' in rules(report)) is checked
    assert ('execution-content-unavailable' in rules(report)) is not checked


@pytest.mark.parametrize('write', [
    'fs.writeFileSync("code.js","console.log(1)");',
    'fs.unlinkSync("code.js");',
    'fs.renameSync("code.js","new.js");',
    'fs.copyFileSync("new.js","code.js");',
    'function change(){fs.writeFileSync("code.js","console.log(1)")} change();',
    'const change=()=>fs.writeFileSync("code.js","console.log(1)"); change();',
    'function change(){fs.writeFileSync("code.js","console.log(1)")} setTimeout(change,0);',
])
@pytest.mark.parametrize('first', [True,False])
def test_possible_writes_invalidate_all_reads(write, first):
    read='eval(fs.readFileSync("code.js","utf8"));'
    source='const fs=require("fs");'+(read+write if first else write+read)
    report, _ = analyze(source,files={'/work/code.js':b'require("fs").rmSync("/etc",{recursive:true,force:true})','/work/new.js':b'console.log(1)'})
    assert 'execution-content-unavailable' in rules(report)
    assert 'delete-protected-root' not in rules(report)


def test_dormant_writes_do_not_invalidate_reads():
    source='const fs=require("fs"); eval(fs.readFileSync("code.js","utf8")); function change(){fs.writeFileSync("code.js","console.log(1)")}'
    report, _ = analyze(source,files={'/work/code.js':b'require("fs").rmSync("/etc",{recursive:true,force:true})'})
    assert 'delete-protected-root' in rules(report)


def test_read_file_variable_is_inspected_once():
    report, _ = analyze('const fs=require("fs"); const code=fs.readFileSync("code.js","utf8"); eval(code);',
                        files={'/work/code.js':b'require("fs").rmSync("/etc",{recursive:true,force:true})'})
    assert 'delete-protected-root' in rules(report)


@pytest.mark.parametrize('call', ['readFileSync("code.js")','readFile("code.js","utf8")'])
def test_buffer_and_callback_reads_not_assumed_source_strings(call):
    report, _ = analyze(f'const fs=require("fs"); eval(fs.{call});',files={'/work/code.js':b'require("fs").rmSync("/etc",{recursive:true,force:true})'})
    assert 'execution-content-unavailable' in rules(report)
    assert 'delete-protected-root' not in rules(report)


def test_windows_paths_and_environment():
    report, _ = analyze('require("fs").unlinkSync(process.env.TARGET);',cwd=r'D:\work',env={'target':r'D:\work\a'})
    assert findings(report,'delete-inside')[0]['data']['target']==r'D:\work\a'


def test_public_json_contract_and_capability():
    analyzer=Analyzer(evidence=DisabledEvidenceProvider())
    assert analyzer.capabilities()['frontends']['javascript']
    assert 'javascript' in analyzer.capabilities()['bounded_value_tracking']
    assert json.loads(analyzer.analyze_javascript_json('console.log("hi")','/work'))=={}
    assert json.loads(analyze_javascript_json('console.log("hi")','/work'))=={}


def test_missing_parser_is_explicit(monkeypatch):
    analyzer=Analyzer(evidence=DisabledEvidenceProvider())
    analyzer.javascript_frontend=None
    assert rules(analyzer.analyze_javascript('require("fs").unlinkSync("a")','/work'))=={'analysis-unavailable'}
    assert 'analysis-unavailable' in rules(analyzer.analyze('node -e "console.log(1)"','/work',shell='bash'))


@pytest.mark.parametrize('command', ['node -e {code}', 'node -p {code}', "node <<'JS'\n{raw}\nJS"])
def test_shell_node_entrypoints(command):
    raw='require("fs").rmSync("/etc",{recursive:true,force:true})'
    report=Analyzer(evidence=DisabledEvidenceProvider()).analyze(command.format(code=shlex.quote(raw),raw=raw),'/work',shell='bash')
    assert 'delete-protected-root' in rules(report)


@pytest.mark.parametrize('source,expected', [
    ('const path=require("path"); fs.unlinkSync(path.join("/work", "/x"));','/work/x'),
    ('const path=require("path"); fs.unlinkSync(path.resolve("/work", "/x"));','/x'),
    ('fs.unlinkSync("a\\u002fb");','/work/a/b'),
    ('fs.unlinkSync("a\\x2fb");','/work/a/b'),
    ('fs.unlinkSync("a\\\\b");','/work/a\\b'),
])
def test_literal_path_semantics(source, expected):
    events=facts('const fs=require("fs");'+source)
    assert next(f for f in events if f.kind=='delete').targets==(expected,)


@pytest.mark.parametrize('expression', ['"/etc"','"build"'])
def test_dormant_body_context(expression):
    report,_=analyze(f'function clean(){{require("fs").rmSync({expression},{{recursive:true,force:true}})}}')
    assert all(f['data']['context']=='defined_body' for f in report.get('findings',[]))


def test_chdir_invalidates_all_relative_cwd_values():
    report,_=analyze('const fs=require("fs"); const p=process.cwd()+"/code.js"; eval(fs.readFileSync(p,"utf8")); process.chdir("elsewhere");',
                      files={'/work/code.js':b'require("fs").rmSync("/etc",{recursive:true,force:true})'})
    assert 'execution-content-unavailable' in rules(report)
    assert 'delete-protected-root' not in rules(report)


@pytest.mark.parametrize('limit', [1,2])
def test_value_count_overflow_is_not_truncated(limit):
    source='const fs=require("fs");let p="a";p="b";p="c";fs.unlinkSync(p);'
    report,_=analyze(source,config=AnalyzerConfig(possible_values=limit))
    assert 'delete-variable-unresolved' in rules(report)
    assert not findings(report,'delete-inside')


def test_value_byte_budget():
    report,_=analyze('const fs=require("fs"); const p="abcdefgh";fs.unlinkSync(p+p);',config=AnalyzerConfig(value_bytes=10))
    assert 'delete-variable-unresolved' in rules(report)


@pytest.mark.parametrize('source', [
    'const fs=require("fs"); eval(await fs.promises.readFile("code.js","utf8"));',
    'import {readFile} from "fs/promises"; eval(await readFile("code.js","utf8"));',
])
def test_awaited_promise_reads(source):
    report,_=analyze(source,files={'/work/code.js':b'require("fs").rmSync("/etc",{recursive:true,force:true})'})
    assert 'delete-protected-root' in rules(report)


def test_read_boundaries_do_not_follow_imports_or_dependencies():
    files={'/work/a.js':b'require("./b.js"); require("child_process").fork("b.js");',
           '/work/b.js':b'require("fs").rmSync("/etc",{recursive:true,force:true})'}
    provider=MemoryEvidenceProvider(files)
    report=Analyzer(evidence=provider).analyze('node a.js','/work',shell='bash')
    assert 'execution-content-unavailable' in rules(report)
    assert 'delete-protected-root' not in rules(report)


@pytest.mark.parametrize('call', ['require("child_process").fork("code.js")', 'require("child_process").spawnSync("node",["code.js"])'])
def test_node_children_read_direct_source(call):
    report,_=analyze(call,files={'/work/code.js':b'require("fs").rmSync("/etc",{recursive:true,force:true})'})
    assert 'delete-protected-root' in rules(report)


@pytest.mark.parametrize('call', ['openSync("x",flags)', 'createWriteStream("x")', 'writeFileSync("x.js","const =", "base64")'])
def test_unsupported_io_not_silent(call):
    report,_=analyze('require("fs").'+call)
    assert rules(report)&{'file-operation-unresolved','unresolved-value'}
    assert 'written-source-syntax-error' not in rules(report)


def test_literal_write_checks_authored_effects_at_none():
    source='require("fs").writeFileSync("x.js",'+json.dumps('require("fs").rmSync("/etc",{recursive:true,force:true})')+');'
    report,_=analyze(source,effort='none')
    assert findings(report,'delete-protected-root')[0]['data']['context']=='written_content'


def test_no_execution_or_ambient_environment(monkeypatch):
    import subprocess
    import os
    def forbidden(*args,**kwargs):
        raise AssertionError('submitted programs must not run')
    monkeypatch.setattr(subprocess,'Popen',forbidden)
    monkeypatch.setattr(os,'system',forbidden)
    monkeypatch.setenv('DELETE_TARGET','/etc')
    report,_=analyze('require("fs").rmSync(process.env.DELETE_TARGET,{recursive:true,force:true});')
    assert 'delete-variable-unresolved' in rules(report)


def test_repr_does_not_expose_source_secrets():
    parsed=JavaScriptFrontend().parse('const secret="password=hidden-example";')
    assert 'hidden-example' not in repr(parsed)


def test_ordinary_third_party_imports_and_calls_are_not_followed():
    assert analyze('const x=require("a-package"); x.run();')[0]=={}


@pytest.mark.parametrize('source', ['const x;', 'let x=1;let x=2;', 'switch(x){case 1:continue;}'])
def test_common_early_syntax_errors(source):
    assert JavaScriptFrontend().parse(source).diagnostics


def test_labeled_break_and_comments_are_supported():
    assert not JavaScriptFrontend().parse('label: {break label;}').diagnostics
    report,_=analyze('const fs=require(/*module*/"fs");fs.unlinkSync(/*target*/"file");')
    assert findings(report,'delete-inside')[0]['data']['target']=='/work/file'


def test_commonjs_top_level_return_not_reported_as_written_syntax_error():
    report,_=analyze('require("fs").writeFileSync("x.cjs","return;");')
    assert 'written-source-syntax-error' not in rules(report)


@pytest.mark.parametrize('constructor', ['Function','new Function'])
def test_dynamic_function_visible_invocation(constructor):
    body='require("fs").rmSync("/etc",{recursive:true,force:true})'
    report,_=analyze(f'{constructor}({json.dumps(body)})();')
    assert findings(report,'delete-protected-root')[0]['data']['context']=='invoked_now'


def test_dynamic_function_does_not_borrow_local_bindings():
    body='require("fs").unlinkSync(p)'
    report,_=analyze(f'const p="file";new Function({json.dumps(body)})();')
    assert 'delete-variable-unresolved' in rules(report)


def test_dynamic_function_writes_invalidate_previous_source_read():
    body='require("fs").writeFileSync("code.js","console.log(1)")'
    source='const fs=require("fs");eval(fs.readFileSync("code.js","utf8"));'+f'new Function({json.dumps(body)})();'
    report,_=analyze(source,files={'/work/code.js':b'require("fs").rmSync("/etc",{recursive:true,force:true})'})
    assert 'execution-content-unavailable' in rules(report)
    assert 'delete-protected-root' not in rules(report)


@pytest.mark.parametrize('command,args', [
    ('cmd',['/c',r'rd /s /q D:\Windows']),
    ('pwsh',['-Command',r'Remove-Item D:\Windows -Recurse -Force']),
    ('powershell',['-Command',r'Remove-Item D:\Windows -Recurse -Force']),
])
def test_node_launches_windows_interpreters(command,args):
    source=f'require("child_process").spawnSync({json.dumps(command)},{json.dumps(args)});'
    report,_=analyze(source,cwd=r'D:\work')
    assert 'unknown-command' not in rules(report)
    assert 'delete-protected-root' in rules(report)


@pytest.mark.parametrize('source,rule', [
    ('fetch("https://example.invalid")','network-request'),
    ('require("https").get("https://example.invalid")','network-request'),
    ('fetch("https://example.invalid",{headers:{Authorization:"Bearer example-token"}})','credentials-sent'),
    ('fetch("https://example.invalid",{method:"POST",body:require("fs").readFileSync("x","utf8")})','publish-risk'),
    ('process.kill(123,"SIGKILL")','force-process-termination'),
    ('require("fs").chmodSync("file",0o777)','permissions-too-broad'),
])
def test_additional_shared_effects(source,rule):
    assert rule in rules(analyze(source)[0])


def test_kill_zero_probe_is_quiet():
    assert analyze('process.kill(123,0)')[0]=={}


def test_value_tracking_metadata_and_redaction():
    source='let p="a";p="b";require("fs").unlinkSync(p);'
    report,_=analyze(source)
    assert len(findings(report,'delete-inside'))==2
    assert all(f['data'].get('possible') for f in report['findings'])
    report,_=analyze('const key="sk-1234567890abcdef0987654321";fetch("https://example.invalid",{headers:{Authorization:key}});')
    assert 'sk-1234567890abcdef0987654321' not in json.dumps(report)


def test_env_assignment_cannot_reuse_caller_binding():
    report,_=analyze('process.env.TARGET="b";require("fs").unlinkSync(process.env.TARGET);',env={'TARGET':'a'})
    assert 'delete-variable-unresolved' in rules(report)
    assert not findings(report,'delete-inside')


def test_fs_namespace_mutation_is_not_quiet():
    report,_=analyze('const fs=require("fs");fs.unlinkSync=other;fs.unlinkSync("file");')
    assert 'file-operation-unresolved' in rules(report)


def test_stream_write_invalidates_unresolved_reads():
    source='const fs=require("fs");eval(fs.readFileSync("code.js","utf8"));const handle=fs.createWriteStream("code.js");handle.write("new");'
    report,_=analyze(source,files={'/work/code.js':b'require("fs").rmSync("/etc",{recursive:true,force:true})'})
    assert 'execution-content-unavailable' in rules(report)
    assert 'delete-protected-root' not in rules(report)


def test_windows_write_outside_workspace():
    report,_=analyze('require("fs").writeFileSync("D:\\\\other\\\\x.txt","hi");',cwd=r'D:\work')
    assert 'write-outside-workspace' in rules(report)


def test_absolute_path_survives_unknown_cwd():
    report,_=analyze('process.chdir(getPath());require("fs").rmSync("/etc",{recursive:true,force:true});')
    assert 'delete-protected-root' in rules(report)


def test_literal_star_is_not_shell_expansion():
    report,_=analyze('require("fs").unlinkSync("*.js");')
    assert findings(report,'delete-inside')[0]['data']['target']=='/work/*.js'


def test_string_boolean_options_do_not_confirm_recursive_force():
    report,_=analyze('require("fs").rmSync("/etc",{recursive:"true",force:"true"});')
    assert 'delete-protected-root' not in rules(report)
    assert 'delete-recursion-unresolved' in rules(report)


def test_script_compilation_does_not_execute_writes():
    body='require("fs").writeFileSync("code.js","console.log(1)")'
    source='const fs=require("fs");new (require("vm").Script)('+json.dumps(body)+');eval(fs.readFileSync("code.js","utf8"));'
    report,_=analyze(source,files={'/work/code.js':b'require("fs").rmSync("/etc",{recursive:true,force:true})'})
    assert 'delete-protected-root' in rules(report)


def test_call_activation_budget_does_not_certify_unchanged_read():
    source='const fs=require("fs");eval(fs.readFileSync("code.js","utf8"));function a(){b()} function b(){fs.writeFileSync("code.js","console.log(1)")}a();'
    report,_=analyze(source,config=AnalyzerConfig(control_flow_steps=1),files={'/work/code.js':b'require("fs").rmSync("/etc",{recursive:true,force:true})'})
    assert 'delete-protected-root' not in rules(report)
    assert 'execution-content-unavailable' in rules(report)
