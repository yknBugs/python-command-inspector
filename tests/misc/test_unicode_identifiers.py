"""PowerShell allows Unicode letters in names, properties and hashtable keys."""
import pytest
from command_inspector import Analyzer
from command_inspector.local_evidence import DisabledEvidenceProvider


def analyze(command):
    return Analyzer(evidence=DisabledEvidenceProvider()).analyze(
        command, "D:\\work", shell="powershell")


@pytest.mark.parametrize("command", [
    "[pscustomobject]@{ 类型='目录'; 名称=$_.Name; MB=[math]::Round(1,1) }",
    "$中文 = 1; Write-Output $中文",
    "Get-ChildItem | Where-Object { $_.名称 -eq 'x' }",
    "foreach ($文件 in $列表) { $文件 }",
    "@{ 类型=1; 名称=2 } | ConvertTo-Json",
])
def test_unicode_identifiers_parse_without_diagnostics(command):
    assert not Analyzer().parse(command, shell="powershell").diagnostics


def test_unicode_hashtable_key_is_not_reported_as_a_command():
    report = analyze("[pscustomobject]@{ 类型='目录'; 名称=$_.Name; MB=[math]::Round(1,1) }")
    assert not report.get("findings")
    assert report.get("level", "NONE") == "NONE"


def test_folded_retry_does_not_change_ascii_only_input():
    command = "[pscustomobject]@{ a=1; b=[math]::Round(2,1) }"
    assert not Analyzer().parse(command, shell="powershell").diagnostics
    assert not analyze(command).get("findings")


@pytest.mark.parametrize('name,other', [('é', 'ZZ'), ('中', 'ZZZ'), ('中文', '另一'), ('имя', 'ZZZZZZ')])
def test_parser_placeholders_never_become_binding_keys(name, other):
    command = f'${name}="C:\\Windows"; ${other}="D:\\work\\safe"; Remove-Item ${name} -Recurse -Force'
    result = analyze(command)
    assert any(f['rule'] == 'delete-protected-root' for f in result['findings'])
    reverse = f'${name}="D:\\work\\safe"; ${other}="C:\\Windows"; Remove-Item ${name} -Recurse -Force'
    assert not any(f['rule'] == 'delete-protected-root' for f in analyze(reverse).get('findings', []))


def test_unicode_tree_preserves_original_text_and_character_spans():
    command = "$中文='路径'; @{ 名称=$中文; ZZZZZZ='other' }"
    parsed = Analyzer().parse(command, shell='powershell')
    assert not parsed.diagnostics
    pending = [parsed.root]
    variables = []
    while pending:
        node = pending.pop()
        assert node.text == command[node.span.start:node.span.end]
        if node.kind == 'variable':
            variables.append(node.text)
        pending.extend(node.children)
    assert variables and set(variables) == {'$中文'}


def test_unicode_retry_does_not_hide_unrelated_syntax_errors():
    assert Analyzer().parse('$中文=1; if (', shell='powershell').diagnostics


def test_identifier_copy_preserves_unicode_punctuation_and_byte_offsets():
    from command_inspector.pwsh.syntax import _identifier_parse_copy
    raw = '$中文=“text”;\u00a0# punctuation: —'.encode('utf-8')
    masked = _identifier_parse_copy(raw)
    assert len(raw) == len(masked)
    assert masked.decode('utf-8') == '$ZZZZZZ=“text”;\u00a0# punctuation: —'
