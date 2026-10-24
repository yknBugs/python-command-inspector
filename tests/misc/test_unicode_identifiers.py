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
