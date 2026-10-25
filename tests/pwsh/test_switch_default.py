"""Default is exhaustive over nonempty input, not over an empty stream."""
import pytest
from command_inspector import Analyzer
from command_inspector.pwsh.semantics import PowerShellBuilder
from command_inspector.shared.value_flow import candidates


def assigned(source):
    builder = PowerShellBuilder(r'C:\work', {})
    builder.build(Analyzer().parse(source, shell='powershell').root)
    return {v.text for v in candidates(builder.variables['a'])}


SWITCH = r"$a='C:\safe'; switch ($c) {1 {$a='C:\a'} default {$a='C:\b'}}"


@pytest.mark.parametrize('prefix', [
    "$c='1'; ", "$c='2'; ",
    "if ($flag) {$c='1'} else {$c='2'}; ",
    "$c=@('1','2'); ",
])
def test_default_removes_entry_path_for_known_nonempty_input(prefix):
    assert assigned(prefix + SWITCH) == {r'C:\a', r'C:\b'}


@pytest.mark.parametrize('prefix', ['', '$c=@(); ', '$c=Get-ChildItem; '])
def test_unknown_or_empty_input_keeps_possible_unvisited_entry(prefix):
    assert r'C:\safe' in assigned(prefix + SWITCH)


def test_without_default_keeps_no_match_path():
    assert r'C:\safe' in assigned(r"$c=2; $a='C:\safe'; switch ($c) {1 {$a='C:\a'}}")


def test_default_body_can_preserve_the_old_value():
    assert assigned(r"$c=2; $a='C:\safe'; switch ($c) {1 {$a='C:\a'} default {Write-Output ok}}") == {r'C:\safe', r'C:\a'}


def test_default_first_and_commented_label_is_recognized():
    assert assigned(r"$c=2; $a='C:\safe'; switch ($c) {<#comment#> default {$a='C:\b'} 1 {$a='C:\a'}}") == {r'C:\a', r'C:\b'}
