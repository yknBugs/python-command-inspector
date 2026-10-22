import pytest
from command_inspector import Analyzer
from command_inspector.local_evidence import MemoryEvidenceProvider


@pytest.mark.parametrize("command,expected", [
    ("grep hello notes", set()),
    ("rg hello notes", set()),
    ("grep password secrets", {"credentials-read"}),
    ("grep -F hello secrets", set()),
    ("rg -F hello secrets", set()),
    ("grep -F password secrets", {"credentials-read"}),
    ("grep -Fi PASSWORD secrets", {"credentials-read"}),
    ("grep -l password secrets", set()),
    ("rg -c password secrets", set()),
    ("grep -q password secrets", set()),
])
def test_search_selection(command, expected):
    provider = MemoryEvidenceProvider({"/work/notes": "hello", "/work/secrets": "hello\npassword=abcdefg\n"})
    result = Analyzer(evidence=provider).analyze(command, "/work", shell="bash")
    assert {f["rule"] for f in result.get("findings", [])} == expected


def test_regular_expression_selection_is_conservative():
    provider = MemoryEvidenceProvider({"/work/secrets": "password=abcdefg"})
    result = Analyzer(evidence=provider).analyze("grep unknown secrets", "/work", shell="bash")
    finding = result["findings"][0]
    assert "may expose" in finding["title"]
    assert finding["data"]["selection"] == "conservative"
