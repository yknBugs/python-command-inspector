"""Android/Termux lexical protections; no device or command is accessed."""
import os
import subprocess

import pytest

from command_inspector import Analyzer, AnalyzerConfig
from command_inspector.local_evidence import MemoryEvidenceProvider, ReadFile


CWD = "/data/data/com.termux/files/home/project"
ROOTS = ["/system", "/system_ext", "/vendor", "/product", "/odm", "/apex", "/metadata", "/dev"]
DEVICES = ["/dev/block/mmcblk0", "/dev/block/mmcblk0p12", "/dev/block/sda", "/dev/block/dm-0",
           "/dev/block/by-name/system", "/dev/block/by-name/boot_a", "/dev/block/mapper/system_a",
           "/dev/block/platform/soc/1d84000.ufshc/by-name/vendor"]


@pytest.fixture(autouse=True)
def no_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Analyzer executed proposed command or accessed device")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "system", forbidden)
    monkeypatch.setattr(os, "open", forbidden)


def analyze(command, *, effort="Full", files=None, config=None):
    provider = MemoryEvidenceProvider(files or {})
    report = Analyzer(config, evidence=provider).analyze_report(command, CWD, effort=effort)
    return report, provider


@pytest.mark.parametrize("root", ROOTS)
@pytest.mark.parametrize("effort", ["Full", "Partial", "None"])
def test_android_system_roots_block_force_recursive_deletion(root, effort):
    report, _ = analyze("rm -rf " + root + "/", effort=effort)
    finding, = [f for f in report.findings if f.rule == "delete-protected-root"]
    assert finding.level.name == "BLOCK" and finding.data["target"] == root


@pytest.mark.parametrize("root", ROOTS)
def test_android_whole_directory_wildcards_retain_block(root):
    report, _ = analyze("rm -rf " + root + "/*", effort="Partial", files={root + "/child": "x"})
    finding, = [f for f in report.findings if f.rule == "delete-protected-root"]
    assert finding.data["matched_targets"] == [root + "/child"]
    assert finding.data["files"] == 1 and "logical_bytes" not in finding.data


@pytest.mark.parametrize("root", ROOTS)
def test_android_roots_keep_existing_self_match_and_nonrecursive_levels(root):
    report, _ = analyze("rm -r " + root, effort="None")
    assert report.level.name == "MEDIUM"
    assert report.findings[0].rule == "delete-outside-workspace"
    report, _ = analyze("rm -rf " + root + "/ordinary-child", effort="None")
    assert report.level.name == "MEDIUM" and report.findings[0].rule == "delete-outside-workspace"
    report, _ = analyze("rm -rf " + root + "-backup", effort="None")
    assert report.level.name == "MEDIUM"


def test_explicit_protection_configuration_replaces_android_presets():
    config = AnalyzerConfig.from_mapping({"protected": {"directories": [{"path": "/custom"}]}})
    report, _ = analyze("rm -rf /system", config=config, effort="None")
    assert report.level.name == "MEDIUM"
    report, _ = analyze("rm -rf /custom", config=config, effort="None")
    assert report.level.name == "BLOCK"


@pytest.mark.parametrize("device", DEVICES)
@pytest.mark.parametrize("effort", ["Full", "Partial", "None"])
def test_android_dd_writes_block_without_device_reads(device, effort):
    report, provider = analyze("dd of=" + device + " bs=4096 count=1", effort=effort)
    finding, = report.findings
    assert finding.rule == "raw-device-write" and finding.level.name == "BLOCK"
    assert finding.data["target"] == device
    assert provider.queries == []


@pytest.mark.parametrize("device", DEVICES)
def test_android_dd_reads_are_high_without_device_reads(device):
    report, provider = analyze("dd if=" + device)
    finding, = report.findings
    assert finding.rule == "raw-device-read" and finding.level.name == "HIGH"
    assert provider.queries == []


@pytest.mark.parametrize("command", [
    "printf text > /dev/block/by-name/system", "cat /dev/block/by-name/system",
    "dd of=/dev/block/by-name/../by-name/system", "dd of=/dev/block/platform/soc/by-name/boot",
    "D=/dev/block/by-name/system; dd of=$D",
    "cd /dev/block && dd of=by-name/system",
    "sudo dd of=/dev/block/by-name/system", "su -c 'dd of=/dev/block/by-name/system'",
])
def test_android_device_protection_is_shared_by_operations_and_wrappers(command):
    report, provider = analyze(command)
    assert {f.rule for f in report.findings} & {"raw-device-write", "raw-device-read"}
    assert not any(isinstance(q, ReadFile) and q.path.startswith("/dev/block/") for q in provider.queries)


@pytest.mark.parametrize("path", ["/dev/blockade/system", "/tmp/dev/block/system", "/dev/block", "/dev/blocks/system"])
def test_similar_paths_are_not_raw_block_devices(path):
    report, _ = analyze("dd of=" + path, effort="None")
    assert "raw-device-write" not in {f.rule for f in report.findings}


@pytest.mark.parametrize("command", ["dd of=/dev/block/by-name/system", "printf text > /dev/block/by-name/system"])
def test_raw_device_writes_invalidate_later_disk_evidence(command):
    report, provider = analyze(command + "; bash later.sh", files={CWD + "/later.sh": "rm -rf /system"})
    assert "raw-device-write" in {f.rule for f in report.findings}
    assert "execution-content-unavailable" in {f.rule for f in report.findings}
    assert "delete-protected-root" not in {f.rule for f in report.findings}
    assert not any(isinstance(q, ReadFile) for q in provider.queries)


def test_existing_null_device_semantics_survive_dev_root_protection():
    for command in ("echo text > /dev/null", "cat /dev/null", "dd of=/dev/null"):
        report, _ = analyze(command)
        assert report.to_dict() == {}
