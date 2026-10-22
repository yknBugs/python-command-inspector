"""Static disk-command fixtures; no disk utility is executed."""
import os
import subprocess

import pytest

from command_inspector import Analyzer
from command_inspector.local_evidence import DisabledEvidenceProvider, MemoryEvidenceProvider
from command_inspector.shared.builtins import command_registry


@pytest.fixture(autouse=True)
def forbid_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('Submitted disk utility was executed')
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    monkeypatch.setattr(os, 'system', forbidden)


def analyze(command, **kwargs):
    return Analyzer(evidence=DisabledEvidenceProvider()).analyze(command, '/work', shell='bash', **kwargs)


def rules(report):
    return {f['rule'] for f in report.get('findings', [])}


@pytest.mark.parametrize('command', [
    'lsblk', 'lsblk -f', 'lsblk -J -o NAME,SIZE,FSTYPE,MOUNTPOINTS',
    'lsblk -dnpo NAME,SIZE /dev/sda', 'lsblk --output=NAME --tree=NAME',
    'lsblk -D --discard --paths --json', 'lsblk --list-columns',
    'lsblk --filter \'TYPE=="disk"\' --ct DiskCount',
    'lsblk --hyperlink=never --properties-by=udev,blkid',
    'fdisk -l', 'fdisk --list /dev/sda /dev/nvme0n1',
    'fdisk -lx /dev/sda', 'fdisk -s /dev/sda',
    'fdisk --list --wipe=always /dev/sda',
    'fdisk -l -u=cylinders -c=dos --color=never --lock=nonblock /dev/sda',
    'wipefs /dev/sda', 'wipefs -f /dev/sda', 'wipefs -J -O DEVICE,OFFSET /dev/sda',
    'wipefs -an /dev/sda', 'wipefs --all --no-act /dev/sda',
    'wipefs --offset=0x438 --no-act /dev/sda',
    'wipefs --help', 'fdisk --version', 'lsblk --help',
])
def test_inspection_modes_are_quiet(command):
    assert analyze(command) == {}


@pytest.mark.parametrize('command,target', [
    ('wipefs -a /dev/sda','/dev/sda'),
    ('wipefs --all --force /dev/nvme0n1','/dev/nvme0n1'),
    ('wipefs -af /dev/mmcblk0p1','/dev/mmcblk0p1'),
    ('wipefs -o0x438 /dev/sda1','/dev/sda1'),
    ('wipefs --offset 0x438 --offset 0x1000 /dev/sda','/dev/sda'),
    ('wipefs --all --lock=nonblock /dev/sda','/dev/sda'),
    ('wipefs --all --backup=/tmp /dev/sda','/dev/sda'),
    ('wipefs --all --backup /dev/sda','/dev/sda'),
    ('DEVICE=/dev/sda; wipefs -a "$DEVICE"','/dev/sda'),
    ('sudo wipefs -a /dev/sda','/dev/sda'),
])
def test_explicit_wipe_is_raw_device_write(command, target):
    report=analyze(command)
    selected=[f for f in report['findings'] if f['rule']=='raw-device-write']
    assert len(selected)==1
    assert selected[0]['level']=='BLOCK'
    assert selected[0]['data']['target']==target
    assert not rules(report)&{'tool-invoked','unknown-command'}


@pytest.mark.parametrize('command', [
    'wipefs -a "$DEVICE"', 'wipefs -a', 'wipefs -o', 'wipefs --wat /dev/sda',
    'wipefs "$OPTIONS" /dev/sda', 'fdisk', 'fdisk "$DEVICE"', 'fdisk --wat /dev/sda',
    'lsblk --output', 'lsblk --wat', 'lsblk "$FLAGS"',
])
def test_incomplete_or_unknown_arguments_are_visible(command):
    report=analyze(command,env={})
    assert rules(report)&{'unresolved-value','file-operation-unresolved','unknown-option'}
    assert 'raw-device-write' not in rules(report)


@pytest.mark.parametrize('command', [
    'fdisk /dev/sda', 'fdisk -w always /dev/sda',
    'fdisk --wipe never --protect-boot /dev/sda',
    "printf 'd\\nw\\n' | fdisk /dev/sda",
    "fdisk /dev/sda <<'END'\nq\nEND",
])
def test_dialog_does_not_claim_confirmed_write(command):
    report=analyze(command)
    assert 'file-operation-unresolved' in rules(report)
    assert not rules(report)&{'raw-device-write','volume-format','unknown-command','tool-invoked'}


def test_multiple_wipe_targets_and_disk_image():
    report=analyze('wipefs -a /dev/sda /dev/sdb disk.img')
    assert {f['data']['target'] for f in report['findings'] if f['rule']=='raw-device-write'}=={'/dev/sda','/dev/sdb'}
    assert analyze('wipefs -a disk.img')=={}


def test_option_terminator_keeps_dash_operand_literal():
    assert analyze('wipefs -a -- --no-act')=={}
    assert 'raw-device-write' in rules(analyze('wipefs -a -- /dev/sda'))


def test_image_write_and_dialog_invalidate_source_evidence():
    for command in ('wipefs -a code.py','fdisk code.py'):
        provider=MemoryEvidenceProvider({'/work/code.py':b'print("old")'})
        report=Analyzer(evidence=provider).analyze(command+'; python code.py','/work',shell='bash')
        assert 'execution-content-unavailable' in rules(report)


def test_models_replace_known_tool_fallback():
    from command_inspector import known_tools
    registry=command_registry()
    for name in ('wipefs','fdisk','lsblk'):
        assert registry.supports(name,'bash')
        assert not registry.supports(name,'cmd')
    # A registry model, not a broad software category, supplies the meaning.
    from pathlib import Path
    text=Path(known_tools.__file__).read_text(encoding='utf-8')
    assert all('"'+name+'":' not in text for name in ('wipefs','fdisk','lsblk'))


@pytest.mark.parametrize('target', ['/dev/loop0','/dev/md0','/dev/dm-0','/dev/mapper/data','/dev/disk/by-id/example'])
def test_named_linux_device_namespaces(target):
    assert 'raw-device-write' in rules(analyze('wipefs -a '+target))


@pytest.mark.parametrize('options', ['-a --backup --no-act','-anb/tmp','-a -b/tmp -n'])
def test_no_act_still_exposes_backup_output(options):
    report=analyze('wipefs '+options+' /dev/sda')
    assert 'raw-device-write' not in rules(report)
    assert 'file-operation-unresolved' in rules(report)


def test_short_optional_backup_argument_is_not_a_no_act_flag():
    assert 'raw-device-write' in rules(analyze('wipefs -abn /dev/sda'))
    assert 'raw-device-write' in rules(analyze('wipefs -ab/tmp /dev/sda'))


def test_read_options_do_not_modify_following_evidence():
    for command in ('wipefs code.py','wipefs -an code.py','fdisk -l code.py','lsblk'):
        provider=MemoryEvidenceProvider({'/work/code.py':b'print("old")'})
        report=Analyzer(evidence=provider).analyze(command+'; python code.py','/work',shell='bash')
        assert 'execution-content-unavailable' not in rules(report)
