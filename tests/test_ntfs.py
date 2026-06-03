"""NTFS undelete mode tests against a synthetic volume."""

import hashlib
import json
import os
import subprocess
import sys

import pytest

import ntfs_builder
from carvx.ntfs import Volume, recover_ntfs
from carvx.reader import Reader

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture
def ntfs_image(tmp_path):
    path = tmp_path / "ntfs.img"
    _, expected = ntfs_builder.build(str(path))
    return str(path), expected


def test_volume_geometry(ntfs_image):
    path, _ = ntfs_image
    with Reader(path) as r:
        vol = Volume(r, 0)
        assert vol.cluster == 4096
        assert vol.rec_size == 1024
        assert vol.record_count == 67


def test_recovers_deleted_only(ntfs_image, tmp_path):
    path, expected = ntfs_image
    records, vol = recover_ntfs(path, 0, str(tmp_path / "out"))
    by_num = {r.offset: r for r in records}
    for num, (name, sha, size, deleted) in expected.items():
        if not deleted:
            assert num not in by_num, f"live file {name} wrongly recovered"
        else:
            r = by_num[num]
            assert r.size == size
            assert r.sha256 == sha
            assert r.name.endswith(name.lstrip("/"))
            assert r.deleted


def test_fragmented_file_reassembled(ntfs_image, tmp_path):
    """deleted-frag.bin spans two non-contiguous clusters."""
    path, expected = ntfs_image
    records, _ = recover_ntfs(path, 0, str(tmp_path / "out"))
    frag = next(r for r in records if r.name.endswith("deleted-frag.bin"))
    on_disk = hashlib.sha256(open(frag.path, "rb").read()).hexdigest()
    assert on_disk == frag.sha256
    assert frag.size == 4096 + 1000             # crosses cluster boundary


def test_timestamps_and_names(ntfs_image, tmp_path):
    path, _ = ntfs_image
    records, _ = recover_ntfs(path, 0, str(tmp_path / "out"))
    for r in records:
        assert r.timestamps["mtime"] > 0
        assert r.name


def test_dry_run_writes_nothing(ntfs_image, tmp_path):
    path, expected = ntfs_image
    out = tmp_path / "out"
    records, _ = recover_ntfs(path, 0, str(out), dry_run=True)
    assert len(records) == sum(1 for _, _, _, d in expected.values() if d)
    assert not out.exists()
    assert all(r.path == "" for r in records)


def test_partition_table_search(tmp_path):
    """Wrap the volume behind an MBR so --ntfs must find the partition."""
    inner = tmp_path / "vol.img"
    _, expected = ntfs_builder.build(str(inner))
    vol_bytes = inner.read_bytes()

    part_lba = 2048
    disk = bytearray(part_lba * 512 + len(vol_bytes))
    mbr = bytearray(512)
    mbr[510:512] = b"\x55\xaa"
    # one primary NTFS partition (type 0x07) starting at part_lba
    import struct
    struct.pack_into("<B", mbr, 446 + 4, 0x07)
    struct.pack_into("<I", mbr, 446 + 8, part_lba)
    struct.pack_into("<I", mbr, 446 + 12, len(vol_bytes) // 512)
    disk[0:512] = mbr
    disk[part_lba * 512:part_lba * 512 + len(vol_bytes)] = vol_bytes
    path = tmp_path / "disk.img"
    path.write_bytes(disk)

    records, vol = recover_ntfs(str(path), 0, str(tmp_path / "out"))
    names = {r.name.split("/")[-1] for r in records}
    assert "deleted-frag.bin" in names and "deleted-resident.txt" in names


def test_cli_ntfs_with_bodyfile(ntfs_image, tmp_path):
    path, expected = ntfs_image
    out = tmp_path / "out"
    body = tmp_path / "bodyfile"
    r = subprocess.run([sys.executable, "-m", "carvx", path, "--ntfs",
                        "-o", str(out), "--bodyfile", str(body), "-q"],
                       cwd=ROOT, capture_output=True)
    assert r.returncode == 0, r.stderr.decode()
    manifest = json.loads((out / "manifest.json").read_text())
    assert manifest["mode"] == "ntfs"
    # bodyfile: one line per recovered file, 11 pipe-delimited fields
    lines = [ln for ln in body.read_text().splitlines() if ln]
    assert lines and all(len(ln.split("|")) == 11 for ln in lines)


def test_non_ntfs_source_errors(tmp_path):
    path = tmp_path / "junk.img"
    path.write_bytes(os.urandom(1 << 20))
    with pytest.raises(ValueError):
        recover_ntfs(str(path), 0, str(tmp_path / "out"))
