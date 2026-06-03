"""HFS+ and APFS recovery tests against real macOS-formatted images.

Skip cleanly when not on macOS or the formatters are unavailable.
HFS+ deleted catalog records are frequently journaled away on a clean unmount,
so the HFS+ test asserts live-file recovery + that the deleted scan runs;
APFS (copy-on-write) reliably retains deleted file records, so its test
asserts byte-exact recovery of the deleted files.
"""

import hashlib
import os

import pytest

import mac_fs_builder
from carvx.apfs import recover_apfs
from carvx.hfsplus import recover_hfs


# ---------------------------------------------------------------- HFS+

def test_hfs_recovers_live_files(tmp_path):
    res = mac_fs_builder.build_hfs()
    if res is None:
        pytest.skip("HFS+ formatter unavailable")
    img, expected, deleted = res
    try:
        records, vol = recover_hfs(img, 0, str(tmp_path / "out"),
                                   include_live=True)
        by_name = {r.name.split("/")[-1]: r for r in records}
        # keep.txt is live and must come back byte-exact
        sha, size = expected["keep.txt"]
        assert "keep.txt" in by_name
        assert by_name["keep.txt"].sha256 == sha
        # deleted scan ran without error (records list is well-formed)
        assert all(r.size >= 0 for r in records)
    finally:
        os.unlink(img)


# ---------------------------------------------------------------- APFS

def test_apfs_recovers_deleted_byte_exact(tmp_path):
    res = mac_fs_builder.build_apfs()
    if res is None:
        pytest.skip("APFS formatter unavailable")
    img, expected, deleted = res
    try:
        records, cont = recover_apfs(img, 0, str(tmp_path / "out"))
        by_hash = {r.sha256: r for r in records}
        for name in deleted:
            sha, size = expected[name]
            assert sha in by_hash, f"{name} not recovered from APFS CoW scan"
            r = by_hash[sha]
            assert r.size == size
            assert hashlib.sha256(open(r.path, "rb").read()).hexdigest() == sha
        # names recovered from DIR_REC
        names = {r.name.split("/")[-1] for r in records}
        assert "photo.jpg" in names
    finally:
        os.unlink(img)


def test_apfs_non_container_errors(tmp_path):
    p = tmp_path / "junk.img"
    p.write_bytes(os.urandom(1 << 20))
    with pytest.raises(ValueError):
        recover_apfs(str(p), 0, str(tmp_path / "out"))
