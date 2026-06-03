"""FAT32 / exFAT undelete tests against real OS-formatted images.

Skips cleanly when the platform formatter/mounter is unavailable (e.g. Linux
CI without root). On macOS these run against newfs_msdos / newfs_exfat images.
"""

import hashlib
import os

import pytest

import fat_builder
from carvx.fat import recover_fat


def _check(kind, tmp_path):
    res = fat_builder.build(kind)
    if res is None:
        pytest.skip(f"{kind}: formatter/mounter unavailable on this platform")
    img, expected, deleted = res
    try:
        records, vol = recover_fat(img, 0, str(tmp_path / "out"))
    finally:
        pass
    # match recovered files by (size, sha256) since short-name mangling may
    # alter the displayed name for deleted 8.3 entries
    got = {(r.size, r.sha256): r for r in records}
    for name in deleted:
        sha, size = expected[name]
        assert (size, sha) in got, f"{kind}: {name} not recovered"
        r = got[(size, sha)]
        assert hashlib.sha256(open(r.path, "rb").read()).hexdigest() == sha
        assert r.deleted
    # the surviving file must not appear as deleted
    keep_sha, keep_size = expected["keep.txt"]
    keep = got.get((keep_size, keep_sha))
    assert keep is None or not keep.deleted
    os.unlink(img)
    return records


def test_fat32_undelete(tmp_path):
    records = _check("fat32", tmp_path)
    assert records


def test_exfat_undelete(tmp_path):
    records = _check("exfat", tmp_path)
    assert records


def test_long_filename_recovered(tmp_path):
    """The VFAT/exFAT long name should survive deletion (reconstructed from
    physical LFN order on FAT, name entries on exFAT)."""
    res = fat_builder.build("fat32")
    if res is None:
        pytest.skip("formatter unavailable")
    img, expected, _ = res
    try:
        records, _ = recover_fat(img, 0, str(tmp_path / "out"))
        sha, size = expected["LongFileName.txt"]
        rec = next(r for r in records if r.size == size and r.sha256 == sha)
        assert rec.name == "LongFileName.txt"
    finally:
        os.unlink(img)


def test_non_fat_source_errors(tmp_path):
    p = tmp_path / "junk.img"
    p.write_bytes(os.urandom(1 << 20))
    with pytest.raises(ValueError):
        recover_fat(str(p), 0, str(tmp_path / "out"))
