"""ext4 undelete tests.

Builds a real ext4 image with mke2fs + debugfs (from e2fsprogs) and deletes
files, then checks carvx recovers them by name + content. Skips cleanly if
e2fsprogs is not installed.
"""

import hashlib
import os
import shutil
import subprocess

import pytest

from carvx.ext4 import recover_ext4

# e2fsprogs ships in /usr/sbin on Linux, or Homebrew's keg on macOS.
_SEARCH = [os.environ.get("PATH", ""),
           "/opt/homebrew/opt/e2fsprogs/sbin",
           "/opt/homebrew/opt/e2fsprogs/bin",
           "/usr/sbin", "/sbin"]
os.environ["PATH"] = os.pathsep.join(p for p in _SEARCH if p)

MKE2FS = shutil.which("mke2fs")
DEBUGFS = shutil.which("debugfs")
pytestmark = pytest.mark.skipif(not (MKE2FS and DEBUGFS),
                                reason="e2fsprogs (mke2fs/debugfs) not installed")


@pytest.fixture
def ext4_image(tmp_path):
    stage = tmp_path / "stage"
    (stage / "docs").mkdir(parents=True)
    files = {
        "photo.jpg": bytes(range(256)) * 400,        # 100 KiB contiguous
        "notes.txt": b"deleted secret note\n" * 500,
        "docs/report.bin": os.urandom(300_000),       # multi-extent
        "keep.txt": b"i survive\n" * 10,              # NOT deleted
    }
    expected = {}
    for rel, data in files.items():
        (stage / rel).write_bytes(data)
        expected[rel] = hashlib.sha256(data).hexdigest()

    img = tmp_path / "ext4.img"
    img.write_bytes(b"\x00" * (16 << 20))
    subprocess.run([MKE2FS, "-F", "-q", "-t", "ext4", "-b", "1024",
                    "-d", str(stage), str(img)], check=True,
                   capture_output=True)
    for rel in ("photo.jpg", "notes.txt", "docs/report.bin"):
        subprocess.run([DEBUGFS, "-w", "-R", f"rm /{rel}", str(img)],
                       check=True, capture_output=True)
    return str(img), expected


def test_recovers_deleted_with_names_and_content(ext4_image, tmp_path):
    path, expected = ext4_image
    records, vol = recover_ext4(path, 0, str(tmp_path / "out"))
    by_name = {r.name.lstrip("/"): r for r in records}

    for rel in ("photo.jpg", "notes.txt", "docs/report.bin"):
        assert rel in by_name, f"{rel} not recovered (got {list(by_name)})"
        r = by_name[rel]
        assert r.sha256 == expected[rel], f"{rel} content mismatch"
        assert hashlib.sha256(open(r.path, "rb").read()).hexdigest() == expected[rel]
        assert r.deleted
        assert r.timestamps["mtime"] > 0

    # live file must not be recovered (no include_live)
    assert "keep.txt" not in by_name


def test_multi_extent_file_reassembled(ext4_image, tmp_path):
    path, expected = ext4_image
    records, _ = recover_ext4(path, 0, str(tmp_path / "out"))
    big = next(r for r in records if r.name.endswith("report.bin"))
    assert big.size == 300_000
    assert big.sha256 == expected["docs/report.bin"]


def test_dry_run_writes_nothing(ext4_image, tmp_path):
    path, _ = ext4_image
    out = tmp_path / "out"
    records, _ = recover_ext4(path, 0, str(out), dry_run=True)
    assert records
    assert not out.exists()
    assert all(r.path == "" for r in records)


def test_non_ext_source_errors(tmp_path):
    p = tmp_path / "junk.img"
    p.write_bytes(os.urandom(1 << 20))
    with pytest.raises(ValueError):
        recover_ext4(str(p), 0, str(tmp_path / "out"))
