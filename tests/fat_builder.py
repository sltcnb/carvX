"""Build real FAT32 / exFAT images by driving the OS formatter + mounter,
populating files, deleting them, and unmounting. Returns (image_path, expected
{name: (sha256, size)}). Skips (returns None) if the tools are unavailable.

macOS: newfs_msdos / newfs_exfat + hdiutil + diskutil.
Linux:  mkfs.vfat / mkfs.exfat + a loop mount (needs root; usually skipped).
"""

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import time


def _run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def _macos_build(kind: str, files: dict, delete: list):
    if not (shutil.which("hdiutil") and shutil.which("diskutil")):
        return None
    newfs = "/sbin/newfs_exfat" if kind == "exfat" else "/sbin/newfs_msdos"
    if not os.path.exists(newfs):
        return None
    img = tempfile.mktemp(suffix=f"_{kind}.img")
    with open(img, "wb") as fh:
        fh.truncate(48 << 20)
    dev = None
    try:
        r = _run(["hdiutil", "attach", "-nomount", img])
        if r.returncode != 0:
            return None
        dev = r.stdout.split()[0]
        fmt = ([newfs, "-v", "CARVX", dev] if kind == "exfat"
               else [newfs, "-F", "32", "-v", "CARVX", dev])
        if _run(fmt).returncode != 0:
            return None
        _run(["diskutil", "mount", dev])
        info = _run(["diskutil", "info", dev]).stdout
        mnt = ""
        for line in info.splitlines():
            if "Mount Point" in line:
                mnt = line.split(":", 1)[1].strip()
        if not mnt or not os.path.isdir(mnt):
            return None
        expected = {}
        for name, data in files.items():
            with open(os.path.join(mnt, name), "wb") as fh:
                fh.write(data)
            expected[name] = (hashlib.sha256(data).hexdigest(), len(data))
        _run(["sync"])
        for name in delete:
            try:
                os.unlink(os.path.join(mnt, name))
            except OSError:
                pass
        _run(["sync"])
        time.sleep(0.3)
        _run(["diskutil", "unmount", dev])
        return img, expected, set(delete)
    finally:
        if dev:
            _run(["hdiutil", "detach", dev])


def build(kind: str):
    """kind in {'fat32','exfat'}. Returns (img, expected, deleted_names) or None."""
    files = {
        "photo.jpg": bytes(range(256)) * 400,            # 100 KiB
        "LongFileName.txt": b"fat deleted note\n" * 600,
        "data.bin": os.urandom(250_000),
        "keep.txt": b"survive\n" * 5,                    # not deleted
    }
    delete = ["photo.jpg", "LongFileName.txt", "data.bin"]
    if sys.platform == "darwin":
        return _macos_build("exfat" if kind == "exfat" else "fat32", files, delete)
    return None


if __name__ == "__main__":
    for k in ("fat32", "exfat"):
        res = build(k)
        if res is None:
            print(f"{k}: tools unavailable, skipped")
            continue
        img, exp, deleted = res
        print(f"{k}: {img}")
        for n, (h, s) in exp.items():
            print(f"  {n} {s}B deleted={n in deleted}")
