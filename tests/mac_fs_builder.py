"""Build real HFS+ and APFS images on macOS (newfs_hfs / diskutil + newfs_apfs),
populate, delete files, and detach. Returns (image_path, expected, deleted) or
None when the platform/tools are unavailable (non-macOS, or no privileges).
"""

import hashlib
import os
import re
import subprocess
import sys
import tempfile
import time


def _run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


FILES = {
    "photo.jpg": bytes(range(256)) * 400,        # 100 KiB, block-aligned
    "data.bin": None,                            # filled with deterministic bytes
    "keep.txt": b"survive\n" * 5,
}
DELETE = ["photo.jpg", "data.bin"]


def _payloads():
    import random
    files = dict(FILES)
    files["data.bin"] = random.Random(99).randbytes(250000)
    return files


def _attach(img):
    r = _run(["hdiutil", "attach", "-nomount", img])
    if r.returncode != 0:
        return None
    return r.stdout.split()[0]


def _detach(dev):
    _run(["hdiutil", "detach", dev])


def build_hfs():
    if sys.platform != "darwin" or not os.path.exists("/sbin/newfs_hfs"):
        return None
    files = _payloads()
    img = tempfile.mktemp(suffix="_hfs.img")
    with open(img, "wb") as fh:
        fh.truncate(48 << 20)
    dev = _attach(img)
    if not dev:
        return None
    try:
        if _run(["/sbin/newfs_hfs", "-v", "CARVX", dev]).returncode != 0:
            return None
        _run(["diskutil", "mount", dev])
        mnt = _mount_point(dev)
        if not mnt:
            return None
        expected = _populate_delete(mnt, files)
        time.sleep(0.3)
        _run(["diskutil", "unmount", dev])
        return img, expected, set(DELETE)
    finally:
        _detach(dev)


def build_apfs():
    if sys.platform != "darwin" or not os.path.exists("/sbin/newfs_apfs"):
        return None
    files = _payloads()
    img = tempfile.mktemp(suffix="_apfs.img")
    with open(img, "wb") as fh:
        fh.truncate(128 << 20)
    dev = _attach(img)
    if not dev:
        return None
    syn = None
    try:
        r = _run(["diskutil", "partitionDisk", dev, "GPT", "APFS", "CARVX", "100%"])
        if r.returncode != 0:
            return None
        # find the synthesized APFS volume (diskN s1 -> a separate synthesized disk)
        time.sleep(1)
        vol = _find_apfs_volume()
        if not vol:
            return None
        syn = vol.rstrip("s1")
        mnt = _mount_point(vol) or (_run(["diskutil", "mount", vol]) and _mount_point(vol))
        if not mnt:
            return None
        expected = _populate_delete(mnt, files)
        time.sleep(0.5)
        _run(["diskutil", "unmount", vol])
        return img, expected, set(DELETE)
    finally:
        if syn:
            _detach(syn)
        _detach(dev)


def _find_apfs_volume():
    out = _run(["diskutil", "list"]).stdout
    # look for an APFS Volume CARVX line -> its disk identifier
    for line in out.splitlines():
        if "CARVX" in line and "APFS Volume" in line:
            m = re.search(r"(disk\d+s\d+)\s*$", line.strip())
            if m:
                return "/dev/" + m.group(1)
    return None


def _mount_point(dev):
    info = _run(["diskutil", "info", dev]).stdout
    for line in info.splitlines():
        if "Mount Point" in line:
            mp = line.split(":", 1)[1].strip()
            if mp and os.path.isdir(mp):
                return mp
    return None


def _populate_delete(mnt, files):
    expected = {}
    for name, data in files.items():
        with open(os.path.join(mnt, name), "wb") as fh:
            fh.write(data)
        expected[name] = (hashlib.sha256(data).hexdigest(), len(data))
    _run(["sync"])
    for name in DELETE:
        try:
            os.unlink(os.path.join(mnt, name))
        except OSError:
            pass
    _run(["sync"])
    return expected


if __name__ == "__main__":
    for fn in (build_hfs, build_apfs):
        res = fn()
        print(fn.__name__, "->", "skipped" if res is None else res[0])
        if res:
            for n, (h, s) in res[1].items():
                print(f"   {n} {s}B deleted={n in res[2]}")
            os.unlink(res[0])
