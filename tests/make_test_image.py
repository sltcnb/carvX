"""Build a synthetic disk image with known files at known offsets,
run carvx over it, and verify recovered files hash-match the originals.

Usage: python3 tests/make_test_image.py
"""

import gzip
import hashlib
import io
import json
import os
import random
import sqlite3
import struct
import subprocess
import sys
import tempfile
import zipfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


# ---------------------------------------------------------------- builders

def make_png() -> bytes:
    """Minimal valid PNG: 8x8 gray image."""
    def chunk(ctype, data):
        return (struct.pack(">I", len(data)) + ctype + data
                + struct.pack(">I", zlib.crc32(ctype + data)))
    ihdr = struct.pack(">IIBBBBB", 8, 8, 8, 0, 0, 0, 0)
    raw = b"".join(b"\x00" + bytes([i * 30 % 256] * 8) for i in range(8))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


def make_jpeg() -> bytes:
    """Structurally valid JPEG (marker walk + entropy + EOI)."""
    app0 = b"\xff\xe0" + struct.pack(">H", 16) + b"JFIF\x00\x01\x02\x00\x00\x01\x00\x01\x00\x00"
    dqt = b"\xff\xdb" + struct.pack(">H", 67) + b"\x00" + bytes(range(1, 65))
    sof = b"\xff\xc0" + struct.pack(">H", 11) + b"\x08\x00\x08\x00\x08\x01\x01\x11\x00"
    dht = b"\xff\xc4" + struct.pack(">H", 19) + b"\x00" + bytes(16)
    entropy = bytes(b if b != 0xFF else 0xFE for b in os.urandom(400))
    sos = b"\xff\xda" + struct.pack(">H", 8) + b"\x01\x01\x00\x00\x3f\x00"
    return b"\xff\xd8" + app0 + dqt + sof + dht + sos + entropy + b"\xff\xd9"


def make_gif() -> bytes:
    """Minimal valid GIF89a, 2x2."""
    lsd = struct.pack("<HHBBB", 2, 2, 0x80, 0, 0)   # global color table, 2 entries
    gct = b"\x00\x00\x00\xff\xff\xff"
    img = b"\x2c" + struct.pack("<HHHHB", 0, 0, 2, 2, 0)
    lzw = b"\x02\x02\x4c\x01\x00"                   # min code + 1 sub-block + terminator
    return b"GIF89a" + lsd + gct + img + lzw + b"\x3b"


def make_bmp() -> bytes:
    row = b"\x00\x00\xff" + b"\x00"                 # 1px BGR + pad to 4
    pixels = row * 4
    size = 14 + 40 + len(pixels)
    return (b"BM" + struct.pack("<IHHI", size, 0, 0, 54)
            + struct.pack("<IiiHHIIiiII", 40, 1, 4, 1, 24, 0, len(pixels), 2835, 2835, 0, 0)
            + pixels)


def make_pdf() -> bytes:
    return (b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"
            b"xref\n0 2\ntrailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n9\n%%EOF\n")


def make_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("hello.txt", "hello carvx " * 50)
        z.writestr("dir/data.bin", os.urandom(1000))
    return buf.getvalue()


def make_docx_like() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", "<w:document/>")
    return buf.getvalue()


def make_gzip() -> bytes:
    return gzip.compress(b"carvx gzip payload " * 200)


def make_sqlite() -> bytes:
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.unlink(path)
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE t (a INTEGER, b TEXT)")
    con.executemany("INSERT INTO t VALUES (?, ?)", [(i, "x" * 50) for i in range(200)])
    con.commit()
    con.close()
    with open(path, "rb") as fh:
        data = fh.read()
    os.unlink(path)
    return data


def make_mp4() -> bytes:
    def box(btype, payload):
        return struct.pack(">I", len(payload) + 8) + btype + payload
    return (box(b"ftyp", b"isom\x00\x00\x02\x00isomiso2")
            + box(b"free", b"\x00" * 16)
            + box(b"mdat", os.urandom(2048))
            + box(b"moov", box(b"mvhd", b"\x00" * 100)))


def make_wav() -> bytes:
    data = os.urandom(4000)
    fmt = struct.pack("<HHIIHH", 1, 1, 8000, 16000, 2, 16)
    body = (b"WAVE" + b"fmt " + struct.pack("<I", len(fmt)) + fmt
            + b"data" + struct.pack("<I", len(data)) + data)
    return b"RIFF" + struct.pack("<I", len(body)) + body


def make_elf() -> bytes:
    """Tiny fake ELF64 with a section header table at the end."""
    body = os.urandom(512)
    shentsize, shnum = 64, 3
    e_shoff = 64 + len(body)
    hdr = bytearray(64)
    hdr[:4] = b"\x7fELF"
    hdr[4], hdr[5], hdr[6] = 2, 1, 1            # 64-bit, LE, v1
    struct.pack_into("<HHIQQQIHHHHHH", hdr, 16,
                     2, 0x3E, 1, 0x400000, 0, e_shoff, 0, 64, 56, 0,
                     shentsize, shnum, 0)
    return bytes(hdr) + body + bytes(shentsize * shnum)


# ---------------------------------------------------------------- image

def main():
    random.seed(7)
    files = {
        "png": make_png(),
        "jpg": make_jpeg(),
        "gif": make_gif(),
        "bmp": make_bmp(),
        "pdf": make_pdf(),
        "zip": make_zip(),
        "docx": make_docx_like(),
        "gz": make_gzip(),
        "sqlite": make_sqlite(),
        "mp4": make_mp4(),
        "wav": make_wav(),
        "elf": make_elf(),
    }

    image_path = os.path.join(tempfile.gettempdir(), "carvx_test.img")
    out_dir = os.path.join(tempfile.gettempdir(), "carvx_test_out")
    subprocess.run(["rm", "-rf", out_dir], check=True)

    expected = {}
    with open(image_path, "wb") as img:
        img.write(b"\x00" * 4096)               # leading slack
        for name, data in files.items():
            img.write(os.urandom(random.randint(1000, 5000)))  # junk between files
            # pad to sector boundary like a real filesystem would
            img.write(b"\x00" * (-img.tell() % 512))
            offset = img.tell()
            img.write(data)
            expected[name] = (offset, len(data), hashlib.sha256(data).hexdigest())
        img.write(os.urandom(3000))
        img.write(b"\x00" * 4096)

    print(f"image: {image_path} ({os.path.getsize(image_path):,} B)")
    r = subprocess.run([sys.executable, "-m", "carvx", image_path, "-o", out_dir, "-q"],
                       cwd=ROOT)
    if r.returncode != 0:
        print("FAIL: carvx exited", r.returncode)
        return 1

    with open(os.path.join(out_dir, "manifest.json")) as fh:
        manifest = json.load(fh)
    by_offset = {f["offset"]: f for f in manifest["files"]}

    failures = 0
    for name, (offset, size, sha) in expected.items():
        rec = by_offset.get(offset)
        if rec is None:
            print(f"FAIL {name:<8} nothing carved at offset {offset:#x}")
            failures += 1
        elif rec["sha256"] != sha:
            print(f"FAIL {name:<8} hash mismatch at {offset:#x} "
                  f"(carved {rec['size']} B as .{rec['ext']}, expected {size} B)")
            failures += 1
        else:
            print(f"OK   {name:<8} {size:>7,} B at {offset:#x} -> .{rec['ext']}")

    extra = [f for f in manifest["files"] if f["offset"] not in
             {off for off, _, _ in expected.values()}]
    for f in extra:
        print(f"NOTE extra carve: .{f['ext']} at {f['offset']:#x} ({f['size']} B)")

    print(f"\n{len(expected) - failures}/{len(expected)} recovered, "
          f"{len(extra)} extra carves")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
