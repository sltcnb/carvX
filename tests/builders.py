"""Builders for minimal-but-valid files of every supported type."""

import gzip
import io
import os
import sqlite3
import struct
import tempfile
import zipfile
import zlib


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
    lsd = struct.pack("<HHBBB", 2, 2, 0x80, 0, 0)
    gct = b"\x00\x00\x00\xff\xff\xff"
    img = b"\x2c" + struct.pack("<HHHHB", 0, 0, 2, 2, 0)
    lzw = b"\x02\x02\x4c\x01\x00"
    return b"GIF89a" + lsd + gct + img + lzw + b"\x3b"


def make_bmp() -> bytes:
    row = b"\x00\x00\xff" + b"\x00"
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
    hdr[4], hdr[5], hdr[6] = 2, 1, 1
    struct.pack_into("<HHIQQQIHHHHHH", hdr, 16,
                     2, 0x3E, 1, 0x400000, 0, e_shoff, 0, 64, 56, 0,
                     shentsize, shnum, 0)
    return bytes(hdr) + body + bytes(shentsize * shnum)


def make_7z() -> bytes:
    """7z signature header pointing at a fake next-header."""
    payload = os.urandom(256)
    next_header = os.urandom(32)
    hdr = (b"7z\xbc\xaf\x27\x1c" + b"\x00\x04" + b"\x00" * 4
           + struct.pack("<QQ", len(payload), len(next_header)) + b"\x00" * 4)
    assert len(hdr) == 32
    return hdr + payload + next_header


def make_mp3() -> bytes:
    """ID3v2 tag + valid MPEG1 Layer III frames (128kbps, 44100Hz)."""
    tag_body = b"\x00" * 100
    n = len(tag_body)                          # synchsafe 4x7-bit encoding
    hdr = b"ID3\x03\x00\x00" + bytes([(n >> 21) & 0x7F, (n >> 14) & 0x7F,
                                      (n >> 7) & 0x7F, n & 0x7F])
    frame_hdr = b"\xff\xfb\x90\x00"            # MPEG1 L3 128k 44100 no-pad
    frame_len = 144 * 128000 // 44100          # 417
    frame = frame_hdr + b"\x00" * (frame_len - 4)
    return hdr + tag_body + frame * 12


def make_macho() -> bytes:
    """Minimal thin Mach-O 64 LE with one segment + symtab."""
    seg_fileoff, seg_filesize = 0x100, 0x200
    cmds = struct.pack("<II16sQQQQIIII", 0x19, 72, b"__TEXT", 0, 0x1000,
                       seg_fileoff, seg_filesize, 7, 5, 0, 0)
    cmds += struct.pack("<IIIIII", 0x02, 24, 0x280, 4, 0x2C0, 0x40)
    hdr = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2,
                      2, len(cmds), 0, 0)
    blob = bytearray(hdr + cmds)
    blob.extend(b"\x00" * (0x300 - len(blob)))
    return bytes(blob)


def make_ico() -> bytes:
    """ICO with one 2x2 BGRA image stored as a BMP info bitmap."""
    img = struct.pack("<IiiHHIIiiII", 40, 2, 4, 1, 32, 0, 16, 0, 0, 0, 0)
    img += os.urandom(16)
    entry = struct.pack("<BBBBHHII", 2, 2, 0, 0, 1, 32, len(img), 6 + 16)
    return b"\x00\x00\x01\x00" + b"\x01\x00" + entry + img


def make_ogg() -> bytes:
    """Two OggS pages; second flagged end-of-stream."""
    def page(header_type, body, seq):
        segs = []
        b = body
        while len(b) >= 255:
            segs.append(255)
            b = b[255:]
        segs.append(len(b))
        head = (b"OggS" + bytes([0, header_type]) + struct.pack("<q", 0)
                + struct.pack("<III", 1, seq, 0) + bytes([len(segs)]) + bytes(segs))
        return head + body
    return page(0x02, b"\x01vorbis" + os.urandom(50), 0) + \
        page(0x04, os.urandom(200), 1)


def make_flac() -> bytes:
    """fLaC + STREAMINFO (last metadata block) + a little frame data."""
    streaminfo = os.urandom(34)
    block = bytes([0x80]) + (len(streaminfo)).to_bytes(3, "big") + streaminfo
    return b"fLaC" + block + b"\xff\xf8" + os.urandom(200)


def make_mkv() -> bytes:
    """EBML header (DocType webm) + Segment with a known size."""
    def elem(eid, payload):
        # 8-byte length vint (marker 0x01 + 7 length bytes) for simplicity
        return eid + (0x01 << 56 | len(payload)).to_bytes(8, "big") + payload
    doctype = elem(b"\x42\x82", b"webm")
    ebml = elem(b"\x1a\x45\xdf\xa3", doctype)
    segment = elem(b"\x18\x53\x80\x67", os.urandom(300))
    return ebml + segment


def make_evtx() -> bytes:
    """ElfFile header claiming 1 chunk -> 4096 + 65536 bytes."""
    hdr = bytearray(4096)
    hdr[:8] = b"ElfFile\x00"
    struct.pack_into("<H", hdr, 40, 1)           # number of chunks
    return bytes(hdr) + os.urandom(65536)


def make_hive() -> bytes:
    """regf base block claiming a small hbins area."""
    hbins = 4096
    hdr = bytearray(4096)
    hdr[:4] = b"regf"
    struct.pack_into("<I", hdr, 40, hbins)
    return bytes(hdr) + os.urandom(hbins)


def make_bplist() -> bytes:
    """Real binary plist via plistlib so the trailer math is correct."""
    import plistlib
    return plistlib.dumps({"a": 1, "b": [1, 2, 3], "c": "carvx"},
                          fmt=plistlib.FMT_BINARY)


def make_psd() -> bytes:
    """8BPS header + four length-prefixed sections + image data."""
    hdr = b"8BPS" + struct.pack(">HxxxxxxHIIHH", 1, 1, 2, 2, 8, 3)
    sections = b""
    for _ in range(3):                           # color mode, resources, layers
        sections += struct.pack(">I", 0)
    sections += struct.pack(">I", 16) + os.urandom(16)   # 4th: image data blob
    return hdr + sections


BUILDERS = {
    "png": make_png, "jpg": make_jpeg, "gif": make_gif, "bmp": make_bmp,
    "pdf": make_pdf, "zip": make_zip, "docx": make_docx_like, "gz": make_gzip,
    "sqlite": make_sqlite, "mp4": make_mp4, "wav": make_wav, "elf": make_elf,
    "7z": make_7z, "mp3": make_mp3, "macho": make_macho,
    "ico": make_ico, "ogg": make_ogg, "mkv": make_mkv,
    "evtx": make_evtx, "hive": make_hive, "plist": make_bplist,
}

# Best-effort formats (no exact end marker); built for handler tests only,
# excluded from the hash-exact integration image.
BEST_EFFORT_BUILDERS = {"flac": make_flac, "psd": make_psd}
