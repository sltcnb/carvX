"""Deep validation: decode carved bytes to confirm integrity.

Each validator returns:
  None              -> validator not applicable / inconclusive (keep as-is)
  (True,  size|None)-> verified; size is a tightened length or None to keep
  (False, None)     -> actively invalid (decode failed) -> downgrade confidence

Validators must never raise; they run on attacker-controlled bytes.
"""

import zlib


def _png(data: bytes):
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    pos = 8
    saw_iend = False
    idat = bytearray()
    while pos + 8 <= len(data):
        length = int.from_bytes(data[pos:pos + 4], "big")
        ctype = data[pos + 4:pos + 8]
        body = data[pos + 8:pos + 8 + length]
        crc_off = pos + 8 + length
        if crc_off + 4 > len(data):
            return (False, None)
        stored = int.from_bytes(data[crc_off:crc_off + 4], "big")
        if zlib.crc32(ctype + body) & 0xFFFFFFFF != stored:
            return (False, None)
        if ctype == b"IDAT":
            idat += body
        pos = crc_off + 4
        if ctype == b"IEND":
            saw_iend = True
            break
    if not saw_iend:
        return (False, None)
    try:
        zlib.decompress(bytes(idat))
    except zlib.error:
        return (False, None)
    return (True, pos)              # tighten to end of IEND


def _pillow_decode(data: bytes):
    """Full pixel decode via Pillow if installed; detects entropy corruption
    that format-structure checks (and JPEG, which has no checksum) cannot."""
    try:
        import io
        from PIL import Image
    except ImportError:
        return None
    try:
        im = Image.open(io.BytesIO(data))
        im.load()                      # force decode of pixel data
        return True
    except Exception:
        return False


def _jpeg(data: bytes):
    if data[:2] != b"\xff\xd8":
        return None
    # Prefer a real decode (Pillow) when available - JPEG has no checksum, so a
    # structural walk cannot catch a corrupt/fragmented entropy stream.
    pil = _pillow_decode(data)
    if pil is not None:
        return (pil, None)
    if data[-2:] != b"\xff\xd9":
        # EOI not at the tail; let the carver's size stand but flag uncertainty
        return None
    # walk header markers up to SOS; lengths must be self-consistent
    pos = 2
    saw_sos = False
    while pos + 4 <= len(data):
        if data[pos] != 0xFF:
            return (False, None)
        marker = data[pos + 1]
        if marker == 0xDA:
            saw_sos = True
            break
        if marker in (0x01,) or 0xD0 <= marker <= 0xD9:
            pos += 2
            continue
        seglen = int.from_bytes(data[pos + 2:pos + 4], "big")
        if seglen < 2:
            return (False, None)
        pos += 2 + seglen
    return (True, None) if saw_sos else (False, None)


def _gif(data: bytes):
    if data[:6] not in (b"GIF87a", b"GIF89a"):
        return None
    if data[-1:] != b"\x3b":
        return (False, None)
    return (True, None)


def _bmp(data: bytes):
    if data[:2] != b"BM" or len(data) < 26:
        return None
    declared = int.from_bytes(data[2:6], "little")
    if declared != len(data):
        return None                # carver may have over/under-read; inconclusive
    return (True, None)


def _zip(data: bytes):
    import io
    import zipfile
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            bad = z.testzip()       # None if all CRCs OK
            names = z.namelist()
    except (zipfile.BadZipFile, OSError, EOFError, NotImplementedError):
        return (False, None)
    if bad is not None:
        return (False, None)
    return (True, None) if names else (False, None)


def _gzip(data: bytes):
    if data[:2] != b"\x1f\x8b":
        return None
    try:
        d = zlib.decompressobj(31)
        out = 0
        for i in range(0, len(data), 1 << 20):
            out += len(d.decompress(data[i:i + (1 << 20)], 1 << 24))
            while d.unconsumed_tail:
                out += len(d.decompress(d.unconsumed_tail, 1 << 24))
        return (True, None) if d.eof or out > 0 else (False, None)
    except zlib.error:
        return (False, None)


def _sqlite(data: bytes):
    if data[:16] != b"SQLite format 3\x00":
        return None
    import os
    import sqlite3
    import tempfile
    fd, path = tempfile.mkstemp(suffix=".sqlite")
    try:
        os.write(fd, data)
        os.close(fd)
        con = sqlite3.connect(path)
        try:
            row = con.execute("PRAGMA integrity_check").fetchone()
        finally:
            con.close()
        return (True, None) if row and row[0] == "ok" else (False, None)
    except sqlite3.DatabaseError:
        return (False, None)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


# ext (from handler/signature name) -> validator
VALIDATORS = {
    "png": _png, "jpg": _jpeg, "gif": _gif, "bmp": _bmp,
    "zip": _zip, "docx": _zip, "xlsx": _zip, "pptx": _zip, "apk": _zip,
    "jar": _zip, "epub": _zip, "odf": _zip,
    "gz": _gzip, "sqlite": _sqlite,
}


def validate(ext: str, data: bytes):
    """Return (verified: bool|None, tightened_size: int|None).

    verified True  -> decode succeeded
    verified False -> decode failed (downgrade)
    verified None  -> no validator / inconclusive
    """
    fn = VALIDATORS.get(ext)
    if fn is None:
        return (None, None)
    try:
        result = fn(data)
    except Exception:
        return (None, None)
    if result is None:
        return (None, None)
    ok, size = result
    return (ok, size)
