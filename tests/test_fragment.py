"""Bifragment gap carving.

Reliable for checksummed formats (PNG: per-chunk CRC + zlib), so the tests use
PNG. JPEG has no integrity check and decoders tolerate corruption, so JPEG
bifragment is best-effort and not asserted here.
"""

import hashlib
import os
import struct
import zlib


from carvx.carver import Carver, Options
from carvx.fragment import bifragment_carve
from carvx.reader import Reader, Window
from carvx.signatures import BY_NAME


def big_png(seed=0):
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d))
    w = h = 64
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 0, 0, 0, 0)
    rng = __import__("random").Random(seed)
    raw = b"".join(b"\x00" + bytes(rng.randrange(256) for _ in range(w)) for _ in range(h))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(raw, 1)) + chunk(b"IEND", b""))


def _fragmented_image(tmp_path, payload, frag1=2048, gap=1536, lead=512):
    f1, f2 = payload[:frag1], payload[frag1:]
    blob = (b"\x00" * lead + f1 + os.urandom(gap) + f2 + b"\x00" * 512)
    p = tmp_path / "frag.img"
    p.write_bytes(blob)
    return str(p), lead


def test_bifragment_window_reassembles_png(tmp_path):
    png = big_png()
    assert len(png) > 3000, "need a multi-cluster PNG"
    path, base = _fragmented_image(tmp_path, png)
    with Reader(path) as r:
        w = Window(r, base, r.size - base)
        result = bifragment_carve(w, "png")
    assert result is not None
    blob, layout = result
    assert hashlib.sha256(blob).hexdigest() == hashlib.sha256(png).hexdigest()
    assert layout.frag1_len == 2048
    assert layout.gap == 1536


def test_carver_recovers_fragmented_png(tmp_path):
    png = big_png(seed=5)
    path, base = _fragmented_image(tmp_path, png)
    sha = hashlib.sha256(png).hexdigest()

    # without --validate: contiguous handler fails -> nothing (or wrong)
    c = Carver(path, [BY_NAME["png"]], Options(out_dir=str(tmp_path / "a"),
                                               quiet=True))
    try:
        plain = c.run()
    finally:
        c.close()
    assert all(r.sha256 != sha for r in plain)

    # with --validate: bifragment reassembles the exact original
    c = Carver(path, [BY_NAME["png"]], Options(out_dir=str(tmp_path / "b"),
                                               quiet=True, validate=True))
    try:
        recovered = c.run()
    finally:
        c.close()
    hit = [r for r in recovered if r.sha256 == sha]
    assert hit, "bifragment did not recover the PNG"
    r = hit[0]
    assert r.verified is True
    assert r.fragments and len(r.fragments) == 2
    assert hashlib.sha256(open(r.path, "rb").read()).hexdigest() == sha


def test_bifragment_disabled(tmp_path):
    png = big_png(seed=9)
    path, base = _fragmented_image(tmp_path, png)
    sha = hashlib.sha256(png).hexdigest()
    c = Carver(path, [BY_NAME["png"]], Options(out_dir=str(tmp_path / "o"),
                                               quiet=True, validate=True,
                                               bifragment=False))
    try:
        recs = c.run()
    finally:
        c.close()
    assert all(r.sha256 != sha for r in recs)


def test_bifragment_unsupported_ext_returns_none(tmp_path):
    p = tmp_path / "x.img"
    p.write_bytes(b"\x00" * 4096)
    with Reader(str(p)) as r:
        assert bifragment_carve(Window(r, 0, r.size), "gz") is None
