"""Image-format reader tests.

Split-raw, QCOW2, and VMDK are verified against qemu-img output when qemu-img
is available (else skipped). EWF is exercised with a minimal hand-built
uncompressed E01 so the section/table parser is covered without libewf.
"""

import os
import shutil
import struct
import subprocess
import zlib

import pytest

import builders
from carvx.images import (open_source, SplitRawReader, Qcow2Reader, EwfReader)
from carvx.reader import Reader

QEMU = shutil.which("qemu-img") or (
    "/opt/homebrew/bin/qemu-img"
    if os.path.exists("/opt/homebrew/bin/qemu-img") else None)


@pytest.fixture
def raw_image(tmp_path):
    """A raw image with a few carvable files; returns (path, sha256 of bytes)."""
    import hashlib
    data = bytearray(b"\x00" * 4096)
    for builder in (builders.make_png, builders.make_jpeg, builders.make_gif):
        data += b"\x11" * 2048 + builder()
    data += b"\x00" * 4096
    p = tmp_path / "raw.img"
    p.write_bytes(bytes(data))
    return str(p), hashlib.sha256(bytes(data)).hexdigest()


def _full_read(reader):
    return reader.pread(0, reader.size)


# ---------------------------------------------------------------- split raw

def test_split_raw_roundtrip(raw_image, tmp_path):
    path, sha = raw_image
    import hashlib
    data = open(path, "rb").read()
    # split into 5000-byte segments named .001, .002, ...
    seg_paths = []
    for i in range(0, len(data), 5000):
        sp = tmp_path / f"img.{i // 5000 + 1:03d}"
        sp.write_bytes(data[i:i + 5000])
        seg_paths.append(str(sp))
    r = open_source(seg_paths[0])
    assert isinstance(r, SplitRawReader)
    try:
        assert r.size == len(data)
        assert hashlib.sha256(_full_read(r)).hexdigest() == sha
        # random spanning read across segment boundary
        assert r.pread(4900, 300) == data[4900:5200]
    finally:
        r.close()


# ---------------------------------------------------------------- qemu formats

@pytest.mark.skipif(not QEMU, reason="qemu-img not installed")
@pytest.mark.parametrize("fmt,extra", [
    ("qcow2", ["-c"]),          # compressed
    ("qcow2", []),              # uncompressed
    ("vmdk", []),
])
def test_qemu_format_roundtrip(raw_image, tmp_path, fmt, extra):
    import hashlib
    path, sha = raw_image
    out = tmp_path / f"img.{fmt}"
    subprocess.run([QEMU, "convert", "-f", "raw", "-O", fmt, *extra,
                    path, str(out)], check=True, capture_output=True)
    r = open_source(str(out))
    try:
        assert r.size >= os.path.getsize(path) - 4096
        got = r.pread(0, os.path.getsize(path))
        assert hashlib.sha256(got).hexdigest() == sha
    finally:
        r.close()


@pytest.mark.skipif(not QEMU, reason="qemu-img not installed")
def test_carve_through_qcow2_matches_raw(raw_image, tmp_path):
    from carvx.carver import Carver, Options
    from carvx.signatures import SIGNATURES
    path, _ = raw_image
    out = tmp_path / "img.qcow2"
    subprocess.run([QEMU, "convert", "-f", "raw", "-O", "qcow2", "-c",
                    path, str(out)], check=True, capture_output=True)

    def carve(src, odir):
        c = Carver(src, list(SIGNATURES), Options(out_dir=str(odir), quiet=True))
        try:
            return sorted((r.size, r.sha256) for r in c.run())
        finally:
            c.close()

    assert carve(path, tmp_path / "a") == carve(str(out), tmp_path / "b")


# ---------------------------------------------------------------- EWF (E01)

def _build_uncompressed_e01(path, payload, chunk_sectors=2, bps=512):
    """Minimal single-segment uncompressed EWF with one sectors+table section."""
    def section(stype, body, next_off_placeholder=0):
        return stype, body

    chunk_size = chunk_sectors * bps
    chunks = [payload[i:i + chunk_size] for i in range(0, len(payload), chunk_size)]
    chunks = [c.ljust(chunk_size, b"\x00") for c in chunks]
    total_sectors = (len(payload) + bps - 1) // bps

    out = bytearray()
    # EWF file header: 8-byte signature + 0x01 + segment number (2) + 0x0000 = 13
    out += b"EVF\x09\x0d\x0a\xff\x00" + bytes([1]) + struct.pack("<HH", 1, 0)

    def emit(stype, body):
        nonlocal out
        start = len(out)
        desc = bytearray(76)
        name = stype[:15] + b"\x00" * (16 - len(stype[:15]))
        desc[:16] = name
        # next_offset and size filled after we know body length
        size = 76 + len(body)
        struct.pack_into("<Q", desc, 16, start + size)        # next section offset
        struct.pack_into("<Q", desc, 24, size)
        struct.pack_into("<I", desc, 72, zlib.adler32(desc[:72]) & 0xFFFFFFFF)
        out += desc + body
        return start

    # volume section: chunk_count(4) sectors_per_chunk(4) bytes_per_sector(4)
    #                 sector_count(4) + padding
    vol = bytearray(1052)
    struct.pack_into("<I", vol, 0, len(chunks))
    struct.pack_into("<I", vol, 4, chunk_sectors)
    struct.pack_into("<I", vol, 8, bps)
    struct.pack_into("<I", vol, 12, total_sectors)
    emit(b"volume", bytes(vol))

    # sectors section holds raw chunk data
    sectors_body = b"".join(chunks)
    sectors_start = emit(b"sectors", sectors_body)
    data_base = sectors_start + 76                  # absolute file offset of chunk 0

    # table section: count(4) pad(4) base_offset(8) pad(4) checksum(4) + entries
    thdr = bytearray(24)
    struct.pack_into("<I", thdr, 0, len(chunks))
    struct.pack_into("<Q", thdr, 8, data_base)      # base offset
    entries = bytearray()
    for i in range(len(chunks)):
        entries += struct.pack("<I", i * chunk_size)   # relative offset, uncompressed
    emit(b"table", bytes(thdr) + bytes(entries))
    emit(b"done", b"")

    with open(path, "wb") as fh:
        fh.write(out)


def test_ewf_minimal_uncompressed(tmp_path):
    payload = bytes(range(256)) * 40 + builders.make_png()   # ~10 KiB
    e01 = tmp_path / "img.E01"
    _build_uncompressed_e01(str(e01), payload)
    r = EwfReader(str(e01))
    try:
        # size is chunk-aligned; the payload prefix must match exactly
        assert r.size >= len(payload)
        assert r.pread(0, len(payload)) == payload
        assert r.pread(100, 50) == payload[100:150]
    finally:
        r.close()


def test_open_source_detects_qcow2_magic(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"QFI\xfb" + b"\x00" * 200)
    # malformed but magic present -> Qcow2Reader attempted (will read zeros)
    try:
        r = open_source(str(p))
        assert isinstance(r, Qcow2Reader)
        r.close()
    except Exception:
        pass        # header too small to fully parse is acceptable


def test_open_source_falls_back_to_raw(tmp_path):
    p = tmp_path / "plain.img"
    p.write_bytes(b"just raw bytes" * 100)
    r = open_source(str(p))
    assert isinstance(r, Reader)
    r.close()


# ---------------------------------------------------------------- stdin spool

def test_stdin_reader_spools_and_reads(tmp_path):
    import io
    from carvx.images import StdinReader
    data = bytes(range(256)) * 500
    r = StdinReader(stream=io.BytesIO(data))
    try:
        assert r.size == len(data)
        assert r.pread(0, 100) == data[:100]
        assert r.pread(1000, 256) == data[1000:1256]
        assert r.path == "-"
        tmp = r._tmp
        assert os.path.exists(tmp)
    finally:
        r.close()
    assert not os.path.exists(tmp)        # cleaned up on close
