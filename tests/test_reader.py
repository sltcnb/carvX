"""Reader and Window behavior."""

import os

import pytest

import carvx.reader as reader_mod
from carvx.reader import Reader, Window


@pytest.fixture
def sample(tmp_path):
    data = bytes(range(256)) * 1000            # 256,000 B, patterned
    p = tmp_path / "img.bin"
    p.write_bytes(data)
    return str(p), data


def test_reader_pread(sample):
    path, data = sample
    with Reader(path) as r:
        assert r.size == len(data)
        assert r.pread(0, 10) == data[:10]
        assert r.pread(1000, 256) == data[1000:1256]
        assert r.pread(len(data) - 5, 100) == data[-5:]      # clamped at EOF
        assert r.pread(len(data) + 1, 10) == b""
        assert r.pread(0, 0) == b""


def test_reader_seek_fallback(sample, monkeypatch):
    """Windows path: no os.pread, seek+read under lock must be identical."""
    path, data = sample
    monkeypatch.setattr(reader_mod, "_HAS_PREAD", False)
    with Reader(path) as r:
        assert r.pread(12345, 777) == data[12345:13122]
        assert r.pread(0, r.size) == data


def test_window_read_and_limit(sample):
    path, data = sample
    with Reader(path) as r:
        w = Window(r, 100, 500)
        assert w.read(0, 10) == data[100:110]
        assert w.read(490, 100) == data[590:600]             # clamped at limit
        assert w.read(500, 1) == b""
        assert w.read(-1, 10) == b""


def test_window_find(sample):
    path, data = sample
    with Reader(path) as r:
        w = Window(r, 0, r.size)
        assert w.find(bytes([7, 8, 9])) == 7
        assert w.find(bytes([7, 8, 9]), 8) == 256 + 7
        assert w.find(b"\xff" + bytes([0])) == 255           # spans period boundary
        assert w.find(b"nonexistent-needle") == -1


def test_window_find_last(sample):
    path, data = sample
    with Reader(path) as r:
        w = Window(r, 0, r.size)
        assert w.find_last(bytes([7, 8, 9])) == 255744 + 7   # last period
        assert w.find_last(bytes([7, 8, 9]), 0, 300) == 263  # 2nd period fits
        assert w.find_last(bytes([7, 8, 9]), 0, 100) == 7


def test_window_find_spanning_block_boundary(tmp_path):
    """Needle straddling the 64 KiB cache block boundary must be found."""
    blk = Window.BLOCK
    data = b"\x00" * (blk - 3) + b"NEEDLE" + b"\x00" * 100
    p = tmp_path / "b.bin"
    p.write_bytes(data)
    with Reader(str(p)) as r:
        w = Window(r, 0, r.size)
        assert w.find(b"NEEDLE") == blk - 3
        assert w.read(blk - 3, 6) == b"NEEDLE"


def test_reader_missing_file():
    with pytest.raises(OSError):
        Reader("/nonexistent/path/img.dd")


def test_reader_empty_file(tmp_path):
    p = tmp_path / "empty.bin"
    p.write_bytes(b"")
    with pytest.raises(ValueError):
        Reader(str(p))


def test_windows_aligned_device_path(sample, monkeypatch):
    """Force the Windows raw-device alignment path on a regular file; the
    round-out-and-trim logic must return byte-identical results."""
    path, data = sample
    with Reader(path) as r:
        r._win_device = True            # simulate a raw \\.\ device
        # unaligned offset + length: result must match the exact slice
        assert r.pread(1000, 300) == data[1000:1300]
        assert r.pread(511, 1) == data[511:512]
        assert r.pread(4095, 4098) == data[4095:8193]
        assert r.pread(0, 512) == data[:512]
        # read clamped at EOF still correct
        assert r.pread(r.size - 10, 100) == data[-10:]


def test_windows_device_size_helper_importable():
    """The IOCTL size helper exists and is callable (real call needs Windows)."""
    import carvx.reader as rm
    assert callable(rm._windows_device_size)
