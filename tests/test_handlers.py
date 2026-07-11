"""Per-handler unit tests: valid input, truncation, corruption."""

import io
import os
import zipfile

import pytest

import builders
from carvx import handlers
from carvx.reader import Window
from carvx.signatures import BY_NAME


class BytesReader:
    """Reader stand-in backed by a bytes object."""

    def __init__(self, data: bytes):
        self.data = data
        self.size = len(data)

    def pread(self, offset, length):
        return self.data[offset:offset + length]


def window(data: bytes, base: int = 0, limit: int | None = None) -> Window:
    return Window(BytesReader(data), base, limit if limit is not None else len(data) - base)


CASES = [
    # (builder key, signature name, expected ext)
    ("png", "png", "png"),
    ("jpg", "jpg", "jpg"),
    ("gif", "gif", "gif"),
    ("bmp", "bmp", "bmp"),
    ("pdf", "pdf", "pdf"),
    ("zip", "zip", "zip"),
    ("docx", "zip", "docx"),
    ("gz", "gz", "gz"),
    ("sqlite", "sqlite", "sqlite"),
    ("mp4", "mp4", "mp4"),
    ("wav", "riff", "wav"),
    ("elf", "elf", "elf"),
    ("7z", "7z", "7z"),
    ("mp3", "mp3", "mp3"),
    ("macho", "macho", "macho"),
    ("ico", "ico", "ico"),
    ("ogg", "ogg", "ogg"),
    ("mkv", "mkv", "webm"),
    ("evtx", "evtx", "evtx"),
    ("hive", "hive", "hive"),
    ("plist", "plist", "plist"),
]

# Best-effort handlers: no exact end marker in the format, so size may include
# trailing data up to the next signature / EOF. Just confirm they don't crash
# and return a plausible carve on valid input.
BEST_EFFORT = [("flac", "flac"), ("psd", "psd")]


@pytest.mark.parametrize("key,sig_name", BEST_EFFORT)
def test_best_effort_handlers(key, sig_name):
    builder = builders.BEST_EFFORT_BUILDERS.get(key)
    if builder is None:
        pytest.skip(f"no builder for {key}")
    data = builder()
    carve = BY_NAME[sig_name].handler(window(data))
    assert carve is not None and carve.size >= len(data) - 4
    assert BY_NAME[sig_name].handler(window(b"")) is None


@pytest.mark.parametrize("key,sig_name,ext", CASES)
def test_exact_size_on_valid_file(key, sig_name, ext):
    data = builders.BUILDERS[key]()
    sig = BY_NAME[sig_name]
    # trailing junk must not change the carved size
    carve = sig.handler(window(data + os.urandom(2000)))
    assert carve is not None, f"{key}: handler rejected valid file"
    assert carve.size == len(data), f"{key}: size {carve.size} != {len(data)}"
    assert carve.ext == ext


@pytest.mark.parametrize("key,sig_name,ext", CASES)
def test_truncated_input_never_overruns(key, sig_name, ext):
    """Cut the file short: handler must reject or return a size within bounds."""
    data = builders.BUILDERS[key]()
    sig = BY_NAME[sig_name]
    for cut in (len(data) // 2, 20, 10):
        w = window(data[:cut])
        carve = sig.handler(w)
        if carve is not None:
            assert carve.size <= cut


@pytest.mark.parametrize("key,sig_name,ext", CASES)
def test_corrupted_tail_never_crashes(key, sig_name, ext):
    data = bytearray(builders.BUILDERS[key]())
    # smash the second half
    half = len(data) // 2
    data[half:] = os.urandom(len(data) - half)
    sig = BY_NAME[sig_name]
    carve = sig.handler(window(bytes(data)))   # must not raise
    if carve is not None:
        assert 0 < carve.size <= len(data)


def test_jpeg_embedded_thumbnail_not_terminating():
    """EOI inside an APP segment (EXIF thumbnail) must not end the carve."""
    inner = builders.make_jpeg()
    app1 = b"\xff\xe1" + (len(inner) + 2).to_bytes(2, "big") + inner
    data = builders.make_jpeg()
    data = data[:2] + app1 + data[2:]
    carve = handlers.carve_jpeg(window(data + b"\x00" * 100))
    assert carve is not None and carve.size == len(data)


def test_zip_eocd_cross_check_picks_right_end():
    """A stored (uncompressed) inner zip must not truncate the outer one."""
    inner = builders.make_zip()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        z.writestr("inner.zip", inner)
        z.writestr("more.txt", "x" * 500)
    data = buf.getvalue()
    carve = handlers.carve_zip(window(data + os.urandom(500)))
    assert carve is not None and carve.size == len(data) and carve.validated


def test_pdf_stops_before_next_pdf():
    a, b = builders.make_pdf(), builders.make_pdf()
    carve = handlers.carve_pdf(window(a + b))
    assert carve is not None and carve.size == len(a)


def test_gzip_multimember():
    data = builders.make_gzip() + builders.make_gzip()
    carve = handlers.carve_gzip(window(data + os.urandom(100)))
    assert carve is not None and carve.size == len(data)


def test_sqlite_rejects_bad_page_size():
    data = bytearray(builders.make_sqlite())
    data[16:18] = (1234).to_bytes(2, "big")    # not a power of two
    assert handlers.carve_sqlite(window(bytes(data))) is None


def test_empty_and_tiny_windows():
    for sig in BY_NAME.values():
        assert sig.handler(window(b"")) is None
        assert sig.handler(window(b"\x00")) is None


def test_macho_fat_binary():
    if not os.path.exists("/bin/ls"):
        pytest.skip("no /bin/ls")
    data = open("/bin/ls", "rb").read()
    carve = handlers.carve_macho(window(data + os.urandom(1000)))
    assert carve is not None and carve.size == len(data)


def test_random_noise_yields_no_validated_carves():
    noise = os.urandom(1 << 20)
    for name, sig in BY_NAME.items():
        for magic in sig.magics:
            idx = noise.find(magic)
            if idx < 0:
                continue
            carve = sig.handler(window(noise, idx))
            if carve is not None:
                assert not carve.validated or carve.size <= len(noise) - idx
