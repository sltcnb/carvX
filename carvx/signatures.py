"""Signature registry: magic bytes -> carving handler.

precheck(buf, i) runs against the in-memory scan chunk before spawning a
Window, to cheaply reject noise from short magics (MZ, BM, RIFF, ...).
i is the index of the magic match inside buf.
"""

from typing import Callable, NamedTuple, Optional

from . import handlers

KB, MB, GB = 1 << 10, 1 << 20, 1 << 30


class Signature(NamedTuple):
    name: str                                   # type key used in --types
    magics: tuple                               # one or more header magics
    header_offset: int                          # magic position inside file
    handler: Callable                           # handlers.carve_*
    max_size: int                               # window cap
    precheck: Optional[Callable] = None


def _pre_bmp(buf, i):
    if i + 26 > len(buf):
        return True
    return (buf[i + 6:i + 10] == b"\x00\x00\x00\x00"
            and int.from_bytes(buf[i + 14:i + 18], "little") in (12, 40, 52, 56, 64, 108, 124))


def _pre_mz(buf, i):
    if i + 64 > len(buf):
        return True
    e_lfanew = int.from_bytes(buf[i + 60:i + 64], "little")
    if not (64 <= e_lfanew <= 0x10000):
        return False
    if i + e_lfanew + 4 <= len(buf):
        return buf[i + e_lfanew:i + e_lfanew + 4] == b"PE\x00\x00"
    return True


def _pre_riff(buf, i):
    if i + 12 > len(buf):
        return True
    return buf[i + 8:i + 12] in (b"WAVE", b"AVI ", b"WEBP")


def _pre_ftyp(buf, i):
    if i < 4:
        return False
    size = int.from_bytes(buf[i - 4:i], "big")
    return size == 1 or 8 <= size <= 0xFFFFFF


def _pre_id3(buf, i):
    if i + 10 > len(buf):
        return True
    return (buf[i + 3] < 0x10 and buf[i + 4] < 0x10
            and not any(b & 0x80 for b in buf[i + 6:i + 10]))


SIGNATURES = [
    Signature("jpg", (b"\xff\xd8\xff",), 0, handlers.carve_jpeg, 64 * MB),
    Signature("png", (b"\x89PNG\r\n\x1a\n",), 0, handlers.carve_png, 64 * MB),
    Signature("gif", (b"GIF87a", b"GIF89a"), 0, handlers.carve_gif, 32 * MB),
    Signature("bmp", (b"BM",), 0, handlers.carve_bmp, 64 * MB, _pre_bmp),
    Signature("tif", (b"II*\x00", b"MM\x00*"), 0, handlers.carve_tiff, 256 * MB),
    Signature("pdf", (b"%PDF-",), 0, handlers.carve_pdf, 128 * MB),
    Signature("zip", (b"PK\x03\x04",), 0, handlers.carve_zip, 512 * MB),
    Signature("gz", (b"\x1f\x8b\x08",), 0, handlers.carve_gzip, 256 * MB),
    Signature("7z", (b"7z\xbc\xaf\x27\x1c",), 0, handlers.carve_7z, 4 * GB),
    Signature("rar", (b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00"), 0,
              handlers.carve_rar, 16 * MB),
    Signature("sqlite", (b"SQLite format 3\x00",), 0, handlers.carve_sqlite, 1 * GB),
    Signature("mp4", (b"ftyp",), 4, handlers.carve_mp4, 4 * GB, _pre_ftyp),
    Signature("riff", (b"RIFF",), 0, handlers.carve_riff, 2 * GB, _pre_riff),
    Signature("mp3", (b"ID3",), 0, handlers.carve_mp3, 256 * MB, _pre_id3),
    Signature("exe", (b"MZ",), 0, handlers.carve_pe, 256 * MB, _pre_mz),
    Signature("elf", (b"\x7fELF",), 0, handlers.carve_elf, 256 * MB),
    Signature("macho", (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe",
                        b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce",
                        b"\xca\xfe\xba\xbe"), 0, handlers.carve_macho, 256 * MB),
    Signature("ole", (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",), 0, handlers.carve_ole, 64 * MB),
    Signature("mkv", (b"\x1a\x45\xdf\xa3",), 0, handlers.carve_mkv, 4 * GB),
    Signature("flac", (b"fLaC",), 0, handlers.carve_flac, 512 * MB),
    Signature("ogg", (b"OggS",), 0, handlers.carve_ogg, 512 * MB),
    Signature("psd", (b"8BPS",), 0, handlers.carve_psd, 512 * MB),
    Signature("ico", (b"\x00\x00\x01\x00", b"\x00\x00\x02\x00"), 0, handlers.carve_ico, 8 * MB),
    Signature("evtx", (b"ElfFile\x00",), 0, handlers.carve_evtx, 256 * MB),
    Signature("hive", (b"regf",), 0, handlers.carve_regf, 256 * MB),
    Signature("plist", (b"bplist00",), 0, handlers.carve_bplist, 64 * MB),
]

BY_NAME = {s.name: s for s in SIGNATURES}

# Friendly aliases for --types
ALIASES = {
    "jpeg": "jpg", "tiff": "tif", "gzip": "gz", "mov": "mp4", "avi": "riff",
    "wav": "riff", "webp": "riff", "docx": "zip", "xlsx": "zip", "pptx": "zip",
    "doc": "ole", "xls": "ole", "ppt": "ole", "pe": "exe", "dll": "exe",
    "sqlite3": "sqlite", "db": "sqlite",
    "heic": "mp4", "heif": "mp4", "avif": "mp4", "m4a": "mp4", "m4v": "mp4",
    "3gp": "mp4", "webm": "mkv", "matroska": "mkv", "cur": "ico",
    "reg": "hive", "registry": "hive", "bplist": "plist",
}


def resolve_types(spec: str):
    """Parse 'jpg,png,...' into a list of Signatures."""
    out = []
    for tok in spec.split(","):
        tok = tok.strip().lower()
        if not tok:
            continue
        name = ALIASES.get(tok, tok)
        sig = BY_NAME.get(name)
        if sig is None:
            raise ValueError(f"unknown type {tok!r} (see --list-types)")
        if sig not in out:
            out.append(sig)
    return out
