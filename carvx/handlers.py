"""Per-type carving handlers.

Each handler receives a Window based at the candidate header and returns a
Carve(size, ext, validated) or None to reject the candidate.

validated=True means the structure parsed cleanly to a definite end;
validated=False means a best-effort fallback size (carved data may have junk
appended at the tail).
"""

import zlib
from typing import NamedTuple, Optional

from .reader import Window

KB, MB, GB = 1 << 10, 1 << 20, 1 << 30


class Carve(NamedTuple):
    size: int
    ext: str
    validated: bool


def _u16le(b, o=0): return int.from_bytes(b[o:o + 2], "little")
def _u32le(b, o=0): return int.from_bytes(b[o:o + 4], "little")
def _u64le(b, o=0): return int.from_bytes(b[o:o + 8], "little")
def _u16be(b, o=0): return int.from_bytes(b[o:o + 2], "big")
def _u32be(b, o=0): return int.from_bytes(b[o:o + 4], "big")
def _u64be(b, o=0): return int.from_bytes(b[o:o + 8], "big")


# ---------------------------------------------------------------- JPEG

def carve_jpeg(w: Window) -> Optional[Carve]:
    pos = 2
    while pos < w.limit:
        hdr = w.read(pos, 4)
        if len(hdr) < 2 or hdr[0] != 0xFF:
            return None
        marker = hdr[1]
        if marker == 0xD9:                      # EOI
            return Carve(pos + 2, "jpg", True)
        if marker == 0xD8 or marker == 0x01 or 0xD0 <= marker <= 0xD7:
            pos += 2
            continue
        if marker == 0xFF:                      # fill byte
            pos += 1
            continue
        if len(hdr) < 4:
            return None
        seglen = _u16be(hdr, 2)
        if seglen < 2:
            return None
        if marker == 0xDA:                      # SOS: scan entropy-coded data
            pos += 2 + seglen
            while True:
                idx = w.find(b"\xff", pos)
                if idx < 0:
                    return None
                nxt = w.read(idx + 1, 1)
                if not nxt:
                    return None
                b = nxt[0]
                if b == 0xD9:                   # EOI
                    return Carve(idx + 2, "jpg", True)
                if b == 0x00 or 0xD0 <= b <= 0xD7:
                    pos = idx + 2
                    continue
                if b == 0xFF:
                    pos = idx + 1
                    continue
                pos = idx                       # real marker: resume segment walk
                break
            continue
        pos += 2 + seglen
    return None


# ---------------------------------------------------------------- PNG

def carve_png(w: Window) -> Optional[Carve]:
    pos = 8
    while pos + 12 <= w.limit:
        h = w.read(pos, 8)
        if len(h) < 8:
            return None
        length = _u32be(h, 0)
        ctype = h[4:8]
        if length > 0x7FFFFFFF or not all(0x41 <= c <= 0x7A and (c <= 0x5A or c >= 0x61) for c in ctype):
            return None
        pos += 12 + length
        if ctype == b"IEND":
            return Carve(pos, "png", True)
    return None


# ---------------------------------------------------------------- GIF

def carve_gif(w: Window) -> Optional[Carve]:
    head = w.read(0, 13)
    if len(head) < 13:
        return None
    pos = 13
    packed = head[10]
    if packed & 0x80:                           # global color table
        pos += 3 * (2 << (packed & 0x07))

    def skip_subblocks(p):
        while True:
            sz = w.read(p, 1)
            if not sz:
                return -1
            p += 1
            if sz[0] == 0:
                return p
            p += sz[0]

    while pos < w.limit:
        b = w.read(pos, 1)
        if not b:
            return None
        tag = b[0]
        pos += 1
        if tag == 0x3B:                         # trailer
            return Carve(pos, "gif", True)
        if tag == 0x21:                         # extension: label + sub-blocks
            pos = skip_subblocks(pos + 1)
        elif tag == 0x2C:                       # image descriptor
            desc = w.read(pos, 9)
            if len(desc) < 9:
                return None
            pos += 9
            if desc[8] & 0x80:                  # local color table
                pos += 3 * (2 << (desc[8] & 0x07))
            pos += 1                            # LZW min code size
            pos = skip_subblocks(pos)
        else:
            return None
        if pos < 0:
            return None
    return None


# ---------------------------------------------------------------- BMP

def carve_bmp(w: Window) -> Optional[Carve]:
    h = w.read(0, 26)
    if len(h) < 26:
        return None
    size = _u32le(h, 2)
    if not (26 <= size <= w.limit):
        return None
    if h[6:10] != b"\x00\x00\x00\x00":          # reserved must be zero
        return None
    if _u32le(h, 14) not in (12, 40, 52, 56, 64, 108, 124):  # DIB header size
        return None
    data_off = _u32le(h, 10)
    if not (26 <= data_off <= size):
        return None
    return Carve(size, "bmp", True)


# ---------------------------------------------------------------- TIFF

_TIFF_TYPE_SIZES = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2,
                    9: 4, 10: 8, 11: 4, 12: 8, 13: 4, 16: 8, 17: 8, 18: 8}


def carve_tiff(w: Window) -> Optional[Carve]:
    h = w.read(0, 8)
    if len(h) < 8:
        return None
    if h[:2] == b"II":
        u16, u32 = _u16le, _u32le
    elif h[:2] == b"MM":
        u16, u32 = _u16be, _u32be
    else:
        return None

    def values(entry, table_off, i):
        """Decode SHORT/LONG entry values (inline or external)."""
        typ, cnt = u16(entry, 2), u32(entry, 4)
        tsz = _TIFF_TYPE_SIZES.get(typ)
        if tsz is None or typ not in (3, 4):
            return []
        total = tsz * cnt
        raw = entry[8:8 + total] if total <= 4 else w.read(u32(entry, 8), total)
        if len(raw) < total:
            return []
        return [u16(raw, k * 2) if typ == 3 else u32(raw, k * 4) for k in range(cnt)]

    end = 8
    ifd = u32(h, 4)
    seen = set()
    while ifd and ifd not in seen:
        seen.add(ifd)
        nb = w.read(ifd, 2)
        if len(nb) < 2:
            return None
        n = u16(nb)
        if n == 0 or n > 4096:
            return None
        table = w.read(ifd + 2, n * 12 + 4)
        if len(table) < n * 12 + 4:
            return None
        end = max(end, ifd + 2 + n * 12 + 4)
        offsets, counts = [], []
        for i in range(n):
            e = table[i * 12:(i + 1) * 12]
            tag, typ, cnt = u16(e, 0), u16(e, 2), u32(e, 4)
            tsz = _TIFF_TYPE_SIZES.get(typ)
            if tsz is None:
                continue
            total = tsz * cnt
            if total > 4:
                end = max(end, u32(e, 8) + total)
            if tag in (273, 324):               # strip/tile offsets
                offsets = values(e, ifd + 2, i)
            elif tag in (279, 325):             # strip/tile byte counts
                counts = values(e, ifd + 2, i)
        for o, c in zip(offsets, counts):
            end = max(end, o + c)
        ifd = u32(table, n * 12)
    if end <= 8 or end > w.limit:
        return None
    return Carve(end, "tif", True)


# ---------------------------------------------------------------- PDF

def carve_pdf(w: Window) -> Optional[Carve]:
    # Bound the search at the next PDF header, if any, to avoid merging files.
    horizon = w.find(b"%PDF-", 5)
    end_limit = horizon if horizon > 0 else w.limit
    last = w.find_last(b"%%EOF", 0, end_limit)
    if last < 0:
        return None
    end = last + 5
    tail = w.read(end, 2)
    for c in tail:
        if c in (0x0D, 0x0A):
            end += 1
        else:
            break
    return Carve(end, "pdf", True)


# ---------------------------------------------------------------- ZIP family

_ZIP_HINTS = [
    (b"word/", "docx"),
    (b"xl/", "xlsx"),
    (b"ppt/", "pptx"),
    (b"AndroidManifest.xml", "apk"),
    (b"META-INF/MANIFEST.MF", "jar"),
    (b"mimetypeapplication/epub+zip", "epub"),
    (b"mimetypeapplication/vnd.oasis.opendocument", "odf"),
]


def carve_zip(w: Window) -> Optional[Carve]:
    pos = 0
    best = -1
    end = -1
    validated = False
    while True:
        eocd = w.find(b"PK\x05\x06", pos)
        if eocd < 0:
            break
        rec = w.read(eocd, 22)
        if len(rec) == 22:
            cd_size, cd_off = _u32le(rec, 12), _u32le(rec, 16)
            clen = _u16le(rec, 20)
            cand = eocd + 22 + clen
            if cand <= w.limit:
                end = cand
                if cd_off + cd_size == eocd:    # central dir lines up: real end
                    validated = True
                    break
        pos = eocd + 1
    if end < 0:
        return None
    ext = "zip"
    head = w.read(0, min(4096, end))
    for needle, hint in _ZIP_HINTS:
        if needle in head:
            ext = hint
            break
    return Carve(end, ext, validated)


# ---------------------------------------------------------------- GZIP

def carve_gzip(w: Window) -> Optional[Carve]:
    pos = 0
    while pos < w.limit:
        d = zlib.decompressobj(31)
        fed = pos
        try:
            while not d.eof:
                buf = w.read(fed, 1 << 20)
                if not buf:
                    return None                  # truncated stream
                d.decompress(buf, 1 << 24)
                while d.unconsumed_tail:
                    d.decompress(d.unconsumed_tail, 1 << 24)
                fed += len(buf)
        except zlib.error:
            return Carve(pos, "gz", True) if pos else None
        pos = fed - len(d.unused_data)
        if w.read(pos, 2) != b"\x1f\x8b":        # multi-member support
            return Carve(pos, "gz", True)
    return Carve(w.limit, "gz", False) if w.limit > 0 else None


# ---------------------------------------------------------------- 7z

def carve_7z(w: Window) -> Optional[Carve]:
    h = w.read(0, 32)
    if len(h) < 32:
        return None
    nh_off, nh_size = _u64le(h, 12), _u64le(h, 20)
    end = 32 + nh_off + nh_size
    if nh_size == 0 or end > w.limit:
        return None
    return Carve(end, "7z", True)


# ---------------------------------------------------------------- RAR (fallback)

def carve_rar(w: Window) -> Optional[Carve]:
    # No cheap exact-size structure; carve a capped window, unvalidated.
    if w.limit < 20:                             # smaller than any real archive
        return None
    return Carve(w.limit, "rar", False)


# ---------------------------------------------------------------- SQLite

def carve_sqlite(w: Window) -> Optional[Carve]:
    h = w.read(0, 100)
    if len(h) < 100:
        return None
    page_size = _u16be(h, 16)
    if page_size == 1:
        page_size = 65536
    if page_size < 512 or page_size & (page_size - 1):
        return None
    if h[18] not in (1, 2) or h[19] not in (1, 2):
        return None
    page_count = _u32be(h, 28)
    if page_count == 0:                          # legacy: header count unset
        return Carve(w.limit, "sqlite", False)
    size = page_size * page_count
    if size > w.limit:
        return None
    return Carve(size, "sqlite", True)


# ---------------------------------------------------------------- MP4 / MOV

_MP4_BOXES = {b"ftyp", b"moov", b"mdat", b"free", b"skip", b"wide", b"pnot",
              b"udta", b"uuid", b"moof", b"mfra", b"meta", b"styp", b"sidx",
              b"ssix", b"prft", b"pdin"}


def carve_mp4(w: Window) -> Optional[Carve]:
    pos = 0
    boxes = 0
    while pos + 8 <= w.limit:
        h = w.read(pos, 16)
        if len(h) < 8:
            break
        size = _u32be(h, 0)
        btype = h[4:8]
        if btype not in _MP4_BOXES:
            break
        if size == 1:
            if len(h) < 16:
                return None
            size = _u64be(h, 8)
        elif size == 0:                          # box extends to end of file
            size = w.limit - pos
        if size < 8 or pos + size > w.limit:
            return None
        pos += size
        boxes += 1
    if boxes < 2:                                # require ftyp + at least one box
        return None
    return Carve(pos, _bmff_ext(w), True)


_BMFF_BRANDS = {
    b"qt  ": "mov", b"heic": "heic", b"heix": "heic", b"heim": "heic",
    b"heis": "heic", b"hevc": "heic", b"mif1": "heic", b"msf1": "heic",
    b"avif": "avif", b"avis": "avif", b"3gp": "3gp", b"3g2": "3g2",
    b"M4A ": "m4a", b"M4V ": "m4v", b"f4v": "f4v", b"qt": "mov",
}


def _bmff_ext(w: Window) -> str:
    """Pick an extension from the ftyp major brand + compatible brands."""
    ftyp_len = _u32be(w.read(0, 4))
    brands = w.read(8, max(0, min(ftyp_len, 64) - 8))
    major = brands[:4]
    if major in _BMFF_BRANDS:
        return _BMFF_BRANDS[major]
    for i in range(0, len(brands) - 3, 4):     # scan compatible brands
        b = brands[i:i + 4]
        if b in _BMFF_BRANDS:
            return _BMFF_BRANDS[b]
    if major.startswith(b"qt"):
        return "mov"
    return "mp4"


# ---------------------------------------------------------------- RIFF

_RIFF_EXT = {b"WAVE": "wav", b"AVI ": "avi", b"WEBP": "webp"}


def carve_riff(w: Window) -> Optional[Carve]:
    h = w.read(0, 12)
    if len(h) < 12:
        return None
    form = h[8:12]
    ext = _RIFF_EXT.get(form)
    if ext is None:
        return None
    size = _u32le(h, 4) + 8
    if size > w.limit:
        return None
    return Carve(size, ext, True)


# ---------------------------------------------------------------- MP3 (ID3v2)

_MP3_BITRATES = {
    (1, 1): [0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448],
    (1, 2): [0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384],
    (1, 3): [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320],
    (2, 1): [0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256],
    (2, 2): [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160],
    (2, 3): [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160],
}
_MP3_RATES = {3: [44100, 48000, 32000], 2: [22050, 24000, 16000], 0: [11025, 12000, 8000]}


def _mp3_frame_len(h: bytes) -> Optional[int]:
    if len(h) < 4 or h[0] != 0xFF or (h[1] & 0xE0) != 0xE0:
        return None
    version = (h[1] >> 3) & 0x03                 # 0=2.5, 2=2, 3=1
    layer = (h[1] >> 1) & 0x03                   # 1=III, 2=II, 3=I
    if version == 1 or layer == 0:
        return None
    vgroup = 1 if version == 3 else 2
    lnum = 4 - layer                             # 1=I, 2=II, 3=III
    br_idx = (h[2] >> 4) & 0x0F
    sr_idx = (h[2] >> 2) & 0x03
    pad = (h[2] >> 1) & 0x01
    if br_idx in (0, 15) or sr_idx == 3:
        return None
    bitrate = _MP3_BITRATES[(vgroup, lnum)][br_idx] * 1000
    rate = _MP3_RATES[version][sr_idx]
    if lnum == 1:
        return (12 * bitrate // rate + pad) * 4
    coeff = 144 if (lnum == 2 or vgroup == 1) else 72
    return coeff * bitrate // rate + pad


def carve_mp3(w: Window) -> Optional[Carve]:
    h = w.read(0, 10)
    if len(h) < 10 or h[3] >= 0x10 or h[4] >= 0x10:
        return None
    if any(b & 0x80 for b in h[6:10]):
        return None
    pos = 10 + (h[6] << 21 | h[7] << 14 | h[8] << 7 | h[9])  # synchsafe size
    frames = 0
    while pos + 4 <= w.limit:
        flen = _mp3_frame_len(w.read(pos, 4))
        if flen is None:
            if w.read(pos, 3) == b"TAG":         # trailing ID3v1
                pos += 128
            break
        if pos + flen > w.limit:                 # frame truncated at EOF/limit
            break
        pos += flen
        frames += 1
    if frames < 1:
        return None
    return Carve(pos, "mp3", frames > 10)


# ---------------------------------------------------------------- PE (EXE/DLL)

def carve_pe(w: Window) -> Optional[Carve]:
    dos = w.read(0, 64)
    if len(dos) < 64:
        return None
    e_lfanew = _u32le(dos, 60)
    if not (64 <= e_lfanew <= 0x10000):
        return None
    pe = w.read(e_lfanew, 24)
    if len(pe) < 24 or pe[:4] != b"PE\x00\x00":
        return None
    nsections = _u16le(pe, 6)
    opt_size = _u16le(pe, 20)
    if not (1 <= nsections <= 96) or opt_size < 64:
        return None
    opt = w.read(e_lfanew + 24, opt_size)
    if len(opt) < opt_size or _u16le(opt, 0) not in (0x10B, 0x20B):
        return None
    end = e_lfanew + 24 + opt_size + nsections * 40
    sects = w.read(e_lfanew + 24 + opt_size, nsections * 40)
    if len(sects) < nsections * 40:
        return None
    for i in range(nsections):
        raw_size = _u32le(sects, i * 40 + 16)
        raw_ptr = _u32le(sects, i * 40 + 20)
        if raw_ptr:
            end = max(end, raw_ptr + raw_size)
    # Authenticode certificate table sits beyond sections (file offset, not RVA).
    dd_off = 96 if _u16le(opt, 0) == 0x10B else 112
    if opt_size >= dd_off + 40:
        cert_off, cert_size = _u32le(opt, dd_off + 32), _u32le(opt, dd_off + 36)
        if cert_off and cert_size:
            end = max(end, cert_off + cert_size)
    if end > w.limit:
        return None
    ext = "dll" if _u16le(pe, 22) & 0x2000 else "exe"
    return Carve(end, ext, True)


# ---------------------------------------------------------------- ELF

def carve_elf(w: Window) -> Optional[Carve]:
    h = w.read(0, 64)
    if len(h) < 52:
        return None
    ei_class, ei_data = h[4], h[5]
    if ei_class not in (1, 2) or ei_data not in (1, 2):
        return None
    u16 = _u16le if ei_data == 1 else _u16be
    u32 = _u32le if ei_data == 1 else _u32be
    u64 = _u64le if ei_data == 1 else _u64be
    if ei_class == 1:                            # 32-bit
        e_phoff, e_shoff = u32(h, 28), u32(h, 32)
        e_phentsize, e_phnum = u16(h, 42), u16(h, 44)
        e_shentsize, e_shnum = u16(h, 46), u16(h, 48)
    else:                                        # 64-bit
        if len(h) < 64:
            return None
        e_phoff, e_shoff = u64(h, 32), u64(h, 40)
        e_phentsize, e_phnum = u16(h, 54), u16(h, 56)
        e_shentsize, e_shnum = u16(h, 58), u16(h, 60)
    end = 0
    if e_shoff and e_shnum:
        end = e_shoff + e_shnum * e_shentsize
    elif e_phoff and e_phnum:
        ph = w.read(e_phoff, e_phnum * e_phentsize)
        if len(ph) < e_phnum * e_phentsize:
            return None
        for i in range(e_phnum):
            base = i * e_phentsize
            if ei_class == 1:
                p_offset, p_filesz = u32(ph, base + 4), u32(ph, base + 16)
            else:
                p_offset, p_filesz = u64(ph, base + 8), u64(ph, base + 32)
            end = max(end, p_offset + p_filesz)
    if end <= 52 or end > w.limit:
        return None
    return Carve(end, "elf", True)


# ---------------------------------------------------------------- Mach-O

_MACHO_MAGICS = {
    b"\xcf\xfa\xed\xfe": (64, "little"), b"\xce\xfa\xed\xfe": (32, "little"),
    b"\xfe\xed\xfa\xcf": (64, "big"), b"\xfe\xed\xfa\xce": (32, "big"),
}


def _macho_thin_size(w: Window, base: int) -> Optional[int]:
    h = w.read(base, 32)
    if len(h) < 32:
        return None
    variant = _MACHO_MAGICS.get(h[:4])
    if variant is None:
        return None
    bits, endian = variant
    def u32(b, o): return int.from_bytes(b[o:o + 4], endian)
    def u64(b, o): return int.from_bytes(b[o:o + 8], endian)
    ncmds, sizeofcmds = u32(h, 16), u32(h, 20)
    if not (1 <= ncmds <= 4096):
        return None
    hdr_len = 32 if bits == 64 else 28
    cmds = w.read(base + hdr_len, sizeofcmds)
    if len(cmds) < sizeofcmds:
        return None
    end = hdr_len + sizeofcmds
    pos = 0
    for _ in range(ncmds):
        if pos + 8 > len(cmds):
            return None
        cmd, cmdsize = u32(cmds, pos), u32(cmds, pos + 4)
        if cmdsize < 8 or pos + cmdsize > len(cmds):
            return None
        if cmd == 0x19 and cmdsize >= 56:        # LC_SEGMENT_64
            end = max(end, u64(cmds, pos + 40) + u64(cmds, pos + 48))
        elif cmd == 0x01 and cmdsize >= 40:      # LC_SEGMENT
            end = max(end, u32(cmds, pos + 32) + u32(cmds, pos + 36))
        elif cmd == 0x02 and cmdsize >= 24:      # LC_SYMTAB
            nlist = 16 if bits == 64 else 12
            end = max(end, u32(cmds, pos + 8) + u32(cmds, pos + 12) * nlist,
                      u32(cmds, pos + 16) + u32(cmds, pos + 20))
        elif cmd in (0x1D, 0x1E, 0x26, 0x29, 0x2B, 0x2E, 0x2F) and cmdsize >= 16:
            end = max(end, u32(cmds, pos + 8) + u32(cmds, pos + 12))  # linkedit_data
        pos += cmdsize
    return end if end > hdr_len else None


def carve_macho(w: Window) -> Optional[Carve]:
    h = w.read(0, 8)
    if len(h) < 8:
        return None
    if h[:4] == b"\xca\xfe\xba\xbe":             # fat/universal (vs Java .class:
        nfat = _u32be(h, 4)                      # class has version word here, >~45)
        if not (1 <= nfat <= 18):
            return None
        table = w.read(8, nfat * 20)
        if len(table) < nfat * 20:
            return None
        end = 0
        for i in range(nfat):
            a_off = _u32be(table, i * 20 + 8)
            a_size = _u32be(table, i * 20 + 12)
            if a_off + a_size > w.limit:
                return None
            if _macho_thin_size(w, a_off) is None:  # each slice must be Mach-O
                return None
            end = max(end, a_off + a_size)
        return Carve(end, "macho", True)
    end = _macho_thin_size(w, 0)
    if end is None or end > w.limit:
        return None
    return Carve(end, "macho", True)


# ---------------------------------------------------------------- OLE2 / CFB

_OLE_HINTS = [
    ("W\x00o\x00r\x00d\x00D\x00o\x00c\x00u\x00m\x00e\x00n\x00t".encode("latin-1"), "doc"),
    ("W\x00o\x00r\x00k\x00b\x00o\x00o\x00k".encode("latin-1"), "xls"),
    ("P\x00o\x00w\x00e\x00r\x00P\x00o\x00i\x00n\x00t".encode("latin-1"), "ppt"),
]

_FREESECT = 0xFFFFFFFF


def carve_ole(w: Window) -> Optional[Carve]:
    h = w.read(0, 512)
    if len(h) < 512:
        return None
    shift = _u16le(h, 30)
    if shift not in (9, 12):
        return None
    sector = 1 << shift
    per_sector = sector // 4

    def fallback():
        return Carve(min(w.limit, 8 << 20), "ole", False)

    # Collect FAT sector locations: 109 header DIFAT entries + DIFAT chain.
    fat_sectors = []
    for i in range(109):
        v = _u32le(h, 76 + i * 4)
        if v != _FREESECT:
            fat_sectors.append(v)
    dif_sect = _u32le(h, 68)
    dif_count = _u32le(h, 72)
    hops = 0
    while dif_sect != 0xFFFFFFFE and dif_sect != _FREESECT and hops < dif_count + 4:
        blk = w.read((dif_sect + 1) * sector, sector)
        if len(blk) < sector:
            return fallback()
        for i in range(per_sector - 1):
            v = _u32le(blk, i * 4)
            if v != _FREESECT:
                fat_sectors.append(v)
        dif_sect = _u32le(blk, (per_sector - 1) * 4)
        hops += 1

    if not fat_sectors:
        return fallback()
    max_used = -1
    idx_base = 0
    for fs in fat_sectors:
        blk = w.read((fs + 1) * sector, sector)
        if len(blk) < sector:
            return fallback()
        for i in range(per_sector):
            if _u32le(blk, i * 4) != _FREESECT:
                max_used = max(max_used, idx_base + i)
        idx_base += per_sector
    if max_used < 0:
        return fallback()
    end = (max_used + 2) * sector                # header occupies "sector -1"
    if end > w.limit:
        return fallback()
    ext = "ole"
    for needle, hint in _OLE_HINTS:
        if w.find(needle, 0, end) >= 0:
            ext = hint
            break
    return Carve(end, ext, True)


# ---------------------------------------------------------------- Matroska / WebM (EBML)

def _ebml_vint(w: Window, pos: int, keep_marker: bool = False):
    """Read an EBML variable-length integer at pos -> (value, length)."""
    first = w.read(pos, 1)
    if not first:
        return None, 0
    b0 = first[0]
    if b0 == 0:
        return None, 0
    length = 8 - b0.bit_length() + 1
    raw = w.read(pos, length)
    if len(raw) < length:
        return None, 0
    val = int.from_bytes(raw, "big")
    if not keep_marker:                          # strip the length-marker bit
        val &= (1 << (7 * length)) - 1
    return val, length


def carve_mkv(w: Window) -> Optional[Carve]:
    # EBML header: 0x1A45DFA3, then a Segment (0x18538067) we size via its vint.
    hdr_size, n = _ebml_vint(w, 4)
    if hdr_size is None or hdr_size > (1 << 20):
        return None
    pos = 4 + n + hdr_size
    if w.read(pos, 4) != b"\x18\x53\x80\x67":    # Segment element id
        return None
    seg_size, n2 = _ebml_vint(w, pos + 4)
    pos += 4 + n2
    unknown = seg_size is None or seg_size >= (1 << (7 * n2)) - 1
    doctype = b"webm" if w.find(b"webm", 0, 64) >= 0 else b"mkv"
    ext = "webm" if doctype == b"webm" else "mkv"
    if unknown:                                  # live-streamed: size not stored
        return Carve(min(w.limit, 256 * MB), ext, False)
    end = pos + seg_size
    if end > w.limit:
        return None
    return Carve(end, ext, True)


# ---------------------------------------------------------------- FLAC

def carve_flac(w: Window) -> Optional[Carve]:
    pos = 4                                      # past "fLaC"
    last = False
    while not last:
        h = w.read(pos, 4)
        if len(h) < 4:
            return None
        last = bool(h[0] & 0x80)
        block_len = (h[1] << 16) | (h[2] << 8) | h[3]  # 24-bit length in h[1:4]
        pos += 4 + block_len
    # Frames follow; no length field. Scan to next stream / EOF for frame data.
    nxt = w.find(b"fLaC", pos)
    end = nxt if nxt > 0 else w.limit
    return Carve(end, "flac", nxt > 0)


# ---------------------------------------------------------------- OGG

def carve_ogg(w: Window) -> Optional[Carve]:
    pos = 0
    last_end = 0
    pages = 0
    while True:
        if w.read(pos, 4) != b"OggS":
            break
        seg_count = w.read(pos + 26, 1)
        if not seg_count:
            break
        nseg = seg_count[0]
        table = w.read(pos + 27, nseg)
        if len(table) < nseg:
            break
        body = sum(table)
        header = (w.read(pos + 5, 1) or b"\x00")[0]
        pos += 27 + nseg + body
        if pos > w.limit:                        # page body runs past EOF/limit
            break
        last_end = pos
        pages += 1
        if header & 0x04:                        # last page of logical stream
            break
        if pages > 1_000_000:
            break
    if pages == 0:
        return None
    return Carve(last_end, "ogg", True)


# ---------------------------------------------------------------- PSD

def carve_psd(w: Window) -> Optional[Carve]:
    h = w.read(0, 26)
    if len(h) < 26 or h[:4] != b"8BPS":
        return None
    pos = 26
    for _ in range(4):                           # color mode, image resources,
        seclen = _u32be(w.read(pos, 4))          # layer/mask, then image data
        pos += 4 + seclen
        if pos > w.limit:
            return None
    # image data section has no length; runs to EOF/next file. Best-effort.
    nxt = w.find(b"8BPS", pos)
    end = nxt if nxt > 0 else w.limit
    return Carve(end, "psd", False)


# ---------------------------------------------------------------- ICO / CUR

def carve_ico(w: Window) -> Optional[Carve]:
    h = w.read(0, 6)
    if len(h) < 6:
        return None
    rtype = _u16le(h, 2)
    count = _u16le(h, 4)
    if rtype not in (1, 2) or not (1 <= count <= 512):
        return None
    end = 6 + count * 16
    entries = w.read(6, count * 16)
    if len(entries) < count * 16:
        return None
    for i in range(count):
        size = _u32le(entries, i * 16 + 8)
        off = _u32le(entries, i * 16 + 12)
        if off < end or size == 0:
            return None
        end = max(end, off + size)
    if end > w.limit:
        return None
    return Carve(end, "ico" if rtype == 1 else "cur", True)


# ---------------------------------------------------------------- EVTX (Windows event log)

def carve_evtx(w: Window) -> Optional[Carve]:
    h = w.read(0, 48)
    if len(h) < 48 or h[:8] != b"ElfFile\x00":
        return None
    num_chunks = _u16le(h, 40)
    if not (1 <= num_chunks <= 0x10000):
        return None
    # 4096-byte file header + 65536 bytes per chunk
    end = 4096 + num_chunks * 65536
    if end > w.limit:
        return None
    return Carve(end, "evtx", True)


# ---------------------------------------------------------------- Registry hive (regf)

def carve_regf(w: Window) -> Optional[Carve]:
    h = w.read(0, 48)
    if len(h) < 48 or h[:4] != b"regf":
        return None
    hbins_size = _u32le(h, 40)                   # size of data area after header
    if hbins_size == 0 or hbins_size > w.limit:
        return None
    end = 4096 + hbins_size                      # 4 KiB base block + hbins
    if end > w.limit:
        return None
    return Carve(end, "hive", True)


# ---------------------------------------------------------------- Binary plist

def carve_bplist(w: Window) -> Optional[Carve]:
    if w.read(0, 8) != b"bplist00":
        return None
    # File = header | objects | offset-table | 32-byte trailer. The trailer's
    # offset_table_start + num_objects*offset_size points at the trailer, so a
    # candidate end is valid iff that identity holds. Walk back from the next
    # plist header (or EOF), bounded, to tolerate trailing junk.
    nxt = w.find(b"bplist00", 8)
    horizon = nxt if nxt > 0 else w.limit
    floor = max(40, horizon - (1 << 20))         # bound the backward scan
    for end in range(horizon, floor, -1):
        tr = w.read(end - 32, 32)
        if len(tr) < 32:
            continue
        offset_size = tr[6]
        num_objects = _u64be(tr, 8)
        ot_start = _u64be(tr, 24)
        if (1 <= offset_size <= 8 and 0 < num_objects < (1 << 32)
                and 8 <= ot_start < end - 32
                and ot_start + num_objects * offset_size == end - 32):
            return Carve(end, "plist", True)
    return None
