"""Forensic/virtual image-format readers.

Each reader exposes the same surface as reader.Reader:
    .size, .is_device (False), .path, pread(offset, length) -> bytes, close(),
    and context-manager support.

open_source(path) auto-detects the format by magic/extension and returns the
right reader (falling back to a plain raw Reader). Supported:
    raw / dd            - Reader
    split raw           - .001/.002... or name.NNN segments concatenated
    EWF / E01           - via pyewf if installed, else a minimal uncompressed/
                          zlib-chunk parser
    QCOW2 (v2/v3)       - L1/L2 mapping, raw + zlib-compressed clusters
    VMDK                - flat + monolithic-sparse (grain tables)
"""

import os
import re
import sys
import tempfile
import zlib

from .reader import Reader

# BitLocker (FVE) transparent decryption layer; see bitlocker.py.


class BitLockerDecryptingReader:
    """Pass-through reader that decrypts BitLocker volume region(s) in place.

    Absolute offsets are preserved: a locked volume at byte `base` reads back as
    its plaintext NTFS, so partition parsing, --offset, and --auto all keep
    working unchanged. Bytes outside any unlocked volume pass through verbatim.
    """

    def __init__(self, base_reader, volumes):
        self.reader = base_reader
        self.size = base_reader.size
        self.is_device = getattr(base_reader, "is_device", False)
        self.path = base_reader.path
        self.volumes = sorted(volumes, key=lambda v: v.base)

    def _vol_at(self, pos):
        for v in self.volumes:
            if v.base <= pos < v.base + v.size:
                return v
        return None

    def _next_base(self, pos, end):
        nxt = end
        for v in self.volumes:
            if pos < v.base < nxt:
                nxt = v.base
        return nxt

    def pread(self, offset, length):
        if offset >= self.size or length <= 0:
            return b""
        length = min(length, self.size - offset)
        out = bytearray()
        pos, end = offset, offset + length
        while pos < end:
            vol = self._vol_at(pos)
            if vol:
                vend = min(end, vol.base + vol.size)
                out += vol.read(pos - vol.base, vend - pos)
                pos = vend
            else:
                nxt = self._next_base(pos, end)
                out += self.reader.pread(pos, nxt - pos)
                pos = nxt
        return bytes(out)

    def close(self):
        self.reader.close()

    def __enter__(self): return self
    def __exit__(self, *a): self.close()


def scan_bitlocker(reader, creds):
    """Find BitLocker volumes (whole-disk + each partition) and unlock them."""
    from . import bitlocker
    from .partition import parse

    bases = set()
    if bitlocker.is_bitlocker(reader, 0):
        bases.add(0)
    try:
        for p in parse(reader):
            if p.start and bitlocker.is_bitlocker(reader, p.start):
                bases.add(p.start)
    except Exception:
        pass

    def _log(msg):
        print(msg, file=sys.stderr)

    vols = []
    for base in sorted(bases):
        try:
            v = bitlocker.unlock_volume(reader, base, creds, log=_log)
            if v:
                vols.append(v)
        except bitlocker.BitLockerError as e:
            print(f"bitlocker: volume @ {base:#x}: {e}", file=sys.stderr)
    return vols


def _u32be(b, o=0): return int.from_bytes(b[o:o + 4], "big")
def _u64be(b, o=0): return int.from_bytes(b[o:o + 8], "big")
def _u32le(b, o=0): return int.from_bytes(b[o:o + 4], "little")
def _u64le(b, o=0): return int.from_bytes(b[o:o + 8], "little")


# ---------------------------------------------------------------- split raw

_SPLIT_RE = re.compile(r"^(.*?)\.(\d{2,3})$")


class SplitRawReader:
    """Concatenate numbered raw segments (image.001, image.002, ...)."""

    def __init__(self, first_segment: str):
        m = _SPLIT_RE.match(first_segment)
        if not m:
            raise ValueError("not a split-raw segment name")
        stem, digits = m.group(1), m.group(2)
        width = len(digits)
        self.path = first_segment
        self.segments = []
        self.offsets = []
        total = 0
        i = int(digits)
        while True:
            seg = f"{stem}.{i:0{width}d}"
            if not os.path.exists(seg):
                break
            sz = os.path.getsize(seg)
            self.segments.append((seg, total, sz))
            self.offsets.append(total)
            total += sz
            i += 1
        if not self.segments:
            raise ValueError("no split-raw segments found")
        self.size = total
        self.is_device = False
        self._fds = {}

    def _fd(self, seg):
        fd = self._fds.get(seg)
        if fd is None:
            fd = os.open(seg, os.O_RDONLY)
            self._fds[seg] = fd
        return fd

    def pread(self, offset, length):
        if offset >= self.size or length <= 0:
            return b""
        length = min(length, self.size - offset)
        out = bytearray()
        for seg, base, sz in self.segments:
            if offset >= base + sz or len(out) >= length:
                continue
            if offset + (length - len(out)) <= base:
                break
            local = max(0, offset - base)
            want = min(sz - local, length - len(out))
            out += os.pread(self._fd(seg), want, local)
            offset = base + local + want
        return bytes(out)

    def close(self):
        for fd in self._fds.values():
            os.close(fd)
        self._fds.clear()

    def __enter__(self): return self
    def __exit__(self, *a): self.close()


# ---------------------------------------------------------------- QCOW2

class Qcow2Reader:
    def __init__(self, path: str):
        self.path = path
        self.is_device = False
        self.fd = os.open(path, os.O_RDONLY)
        hdr = os.pread(self.fd, 104, 0)
        if hdr[:4] != b"QFI\xfb":
            os.close(self.fd)
            raise ValueError("not a QCOW2 image")
        self.version = _u32be(hdr, 4)
        self.cluster_bits = _u32be(hdr, 20)
        self.cluster_size = 1 << self.cluster_bits
        self.size = _u64be(hdr, 24)
        self.l1_size = _u32be(hdr, 36)
        self.l1_offset = _u64be(hdr, 40)
        self.l2_size = self.cluster_size // 8
        self._l1 = self._read_l1()
        self._l2_cache = {}

    def _read_l1(self):
        raw = os.pread(self.fd, self.l1_size * 8, self.l1_offset)
        return [_u64be(raw, i * 8) for i in range(self.l1_size)]

    def _l2_table(self, l2_off):
        t = self._l2_cache.get(l2_off)
        if t is None:
            raw = os.pread(self.fd, self.cluster_size, l2_off)
            t = raw
            if len(self._l2_cache) > 64:
                self._l2_cache.clear()
            self._l2_cache[l2_off] = t
        return t

    _L1_OFFSET_MASK = 0x00FFFFFFFFFFFE00
    _L2_OFFSET_MASK = 0x00FFFFFFFFFFFE00
    _COMPRESSED = 1 << 62

    def _read_cluster(self, vaddr):
        """Return one cluster of guest data starting at vaddr (cluster-aligned)."""
        l2_per = self.l2_size
        cluster_idx = vaddr >> self.cluster_bits
        l1_idx = cluster_idx // l2_per
        l2_idx = cluster_idx % l2_per
        if l1_idx >= len(self._l1):
            return bytes(self.cluster_size)
        l1_entry = self._l1[l1_idx] & self._L1_OFFSET_MASK
        if l1_entry == 0:
            return bytes(self.cluster_size)
        l2 = self._l2_table(l1_entry)
        entry = _u64be(l2, l2_idx * 8)
        if entry & self._COMPRESSED:
            return self._read_compressed(entry)
        host = entry & self._L2_OFFSET_MASK
        if host == 0:
            return bytes(self.cluster_size)
        return os.pread(self.fd, self.cluster_size, host)

    def _read_compressed(self, entry):
        # compressed descriptor: x = 62-cluster_bits bits offset field width
        x = 62 - (self.cluster_bits - 8)
        offset = entry & ((1 << x) - 1)
        nsectors = (entry >> x) & ((1 << (62 - x)) - 1)
        nbytes = (nsectors + 1) * 512 - (offset & 511)
        comp = os.pread(self.fd, nbytes, offset)
        try:
            d = zlib.decompressobj(-zlib.MAX_WBITS)
            out = d.decompress(comp, self.cluster_size)
            return out.ljust(self.cluster_size, b"\x00")
        except zlib.error:
            return bytes(self.cluster_size)

    def pread(self, offset, length):
        if offset >= self.size or length <= 0:
            return b""
        length = min(length, self.size - offset)
        out = bytearray()
        pos = offset
        while len(out) < length:
            base = pos & ~(self.cluster_size - 1)
            cluster = self._read_cluster(base)
            start = pos - base
            take = min(self.cluster_size - start, length - len(out))
            out += cluster[start:start + take]
            pos += take
        return bytes(out)

    def close(self):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self): return self
    def __exit__(self, *a): self.close()


# ---------------------------------------------------------------- VMDK

class VmdkReader:
    """Monolithic sparse + flat VMDK. (Stream-optimized/compressed handled via
    grain markers is not supported; falls back to raw if descriptor-only.)"""

    def __init__(self, path: str):
        self.path = path
        self.is_device = False
        self.fd = os.open(path, os.O_RDONLY)
        magic = os.pread(self.fd, 4, 0)
        if magic == b"KDMV":                     # SparseExtentHeader
            self._init_sparse()
        else:
            os.close(self.fd)
            raise ValueError("not a sparse VMDK (flat/descriptor handled as raw)")

    def _init_sparse(self):
        h = os.pread(self.fd, 512, 0)
        self.cap_sectors = _u64le(h, 12)
        self.grain_size = _u64le(h, 20)          # in sectors
        self.gd_offset = _u64le(h, 56)           # grain directory offset (sectors)
        self.num_gtes_per_gt = _u32le(h, 44)
        self.size = self.cap_sectors * 512
        self.grain_bytes = self.grain_size * 512
        gd_entries = (self.cap_sectors + self.grain_size * self.num_gtes_per_gt - 1) \
            // (self.grain_size * self.num_gtes_per_gt)
        gd_raw = os.pread(self.fd, gd_entries * 4, self.gd_offset * 512)
        self._gd = [_u32le(gd_raw, i * 4) for i in range(gd_entries)]
        self._gt_cache = {}

    def _grain_offset_sectors(self, grain_idx):
        gt_idx = grain_idx // self.num_gtes_per_gt
        gte_idx = grain_idx % self.num_gtes_per_gt
        if gt_idx >= len(self._gd) or self._gd[gt_idx] == 0:
            return 0
        gt = self._gt_cache.get(gt_idx)
        if gt is None:
            gt = os.pread(self.fd, self.num_gtes_per_gt * 4, self._gd[gt_idx] * 512)
            self._gt_cache[gt_idx] = gt
        return _u32le(gt, gte_idx * 4)

    def pread(self, offset, length):
        if offset >= self.size or length <= 0:
            return b""
        length = min(length, self.size - offset)
        out = bytearray()
        pos = offset
        while len(out) < length:
            grain_idx = pos // self.grain_bytes
            base = grain_idx * self.grain_bytes
            within = pos - base
            take = min(self.grain_bytes - within, length - len(out))
            sec = self._grain_offset_sectors(grain_idx)
            if sec == 0:
                out += bytes(take)
            else:
                out += os.pread(self.fd, take, sec * 512 + within)
            pos += take
        return bytes(out)

    def close(self):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self): return self
    def __exit__(self, *a): self.close()


# ---------------------------------------------------------------- EWF / E01

class EwfPyReader:
    """EWF via libewf's pyewf bindings (handles all compression + segmenting)."""

    def __init__(self, path: str):
        import pyewf
        self.path = path
        self.is_device = False
        filenames = pyewf.glob(path)
        self._h = pyewf.handle()
        self._h.open(filenames)
        self.size = self._h.get_media_size()

    def pread(self, offset, length):
        if offset >= self.size or length <= 0:
            return b""
        self._h.seek(offset)
        return self._h.read(min(length, self.size - offset))

    def close(self):
        try:
            self._h.close()
        except Exception:
            pass

    def __enter__(self): return self
    def __exit__(self, *a): self.close()


class EwfReader:
    """Minimal EWF (E01) parser: walks sections, builds a chunk table, and
    decompresses zlib chunks on demand. Handles single- or multi-segment sets.
    Falls back where the format uses features it doesn't model."""

    def __init__(self, path: str):
        self.path = path
        self.is_device = False
        self.segments = self._glob(path)
        self._fds = {}
        self.chunk_size = None
        self.bytes_per_sector = 512
        self.size = 0
        self._chunks = []          # (segment_idx, file_offset, compressed)
        self._parse()

    @staticmethod
    def _glob(path):
        # E01, E02, ... or .e01/.ex01 style
        m = re.match(r"(?i)^(.*)\.(e|s|l)(01|x01)$", path)
        if not m:
            if not os.path.exists(path):
                raise ValueError("EWF segment not found")
            return [path]
        stem, kind = m.group(1), m.group(2)
        segs = []
        n = 1
        while True:
            cand = f"{stem}.{kind}{n:02d}"
            if not os.path.exists(cand):
                cand2 = f"{stem}.{kind}x{n:02d}"
                if os.path.exists(cand2):
                    cand = cand2
                else:
                    break
            segs.append(cand)
            n += 1
        return segs or [path]

    def _fd(self, idx):
        fd = self._fds.get(idx)
        if fd is None:
            fd = os.open(self.segments[idx], os.O_RDONLY)
            self._fds[idx] = fd
        return fd

    def _parse(self):
        for sidx, seg in enumerate(self.segments):
            fd = self._fd(sidx)
            sig = os.pread(fd, 13, 0)
            if sig[:8] != b"EVF\x09\x0d\x0a\xff\x00":
                raise ValueError("not an EWF/E01 image")
            offset = 13
            table_base = 0
            while True:
                desc = os.pread(fd, 76, offset)
                if len(desc) < 76:
                    break
                stype = desc[:16].split(b"\x00", 1)[0]
                next_off = _u64le(desc, 16)
                data_off = offset + 76
                if stype == b"volume" or stype == b"disk":
                    vol = os.pread(fd, 1052, data_off)
                    # EWF volume: chunk_count(4) sectors_per_chunk(4)
                    # bytes_per_sector(4) sector_count(4) ...
                    spc = _u32le(vol, 4)
                    bps = _u32le(vol, 8)
                    self.bytes_per_sector = bps or 512
                    self.chunk_size = spc * self.bytes_per_sector
                elif stype == b"sectors":
                    table_base = data_off
                elif stype in (b"table",):
                    self._parse_table(fd, sidx, data_off, table_base)
                if next_off == 0 or next_off == offset:
                    break
                offset = next_off
        if self.chunk_size:
            self.size = self._media_size()

    def _parse_table(self, fd, sidx, data_off, sectors_base):
        hdr = os.pread(fd, 24, data_off)
        count = _u32le(hdr, 0)
        base_off = _u64le(hdr, 8) if count and len(hdr) >= 16 else 0
        entries = os.pread(fd, count * 4, data_off + 24)
        for i in range(count):
            v = _u32le(entries, i * 4)
            compressed = bool(v & 0x80000000)
            file_off = (v & 0x7FFFFFFF) + (base_off if base_off else 0)
            self._chunks.append((sidx, file_off, compressed))

    def _media_size(self):
        # last chunk may be partial; without per-chunk sizes we assume full and
        # rely on filesystem/carver tolerating trailing slack.
        return len(self._chunks) * self.chunk_size

    def _read_chunk(self, idx):
        sidx, foff, comp = self._chunks[idx]
        fd = self._fd(sidx)
        if comp:
            raw = os.pread(fd, self.chunk_size * 2 + 1024, foff)
            try:
                return zlib.decompress(raw)[:self.chunk_size]
            except zlib.error:
                return zlib.decompressobj().decompress(raw, self.chunk_size)
        return os.pread(fd, self.chunk_size, foff)

    def pread(self, offset, length):
        if not self.chunk_size or offset >= self.size or length <= 0:
            return b""
        length = min(length, self.size - offset)
        out = bytearray()
        pos = offset
        while len(out) < length:
            cidx = pos // self.chunk_size
            if cidx >= len(self._chunks):
                break
            base = cidx * self.chunk_size
            chunk = self._read_chunk(cidx)
            start = pos - base
            take = min(len(chunk) - start, length - len(out))
            if take <= 0:
                break
            out += chunk[start:start + take]
            pos += take
        return bytes(out)

    def close(self):
        for fd in self._fds.values():
            os.close(fd)
        self._fds.clear()

    def __enter__(self): return self
    def __exit__(self, *a): self.close()


# ---------------------------------------------------------------- stdin spool

class StdinReader(Reader):
    """Spool a non-seekable stream (stdin / pipe) to a temp file, then read it
    with random access. Handlers need to seek, so a pipe must be materialized;
    this supports `dd if=/dev/sdb | carvx -` up to available temp-disk space."""

    def __init__(self, stream=None, spool_dir=None):
        stream = stream if stream is not None else sys.stdin.buffer
        fd, self._tmp = tempfile.mkstemp(prefix="carvx_stdin_", dir=spool_dir)
        try:
            while True:
                chunk = stream.read(8 << 20)
                if not chunk:
                    break
                os.write(fd, chunk)
        finally:
            os.close(fd)
        super().__init__(self._tmp)
        self.path = "-"

    def close(self):
        super().close()
        try:
            os.unlink(self._tmp)
        except OSError:
            pass


# ---------------------------------------------------------------- factory

def open_source(path: str):
    """Detect the image format, then transparently decrypt BitLocker volumes if
    a credential is configured (env CARVX_BITLOCKER); else return the raw reader."""
    reader = _open_raw(path)
    from . import bitlocker
    creds = bitlocker.Credentials.from_env()
    if creds:
        vols = scan_bitlocker(reader, creds)
        if vols:
            return BitLockerDecryptingReader(reader, vols)
    return reader


def _open_raw(path: str):
    """Detect the image format and return an appropriate (still-encrypted) reader."""
    if path == "-" or path == "/dev/stdin":
        return StdinReader()
    # Split raw by name pattern (.001 etc.) only when a sibling .002 exists, so
    # a lone foo.001 still parses but we don't misfire on unrelated names.
    m = _SPLIT_RE.match(path)
    if m:
        stem, digits = m.group(1), m.group(2)
        nxt = f"{stem}.{int(digits) + 1:0{len(digits)}d}"
        if os.path.exists(nxt) or int(digits) <= 1:
            try:
                return SplitRawReader(path)
            except ValueError:
                pass

    try:
        with open(path, "rb") as fh:
            magic = fh.read(16)
    except OSError:
        return Reader(path)                      # let Reader raise/ handle devices

    if magic[:4] == b"QFI\xfb":
        return Qcow2Reader(path)
    if magic[:4] == b"KDMV":
        return VmdkReader(path)
    if magic[:8] == b"EVF\x09\x0d\x0a\xff\x00" or magic[:8] == b"EVF2\x0d\x0a\x81\x00":
        try:
            return EwfPyReader(path)             # prefer libewf if available
        except Exception:
            return EwfReader(path)
    if path.lower().endswith((".e01", ".ex01", ".s01", ".l01")):
        try:
            return EwfPyReader(path)
        except Exception:
            return EwfReader(path)
    return Reader(path)
