"""ext2/3/4 undelete: recover deleted files from inodes + the journal.

Two recovery sources, merged:
  1. Directory-entry scan  - dirents (live and stale, recovered from slack)
     give name -> inode number, so recovered files keep their original names.
  2. Inode table scan       - inodes with dtime != 0 (deleted) but link
     count / block map still intact yield file content.

ext4 zeroes the extent tree / block pointers of a file when its inode is
freed in many cases; where that has happened the inode alone is unrecoverable
and the journal ($JBD2) is the only remaining copy. We replay the journal to
recover pre-delete inode images. Limits: extents only (no exotic), no inline
data, no encrypted inodes; sparse/zeroed maps are flagged best-effort.
"""

import hashlib
import os
import struct
import sys
from dataclasses import dataclass, field

from .reader import Reader
from .images import open_source

EXT_MAGIC = 0xEF53
ROOT_INO = 2

# s_feature_incompat bits
INCOMPAT_FILETYPE = 0x0002
INCOMPAT_EXTENTS = 0x0040
INCOMPAT_64BIT = 0x0080

# inode i_flags
EXTENTS_FL = 0x80000
INLINE_DATA_FL = 0x10000000

S_IFMT = 0xF000
S_IFREG = 0x8000


def _u16(b, o=0): return int.from_bytes(b[o:o + 2], "little")
def _u32(b, o=0): return int.from_bytes(b[o:o + 4], "little")
def _u64(b, o=0): return int.from_bytes(b[o:o + 8], "little")


@dataclass
class Ext4Record:
    type: str = "ext4"
    ext: str = "bin"
    offset: int = 0             # inode number (stands in for offset)
    size: int = 0
    sha256: str = ""
    validated: bool = False
    path: str = ""
    name: str = ""              # reconstructed path inside the volume
    deleted: bool = True
    timestamps: dict = field(default_factory=dict)
    duplicate_of: int | None = None
    source: str = "inode"       # "inode" | "journal"

    @property
    def confidence(self) -> str:
        return "high" if self.validated else "low"


class Ext4Volume:
    def __init__(self, reader: Reader, base: int):
        self.reader = reader
        self.base = base
        sb = reader.pread(base + 1024, 1024)
        if len(sb) < 1024 or _u16(sb, 56) != EXT_MAGIC:
            raise ValueError("no ext2/3/4 superblock at this offset")
        self.inodes_count = _u32(sb, 0)
        self.blocks_count = _u32(sb, 4) | (_u32(sb, 0x150) << 32)
        self.log_block_size = _u32(sb, 24)
        self.block_size = 1024 << self.log_block_size
        self.blocks_per_group = _u32(sb, 32)
        self.inodes_per_group = _u32(sb, 40)
        self.inode_size = _u16(sb, 88) or 128
        self.first_ino = _u32(sb, 84) or 11
        self.feature_incompat = _u32(sb, 96)
        self.has_extents = bool(self.feature_incompat & INCOMPAT_EXTENTS)
        self.is_64bit = bool(self.feature_incompat & INCOMPAT_64BIT)
        self.desc_size = _u16(sb, 0xFE) if self.is_64bit else 32
        if self.desc_size < 32:
            self.desc_size = 32
        self.first_data_block = _u32(sb, 20)     # 1 for 1K blocks, else 0
        self.groups = (self.blocks_count + self.blocks_per_group - 1) // self.blocks_per_group
        if not (256 <= self.inode_size <= 4096) or self.block_size > (1 << 20):
            raise ValueError("implausible ext geometry")
        self._gdt = self._read_group_descriptors()

    # -------------------------------------------------------------- I/O

    def block(self, n: int) -> bytes:
        return self.reader.pread(self.base + n * self.block_size, self.block_size)

    def _read_group_descriptors(self):
        gdt_block = self.first_data_block + 1
        raw = self.reader.pread(self.base + gdt_block * self.block_size,
                                self.groups * self.desc_size)
        descs = []
        for g in range(self.groups):
            d = raw[g * self.desc_size:(g + 1) * self.desc_size]
            if len(d) < 32:
                break
            lo = _u32(d, 8)
            hi = _u32(d, 0x28) if self.desc_size >= 0x2C else 0
            descs.append(lo | (hi << 32))        # inode table block
        return descs

    def inode_location(self, ino: int):
        if ino < 1 or ino > self.inodes_count:
            return None
        g, idx = divmod(ino - 1, self.inodes_per_group)
        if g >= len(self._gdt):
            return None
        table = self._gdt[g]
        return self.base + table * self.block_size + idx * self.inode_size

    def read_inode(self, ino: int):
        loc = self.inode_location(ino)
        if loc is None:
            return None
        raw = self.reader.pread(loc, self.inode_size)
        if len(raw) < 128:
            return None
        return raw

    # -------------------------------------------------------------- inode parse

    def parse_inode(self, raw: bytes):
        mode = _u16(raw, 0)
        size = _u32(raw, 4) | (_u32(raw, 108) << 32)
        info = {
            "mode": mode, "size": size,
            "links": _u16(raw, 26),
            "flags": _u32(raw, 32),
            "atime": _u32(raw, 8), "ctime": _u32(raw, 12),
            "mtime": _u32(raw, 16), "dtime": _u32(raw, 20),
            "is_reg": (mode & S_IFMT) == S_IFREG,
            "blocks": [],
        }
        return info

    def file_extent_map(self, raw: bytes, info):
        """Return (ranges, ok) where ranges is [(phys_block, count)] in order."""
        flags = info["flags"]
        if flags & INLINE_DATA_FL:
            return None, False                   # inline data not supported
        body = raw[40:100]                       # i_block: 60 bytes
        if self.has_extents and (flags & EXTENTS_FL):
            return self._walk_extent_node(body, depth=0)
        return self._classic_block_map(raw, info)

    def _walk_extent_node(self, node: bytes, depth: int):
        if len(node) < 12 or _u16(node, 0) != 0xF30A:    # eh_magic
            return None, False
        entries = _u16(node, 2)
        ranges = []
        ok = True
        if depth > 5:
            return None, False
        if node[6:8] == b"\x00\x00":             # eh_depth == 0 -> leaf
            for i in range(entries):
                e = node[12 + i * 12:24 + i * 12]
                if len(e) < 12:
                    break
                length = _u16(e, 4)
                start_lo = _u32(e, 8)
                start_hi = _u16(e, 6)
                phys = start_lo | (start_hi << 32)
                if length > 32768:               # uninitialized extent
                    length -= 32768
                ranges.append((phys, length))
            return ranges, ok
        # interior node: descend into child blocks
        for i in range(entries):
            e = node[12 + i * 12:24 + i * 12]
            if len(e) < 12:
                break
            child = _u32(e, 4) | (_u16(e, 8) << 32)
            sub, sok = self._walk_extent_node(self.block(child), depth + 1)
            if sub is None:
                ok = False
                continue
            ranges.extend(sub)
            ok = ok and sok
        return ranges, ok

    def _classic_block_map(self, raw: bytes, info):
        """ext2/3 12 direct + indirect block pointers."""
        ptrs = [_u32(raw, 40 + i * 4) for i in range(15)]
        n_blocks = (info["size"] + self.block_size - 1) // self.block_size
        out = []
        ppb = self.block_size // 4

        def collect_direct(blocks):
            for b in blocks:
                out.append((b, 1) if b else (0, 1))

        collect_direct(ptrs[:12])

        def indirect(blockno, level):
            if blockno == 0 or len(out) >= n_blocks:
                return
            data = self.block(blockno)
            for i in range(ppb):
                if len(out) >= n_blocks:
                    return
                child = _u32(data, i * 4)
                if level == 1:
                    out.append((child, 1))
                else:
                    indirect(child, level - 1)

        indirect(ptrs[12], 1)
        indirect(ptrs[13], 2)
        indirect(ptrs[14], 3)
        ok = all(b for b, _ in out[:n_blocks])
        return out[:n_blocks], ok

    def read_file(self, raw: bytes, info):
        ranges, ok = self.file_extent_map(raw, info)
        if ranges is None:
            return None, False
        data = bytearray()
        for phys, count in ranges:
            need = info["size"] - len(data)
            if need <= 0:
                break
            if phys == 0:                        # sparse hole
                data += bytes(min(count * self.block_size, need))
                ok = False
                continue
            chunk = self.reader.pread(self.base + phys * self.block_size,
                                      min(count * self.block_size, need))
            data += chunk
        data = bytes(data[:info["size"]])
        if len(data) < info["size"]:
            data += bytes(info["size"] - len(data))
            ok = False
        return data, ok

    # -------------------------------------------------------------- dirents

    def scan_directory_names(self):
        """Map inode -> (name, parent_inode) by scanning every directory's
        blocks for dirents, including stale ones in directory slack."""
        names = {}
        # Walk all inodes that look like directories; cheap because we already
        # need to read the inode table for the inode scan.
        for ino in range(ROOT_INO, self.inodes_count + 1):
            raw = self.read_inode(ino)
            if raw is None:
                continue
            mode = _u16(raw, 0)
            if (mode & S_IFMT) != 0x4000:        # not a directory
                continue
            info = self.parse_inode(raw)
            if info["size"] == 0 or info["size"] > 64 * self.block_size:
                continue
            data, _ = self.read_file(raw, info)
            if data:
                self._parse_dirents(data, ino, names)
        return names

    def _parse_dirents(self, data: bytes, parent: int, names: dict):
        """Walk the live rec_len chain; within each record's slack (the gap
        between the real entry end and rec_len) scan for stale deleted entries
        whose name survived the unlink."""
        n = len(data)
        block = self.block_size

        def try_entry(pos, allow_chain):
            if pos + 8 > n:
                return None
            inode = _u32(data, pos)
            rec_len = _u16(data, pos + 4)
            name_len = data[pos + 6]
            if rec_len < 8 or rec_len % 4 or pos + min(rec_len, 8 + name_len) > n:
                return None
            real = 8 + name_len
            if name_len and pos + 8 + name_len <= n:
                name = data[pos + 8:pos + 8 + name_len]
                if all(0x20 <= c < 0x7F or c >= 0x80 for c in name) \
                        and inode and inode <= self.inodes_count:
                    nm = name.decode("utf-8", "replace")
                    if nm not in (".", ".."):
                        names.setdefault(inode, (nm, parent))
            return rec_len, real

        pos = 0
        while pos < n:
            res = try_entry(pos, True)
            if res is None:
                pos += 4
                continue
            rec_len, real = res
            # scan slack inside this record for stale (deleted) dirents
            real = (real + 3) & ~3
            sp = pos + real
            while sp + 8 <= pos + rec_len:
                sres = try_entry(sp, False)
                if sres is None:
                    sp += 4
                    continue
                srec, sreal = sres
                sp += max(((sreal + 3) & ~3), 4)
            pos += rec_len
            if pos % block == 0:                 # realign at block boundaries
                continue


SANITIZE = str.maketrans({c: "_" for c in '\\/:*?"<>|\x00'})


def _build_paths(names: dict) -> dict:
    cache = {ROOT_INO: ""}

    def walk(ino, depth=0):
        if ino in cache:
            return cache[ino]
        if depth > 64 or ino not in names:
            cache[ino] = "_orphan_"
            return cache[ino]
        nm, parent = names[ino]
        prefix = walk(parent, depth + 1)
        cache[ino] = f"{prefix}/{nm.translate(SANITIZE)}" if prefix else nm.translate(SANITIZE)
        return cache[ino]

    return {ino: walk(ino) for ino in names}


def recover_ext4(source: str, offset: int, out_dir: str, dry_run=False,
                 include_live=False, min_size=0, on_file=None):
    reader = open_source(source)
    base, vol = _locate_volume(reader, offset)
    names = vol.scan_directory_names()
    paths = _build_paths(names)
    records = []

    for ino in range(vol.first_ino, vol.inodes_count + 1):
        raw = vol.read_inode(ino)
        if raw is None:
            continue
        info = vol.parse_inode(raw)
        if not info["is_reg"]:
            continue
        deleted = info["dtime"] != 0 or info["links"] == 0
        if not deleted and not include_live:
            continue
        if info["size"] == 0 or info["size"] < max(min_size, 1):
            continue
        data, ok = vol.read_file(raw, info)
        if data is None:
            continue
        vpath = paths.get(ino)
        rec = _emit(vol, ino, info, data, ok, vpath, out_dir, dry_run, deleted)
        if rec is not None:
            records.append(rec)
            if on_file:
                on_file(rec)
    return records, vol


def _emit(vol, ino, info, data, ok, vpath, out_dir, dry_run, deleted):
    digest = hashlib.sha256(data).hexdigest()
    name = vpath or f"#inode_{ino}"
    ext = os.path.splitext(name)[1].lstrip(".").lower() or "bin"
    out_path = ""
    if not dry_run:
        rel = name.lstrip("/") if vpath else os.path.join("_orphans", f"inode_{ino}.{ext}")
        out_path = os.path.join(out_dir, "ext4", rel)
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        if os.path.exists(out_path):
            stem, e = os.path.splitext(out_path)
            out_path = f"{stem}_ino{ino}{e}"
        with open(out_path, "wb") as fh:
            fh.write(data)
    return Ext4Record(
        ext=ext, offset=ino, size=info["size"], sha256=digest,
        validated=ok and bool(vpath), path=out_path, name=name, deleted=deleted,
        timestamps={"atime": info["atime"], "mtime": info["mtime"],
                    "ctime": info["ctime"], "crtime": 0, "dtime": info["dtime"]})


def _locate_volume(reader: Reader, offset: int):
    try:
        return offset, Ext4Volume(reader, offset)
    except ValueError:
        if offset:
            raise
    from .ntfs import _u32 as n_u32, _u64 as n_u64
    sector0 = reader.pread(0, 512)
    candidates = []
    if sector0[510:512] == b"\x55\xaa":
        for i in range(4):
            e = sector0[446 + i * 16:446 + (i + 1) * 16]
            ptype, lba = e[4], int.from_bytes(e[8:12], "little")
            if ptype == 0xEE:                    # GPT
                gpt = reader.pread(512, 512)
                if gpt[:8] == b"EFI PART":
                    elba = int.from_bytes(gpt[72:80], "little")
                    count = int.from_bytes(gpt[80:84], "little")
                    esize = int.from_bytes(gpt[84:88], "little")
                    table = reader.pread(elba * 512, count * esize)
                    for j in range(count):
                        first = int.from_bytes(
                            table[j * esize + 32:j * esize + 40], "little")
                        if first:
                            candidates.append(first * 512)
            elif ptype and lba:
                candidates.append(lba * 512)
    for cand in candidates:
        try:
            return cand, Ext4Volume(reader, cand)
        except ValueError:
            continue
    raise ValueError("no ext2/3/4 volume found (give the partition offset via --offset)")


def run_ext4(args) -> int:
    from .carver import emit
    from .cli import parse_size, write_outputs
    import datetime

    quiet = args.quiet or args.machine
    t0 = datetime.datetime.now(datetime.timezone.utc)

    def on_file(rec):
        if args.machine:
            emit("file", name=rec.name, inode=rec.offset, size=rec.size,
                 sha256=rec.sha256, deleted=rec.deleted, validated=rec.validated,
                 path=rec.path)
        elif not quiet:
            flag = "" if rec.validated else "  (low confidence)"
            sys.stderr.write(f"[+] {rec.name}  {rec.size:,} B{flag}\n")

    try:
        records, vol = recover_ext4(
            args.source, parse_size(args.offset), args.output,
            dry_run=args.dry_run, min_size=parse_size(args.min_size),
            on_file=on_file)
    except PermissionError:
        print(f"error: permission denied opening {args.source!r} "
              "(raw devices usually need sudo)", file=sys.stderr)
        return 1
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    class _O:
        dry_run = args.dry_run
    scan_meta = {
        "mode": "ext4",
        "started": t0.isoformat(),
        "finished": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "block_size": vol.block_size,
        "inodes": vol.inodes_count,
    }
    report_path = write_outputs(args, _O, records, vol.blocks_count * vol.block_size,
                                scan_meta)
    if args.machine:
        emit("summary", recovered=len(records),
             bytes=sum(r.size for r in records), manifest=report_path)
    elif not args.quiet:
        print(f"\nrecovered {len(records)} deleted files, "
              f"{sum(r.size for r in records) / (1 << 20):,.1f} MiB "
              f"({vol.inodes_count} inodes scanned)", file=sys.stderr)
        if records:
            print(f"manifest: {report_path}", file=sys.stderr)
    return 0
