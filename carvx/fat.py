"""FAT12/16/32 and exFAT undelete.

FAT: deleted directory entries keep their full metadata; only the first name
byte is overwritten with 0xE5 and the FAT chain is freed. We recover the name
(VFAT long-name entries that precede the short entry usually survive), the
start cluster, and the size, then read clusters contiguously from the start
(the freed chain can't be followed, so fragmented files recover only their
first run - flagged best-effort).

exFAT: deleted file/stream entries clear the in-use bit (0x85 -> 0x05); the
stream extension entry still holds first-cluster + data length, and the
"no FAT chain" flag lets us read contiguous runs directly.
"""

import hashlib
import os
import sys
from dataclasses import dataclass, field

from .reader import Reader
from .images import open_source


def _u16(b, o=0): return int.from_bytes(b[o:o + 2], "little")
def _u32(b, o=0): return int.from_bytes(b[o:o + 4], "little")


@dataclass
class FatRecord:
    type: str = "fat"
    ext: str = "bin"
    offset: int = 0             # byte offset of the directory entry
    size: int = 0
    sha256: str = ""
    validated: bool = False
    path: str = ""
    name: str = ""
    deleted: bool = True
    timestamps: dict = field(default_factory=dict)
    duplicate_of: int | None = None

    @property
    def confidence(self) -> str:
        return "high" if self.validated else "low"


def _dos_time(date: int, time: int) -> int:
    """FAT date+time -> unix seconds (local, treated as UTC)."""
    if date == 0:
        return 0
    import calendar
    y = ((date >> 9) & 0x7F) + 1980
    mo = (date >> 5) & 0x0F
    d = date & 0x1F
    h = (time >> 11) & 0x1F
    mi = (time >> 5) & 0x3F
    s = (time & 0x1F) * 2
    try:
        return calendar.timegm((y, max(mo, 1), max(d, 1), h, mi, s, 0, 0, 0))
    except Exception:
        return 0


class FatVolume:
    def __init__(self, reader: Reader, base: int):
        self.reader = reader
        self.base = base
        bs = reader.pread(base, 512)
        if len(bs) < 512 or bs[510:512] != b"\x55\xaa":
            raise ValueError("no FAT/exFAT boot sector (bad 0x55AA signature)")
        if bs[3:11] == b"EXFAT   ":
            self.kind = "exfat"
            self._init_exfat(bs)
        else:
            self.kind = "fat"
            self._init_fat(bs)

    # -------------------------------------------------------------- FAT12/16/32

    def _init_fat(self, bs):
        self.bytes_per_sector = _u16(bs, 11)
        self.sectors_per_cluster = bs[13]
        if self.bytes_per_sector not in (512, 1024, 2048, 4096) or \
                self.sectors_per_cluster == 0:
            raise ValueError("implausible FAT geometry")
        self.reserved = _u16(bs, 14)
        self.num_fats = bs[16]
        self.root_entries = _u16(bs, 17)
        total16 = _u16(bs, 19)
        self.fat_size16 = _u16(bs, 22)
        total32 = _u32(bs, 32)
        self.fat_size32 = _u32(bs, 36)
        self.total_sectors = total16 or total32
        self.cluster_size = self.bytes_per_sector * self.sectors_per_cluster
        fat_size = self.fat_size16 or self.fat_size32
        self.root_dir_sectors = ((self.root_entries * 32) +
                                 (self.bytes_per_sector - 1)) // self.bytes_per_sector
        self.first_data_sector = (self.reserved + self.num_fats * fat_size +
                                  self.root_dir_sectors)
        data_sectors = self.total_sectors - self.first_data_sector
        if self.sectors_per_cluster == 0 or data_sectors <= 0:
            raise ValueError("implausible FAT data region")
        self.cluster_count = data_sectors // self.sectors_per_cluster
        if self.cluster_count < 4085:
            self.fat_type = 12
        elif self.cluster_count < 65525:
            self.fat_type = 16
        else:
            self.fat_type = 32
        self.root_cluster = _u32(bs, 44) if self.fat_type == 32 else 0
        self.volume_size = self.total_sectors * self.bytes_per_sector

    def _cluster_offset(self, cluster: int) -> int:
        sector = self.first_data_sector + (cluster - 2) * self.sectors_per_cluster
        return self.base + sector * self.bytes_per_sector

    def _root_dir_offset(self) -> int:
        sector = self.reserved + self.num_fats * (self.fat_size16 or self.fat_size32)
        return self.base + sector * self.bytes_per_sector

    # -------------------------------------------------------------- exFAT

    def _init_exfat(self, bs):
        self.partition_offset = _u32(bs, 64)
        self.fat_offset = _u32(bs, 80)           # in sectors
        self.fat_length = _u32(bs, 84)
        self.cluster_heap_offset = _u32(bs, 88)
        self.cluster_count = _u32(bs, 92)
        self.root_cluster = _u32(bs, 96)
        self.bytes_per_sector = 1 << bs[108]
        self.sectors_per_cluster = 1 << bs[109]
        self.num_fats = bs[110]
        self.cluster_size = self.bytes_per_sector * self.sectors_per_cluster
        if self.bytes_per_sector < 512 or self.cluster_size > (1 << 25):
            raise ValueError("implausible exFAT geometry")
        self.volume_size = _u32(bs, 72) * self.bytes_per_sector or \
            (self.cluster_heap_offset + self.cluster_count *
             self.sectors_per_cluster) * self.bytes_per_sector

    def _exfat_cluster_offset(self, cluster: int) -> int:
        sector = self.cluster_heap_offset + (cluster - 2) * self.sectors_per_cluster
        return self.base + sector * self.bytes_per_sector

    # -------------------------------------------------------------- recovery

    def recover(self, out_dir, dry_run=False, include_live=False, min_size=0,
                on_file=None):
        if self.kind == "exfat":
            entries = self._walk_exfat()
        else:
            entries = self._walk_fat()
        records = []
        for ent in entries:
            if not ent["deleted"] and not include_live:
                continue
            if ent["size"] < max(min_size, 1):
                continue
            rec = self._emit(ent, out_dir, dry_run)
            if rec is not None:
                records.append(rec)
                if on_file:
                    on_file(rec)
        return records

    def _read_contig(self, first_cluster, size, exfat=False):
        """Read `size` bytes starting at first_cluster, assuming contiguous
        allocation (freed FAT chains can't be followed)."""
        if first_cluster < 2:
            return b"", False
        off = (self._exfat_cluster_offset(first_cluster) if exfat
               else self._cluster_offset(first_cluster))
        if off + size > self.base + self.volume_size:
            return b"", False
        data = self.reader.pread(off, size)
        return data, len(data) == size

    # ---- FAT directory walk

    def _walk_fat(self):
        entries = []
        seen_dirs = set()

        def walk_dir(offset, n_entries, cluster_walk=None, depth=0):
            if depth > 32:
                return
            lfn = []
            if cluster_walk is not None:
                data = self._read_cluster_chain_raw(cluster_walk)
            else:
                data = self.reader.pread(offset, n_entries * 32)
            for i in range(0, len(data) - 31, 32):
                e = data[i:i + 32]
                first = e[0]
                if first == 0x00:
                    lfn = []
                    continue
                attr = e[11]
                if attr == 0x0F:                 # long-name component
                    lfn.append(e)
                    continue
                deleted = first == 0xE5
                if attr & 0x08:                  # volume label
                    lfn = []
                    continue
                name = self._lfn_or_short(lfn, e, deleted)
                lfn = []
                start = (_u16(e, 26) | (_u16(e, 20) << 16))
                size = _u32(e, 28)
                is_dir = bool(attr & 0x10)
                ent_off = (offset + i) if cluster_walk is None else None
                if is_dir:
                    if not deleted and start >= 2 and start not in seen_dirs:
                        seen_dirs.add(start)
                        walk_dir(0, 0, cluster_walk=start, depth=depth + 1)
                    continue
                entries.append({
                    "name": name, "deleted": deleted, "start": start,
                    "size": size, "offset": ent_off or (offset + i),
                    "exfat": False,
                    "timestamps": {
                        "mtime": _dos_time(_u16(e, 24), _u16(e, 22)),
                        "atime": _dos_time(_u16(e, 18), 0),
                        "crtime": _dos_time(_u16(e, 16), _u16(e, 14)),
                        "ctime": 0, "dtime": 0},
                })

        if self.fat_type == 32:
            walk_dir(0, 0, cluster_walk=self.root_cluster)
        else:
            walk_dir(self._root_dir_offset(), self.root_entries)
        return entries

    def _read_cluster_chain_raw(self, start, max_clusters=4096):
        """Follow a LIVE FAT chain to read a directory (used for live dirs so
        we can reach deleted entries inside them)."""
        out = bytearray()
        cluster = start
        for _ in range(max_clusters):
            if cluster < 2 or cluster >= self.cluster_count + 2:
                break
            out += self.reader.pread(self._cluster_offset(cluster),
                                     self.cluster_size)
            cluster = self._fat_next(cluster)
            if cluster is None or cluster >= 0x0FFFFFF8:
                break
        return bytes(out)

    def _fat_next(self, cluster):
        base = self.base + self.reserved * self.bytes_per_sector
        if self.fat_type == 16:
            v = _u16(self.reader.pread(base + cluster * 2, 2))
            return v if v < 0xFFF8 else None
        if self.fat_type == 32:
            v = _u32(self.reader.pread(base + cluster * 4, 4)) & 0x0FFFFFFF
            return v if v < 0x0FFFFFF8 else None
        # FAT12
        idx = cluster + (cluster >> 1)
        raw = _u16(self.reader.pread(base + idx, 2))
        v = (raw >> 4) if (cluster & 1) else (raw & 0x0FFF)
        return v if v < 0xFF8 else None

    @staticmethod
    def _short_name(e, deleted):
        raw = bytearray(e[:11])
        if deleted:
            raw[0] = ord("_")                    # 0xE5 replaced first char
        base = raw[:8].decode("ascii", "replace").rstrip()
        ext = raw[8:11].decode("ascii", "replace").rstrip()
        name = base + ("." + ext if ext else "")
        return name.strip()

    def _lfn_or_short(self, lfn_entries, short, deleted):
        # LFN entries are stored physically in reverse (highest sequence first).
        # On deletion the sequence byte (entry[0]) is overwritten with 0xE5, so
        # we cannot trust it - reconstruct from physical order instead.
        if lfn_entries:
            pieces = []
            for le in lfn_entries:               # physical order: seq n .. seq 1
                chars = le[1:11] + le[14:26] + le[28:32]
                s = chars.decode("utf-16-le", "replace")
                s = s.split("\x00", 1)[0].replace("￿", "")
                pieces.append(s)
            name = "".join(reversed(pieces))      # reverse -> seq 1 .. seq n
            if name:
                return name
        return self._short_name(short, deleted)

    # ---- exFAT directory walk

    def _walk_exfat(self):
        entries = []
        seen = set()

        def walk(cluster, depth=0):
            if depth > 32 or cluster in seen or cluster < 2:
                return
            seen.add(cluster)
            data = self._read_exfat_chain(cluster)
            i = 0
            while i + 32 <= len(data):
                etype = data[i]
                in_use = bool(etype & 0x80)
                base = etype & 0x7F
                if etype == 0x00:
                    break
                if base == 0x05:                 # File directory entry (0x85/0x05)
                    secondary = data[i + 1]
                    name = ""
                    attr = _u16(data, i + 4)
                    crtime = _u32(data, i + 8)
                    mtime = _u32(data, i + 12)
                    stream = data[i + 32:i + 64]
                    if len(stream) < 32 or (stream[0] & 0x7F) != 0x40:
                        i += 32
                        continue
                    name_len = stream[3]
                    no_fat = bool(stream[1] & 0x02)
                    first_cluster = _u32(stream, 20)
                    data_len = _u32(stream, 24) | (_u32(stream, 28) << 32)
                    # name entries (0xC1) follow
                    chars = []
                    j = i + 64
                    for _ in range(max(secondary - 1, 0)):
                        if j + 32 > len(data) or (data[j] & 0x7F) != 0x41:
                            break
                        chars.append(data[j + 2:j + 32])
                        j += 32
                    name = b"".join(chars).decode("utf-16-le", "replace")[:name_len]
                    is_dir = bool(attr & 0x10)
                    if is_dir and in_use and first_cluster >= 2:
                        walk(first_cluster, depth + 1)
                    elif not is_dir:
                        entries.append({
                            "name": name or f"exfat_{first_cluster}",
                            "deleted": not in_use, "start": first_cluster,
                            "size": data_len, "offset": first_cluster,
                            "exfat": True, "no_fat": no_fat,
                            "timestamps": {"mtime": _exfat_time(mtime),
                                           "crtime": _exfat_time(crtime),
                                           "atime": 0, "ctime": 0, "dtime": 0}})
                    i = j
                    continue
                i += 32

        walk(self.root_cluster)
        return entries

    def _read_exfat_chain(self, start, max_clusters=4096):
        out = bytearray()
        cluster = start
        fat_base = self.base + self.fat_offset * self.bytes_per_sector
        for _ in range(max_clusters):
            if cluster < 2 or cluster >= self.cluster_count + 2:
                break
            out += self.reader.pread(self._exfat_cluster_offset(cluster),
                                     self.cluster_size)
            nxt = _u32(self.reader.pread(fat_base + cluster * 4, 4))
            if nxt >= 0xFFFFFFF7 or nxt < 2:
                break
            cluster = nxt
        return bytes(out)

    # ---- emit

    def _emit(self, ent, out_dir, dry_run):
        data, ok = self._read_contig(ent["start"], ent["size"], ent["exfat"])
        if not data:
            return None
        digest = hashlib.sha256(data).hexdigest()
        name = ent["name"] or f"file_{ent['start']}"
        ext = os.path.splitext(name)[1].lstrip(".").lower() or "bin"
        out_path = ""
        if not dry_run:
            safe = "".join("_" if c in '\\/:*?"<>|' else c for c in name)
            out_path = os.path.join(out_dir, self.kind, safe)
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            if os.path.exists(out_path):
                stem, e = os.path.splitext(out_path)
                out_path = f"{stem}_{ent['offset']:x}{e}"
            with open(out_path, "wb") as fh:
                fh.write(data)
        return FatRecord(
            type=self.kind, ext=ext, offset=ent["offset"], size=ent["size"],
            sha256=digest, validated=ok, path=out_path, name=name,
            deleted=ent["deleted"], timestamps=ent["timestamps"])


def _exfat_time(v: int) -> int:
    if v == 0:
        return 0
    import calendar
    s = (v & 0x1F) * 2
    mi = (v >> 5) & 0x3F
    h = (v >> 11) & 0x1F
    d = (v >> 16) & 0x1F
    mo = (v >> 21) & 0x0F
    y = ((v >> 25) & 0x7F) + 1980
    try:
        return calendar.timegm((y, max(mo, 1), max(d, 1), h, mi, s, 0, 0, 0))
    except Exception:
        return 0


def recover_fat(source, offset, out_dir, dry_run=False, include_live=False,
                min_size=0, on_file=None):
    reader = open_source(source)
    base, vol = _locate_volume(reader, offset)
    records = vol.recover(out_dir, dry_run, include_live, min_size, on_file)
    return records, vol


def _locate_volume(reader, offset):
    try:
        return offset, FatVolume(reader, offset)
    except ValueError:
        if offset:
            raise
    sector0 = reader.pread(0, 512)
    if sector0[510:512] == b"\x55\xaa":
        for i in range(4):
            e = sector0[446 + i * 16:446 + (i + 1) * 16]
            ptype, lba = e[4], _u32(e, 8)
            if ptype in (0x01, 0x04, 0x06, 0x0B, 0x0C, 0x0E, 0x07) and lba:
                try:
                    return lba * 512, FatVolume(reader, lba * 512)
                except ValueError:
                    continue
    raise ValueError("no FAT/exFAT volume found (give the partition offset via --offset)")


def run_fat(args) -> int:
    from .carver import emit
    from .cli import parse_size, write_outputs
    import datetime

    quiet = args.quiet or args.machine
    t0 = datetime.datetime.now(datetime.timezone.utc)

    def on_file(rec):
        if args.machine:
            emit("file", name=rec.name, offset=rec.offset, size=rec.size,
                 sha256=rec.sha256, deleted=rec.deleted, validated=rec.validated,
                 path=rec.path)
        elif not quiet:
            flag = "" if rec.validated else "  (low confidence: maybe fragmented)"
            sys.stderr.write(f"[+] {rec.name}  {rec.size:,} B{flag}\n")

    try:
        records, vol = recover_fat(
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
    scan_meta = {"mode": vol.kind, "started": t0.isoformat(),
                 "finished": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                 "cluster_size": vol.cluster_size}
    report_path = write_outputs(args, _O, records, vol.volume_size, scan_meta)
    if args.machine:
        emit("summary", recovered=len(records),
             bytes=sum(r.size for r in records), manifest=report_path)
    elif not args.quiet:
        print(f"\nrecovered {len(records)} deleted files "
              f"({vol.kind.upper()})", file=sys.stderr)
        if records:
            print(f"manifest: {report_path}", file=sys.stderr)
    return 0
