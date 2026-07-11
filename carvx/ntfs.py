"""NTFS undelete: parse the MFT for deleted file records.

Unlike carving, this recovers filenames, timestamps, directory paths, and
fragmented files (via data runlists). Limits: clusters of a deleted file may
have been reused (recovered content is then wrong  -  flagged best-effort),
attribute lists (very large/heavily fragmented files) are not followed, and
NTFS-compressed/encrypted streams are skipped.
"""

import hashlib
import os
import re
import sys
from dataclasses import dataclass, field

from .reader import Reader
from .images import open_source

FILETIME_EPOCH = 116444736000000000     # 1601-01-01 -> 1970-01-01, in 100ns


def _u16(b, o=0): return int.from_bytes(b[o:o + 2], "little")
def _u32(b, o=0): return int.from_bytes(b[o:o + 4], "little")
def _u64(b, o=0): return int.from_bytes(b[o:o + 8], "little")


def _ft2unix(ft: int) -> int:
    if ft == 0:
        return 0
    return max(0, (ft - FILETIME_EPOCH) // 10_000_000)


@dataclass
class NtfsRecord:
    type: str               # "ntfs"
    ext: str
    offset: int             # MFT record number (stands in for offset/inode)
    size: int
    sha256: str
    validated: bool         # all runs read within volume, not compressed
    path: str               # recovered output path on disk
    name: str = ""          # reconstructed original path inside the volume
    deleted: bool = True
    timestamps: dict = field(default_factory=dict)
    duplicate_of: int | None = None

    @property
    def confidence(self) -> str:
        return "high" if self.validated else "low"


class Volume:
    """Minimal NTFS reader: boot sector, MFT map, record parsing."""

    def __init__(self, reader: Reader, base: int):
        self.reader = reader
        self.base = base
        boot = reader.pread(base, 512)
        if len(boot) < 512 or boot[3:11] != b"NTFS    ":
            raise ValueError("no NTFS boot sector at this offset")
        self.bps = _u16(boot, 11)
        self.spc = boot[13]
        if self.bps not in (512, 1024, 2048, 4096) or self.spc == 0:
            raise ValueError("implausible NTFS geometry")
        self.cluster = self.bps * self.spc
        self.total_sectors = _u64(boot, 40)
        self.volume_size = self.total_sectors * self.bps
        mft_lcn = _u64(boot, 48)
        cpr = boot[64]
        if cpr > 127:                            # signed: 2^|n| bytes
            self.rec_size = 1 << (256 - cpr)
        else:
            self.rec_size = cpr * self.cluster
        if not (256 <= self.rec_size <= 65536):
            raise ValueError("implausible MFT record size")
        # Map the MFT itself (it can be fragmented): parse record 0's $DATA.
        first = self._read_clusters([(mft_lcn, 1)], self.cluster)[:self.rec_size]
        rec0 = self._fixup(first)
        if rec0 is None:
            raise ValueError("cannot read $MFT record 0")
        runs = None
        for attr in self._attributes(rec0):
            if attr["type"] == 0x80 and not attr["name"]:
                runs = attr.get("runs")
                self.mft_size = attr.get("real", 0)
        if not runs:
            raise ValueError("cannot map $MFT data runs")
        self.mft_runs = runs
        self.record_count = self.mft_size // self.rec_size

    # -------------------------------------------------------------- I/O

    def _read_clusters(self, runs, length: int) -> bytes:
        """Concatenate data runs (lcn=None means sparse -> zeros)."""
        out = bytearray()
        for lcn, count in runs:
            n = min(count * self.cluster, length - len(out))
            if n <= 0:
                break
            if lcn is None:
                out += bytes(n)
            else:
                out += self.reader.pread(self.base + lcn * self.cluster, n)
        return bytes(out)

    def _fixup(self, rec: bytes):
        """Validate FILE signature and apply update sequence fixups."""
        if len(rec) < 48 or rec[:4] != b"FILE":
            return None
        usa_off, usa_count = _u16(rec, 4), _u16(rec, 6)
        if usa_count < 1 or usa_off + usa_count * 2 > len(rec):
            return None
        rec = bytearray(rec)
        usn = rec[usa_off:usa_off + 2]
        for i in range(1, usa_count):
            sec_end = i * self.bps - 2
            if sec_end + 2 > len(rec):
                break
            if rec[sec_end:sec_end + 2] != usn:
                return None                      # torn write
            rec[sec_end:sec_end + 2] = rec[usa_off + i * 2:usa_off + i * 2 + 2]
        return bytes(rec)

    def record(self, num: int):
        """Read MFT record num through the MFT runlist, fixups applied."""
        byte_off = num * self.rec_size
        remaining = byte_off
        for lcn, count in self.mft_runs:
            run_bytes = count * self.cluster
            if remaining < run_bytes:
                if lcn is None:
                    return None
                src = self.base + lcn * self.cluster + remaining
                return self._fixup(self.reader.pread(src, self.rec_size))
            remaining -= run_bytes
        return None

    # -------------------------------------------------------------- parsing

    @staticmethod
    def _decode_runs(data: bytes):
        """Runlist -> [(lcn|None, cluster_count)]; None = sparse."""
        runs = []
        pos = 0
        lcn = 0
        while pos < len(data):
            header = data[pos]
            pos += 1
            if header == 0:
                break
            len_sz, off_sz = header & 0x0F, header >> 4
            if len_sz == 0 or pos + len_sz + off_sz > len(data):
                return None
            count = int.from_bytes(data[pos:pos + len_sz], "little")
            pos += len_sz
            if off_sz == 0:
                runs.append((None, count))       # sparse
                continue
            delta = int.from_bytes(data[pos:pos + off_sz], "little", signed=True)
            pos += off_sz
            lcn += delta
            if lcn < 0 or count == 0:
                return None
            runs.append((lcn, count))
        return runs

    def _attributes(self, rec: bytes):
        """Yield parsed attribute dicts from a fixed-up record."""
        pos = _u16(rec, 20)
        used = min(_u32(rec, 24), len(rec))
        while pos + 8 <= used:
            atype = _u32(rec, pos)
            if atype == 0xFFFFFFFF:
                break
            alen = _u32(rec, pos + 4)
            if alen < 16 or pos + alen > used:
                break
            a = {"type": atype, "name": "", "resident": rec[pos + 8] == 0}
            namelen, nameoff = rec[pos + 9], _u16(rec, pos + 10)
            if namelen:
                raw = rec[pos + nameoff:pos + nameoff + namelen * 2]
                a["name"] = raw.decode("utf-16-le", "replace")
            a["flags"] = _u16(rec, pos + 12)
            if a["resident"]:
                csize, coff = _u32(rec, pos + 16), _u16(rec, pos + 20)
                a["content"] = rec[pos + coff:pos + coff + csize]
            else:
                runoff = _u16(rec, pos + 32)
                a["alloc"] = _u64(rec, pos + 40)
                a["real"] = _u64(rec, pos + 48)
                a["runs"] = self._decode_runs(rec[pos + runoff:pos + alen])
            yield a
            pos += alen

    def parse_record(self, num: int):
        """Extract name/parent/timestamps/data info from one MFT record."""
        rec = self.record(num)
        if rec is None:
            return None
        flags = _u16(rec, 22)
        info = {"num": num, "in_use": bool(flags & 1), "is_dir": bool(flags & 2),
                "base": _u64(rec, 32) & 0xFFFFFFFFFFFF,
                "name": "", "parent": None, "namespace": -1, "timestamps": {},
                "data": [],                      # (stream_name, attr dict)
                }
        for a in self._attributes(rec):
            if a["type"] == 0x10 and a["resident"] and len(a["content"]) >= 32:
                c = a["content"]
                info["timestamps"] = {
                    "crtime": _ft2unix(_u64(c, 0)), "mtime": _ft2unix(_u64(c, 8)),
                    "ctime": _ft2unix(_u64(c, 16)), "atime": _ft2unix(_u64(c, 24)),
                }
            elif a["type"] == 0x30 and a["resident"] and len(a["content"]) >= 66:
                c = a["content"]
                namelen, namespace = c[64], c[65]
                if len(c) < 66 + namelen * 2:
                    continue
                # Prefer a Win32/POSIX name (namespace 1/0/3) over DOS 8.3 (2);
                # take the first name seen otherwise.
                better = info["namespace"] < 0 or (info["namespace"] == 2 and namespace != 2)
                if better:
                    info["name"] = c[66:66 + namelen * 2].decode("utf-16-le", "replace")
                    info["parent"] = _u64(c, 0) & 0xFFFFFFFFFFFF
                    info["namespace"] = namespace
            elif a["type"] == 0x80:
                info["data"].append((a["name"], a))
        return info


SANITIZE = re.compile(r'[\\/:*?"<>|\x00-\x1f]')


def _build_paths(infos: dict) -> dict:
    """Record number -> reconstructed path string."""
    cache = {5: ""}                              # root

    def walk(num, depth=0):
        if num in cache:
            return cache[num]
        if depth > 64:
            return "_deep_"
        info = infos.get(num)
        if info is None or not info["name"] or info["parent"] is None:
            cache[num] = "_orphan_"
            return cache[num]
        parent = walk(info["parent"], depth + 1)
        name = SANITIZE.sub("_", info["name"])
        cache[num] = f"{parent}/{name}" if parent else name
        return cache[num]

    return {num: walk(num) for num in infos}


def recover_ntfs(source: str, offset: int, out_dir: str,
                 dry_run=False, include_live=False, min_size=0,
                 on_file=None):
    """Walk the MFT, recover deleted files. Returns (records, volume)."""
    reader = open_source(source)
    base, vol = _locate_volume(reader, offset)
    records = []
    infos = {}
    for num in range(vol.record_count):
        try:
            info = vol.parse_record(num)
        except Exception:
            info = None
        if info and info["base"] == 0:           # skip extension records
            infos[num] = info
    paths = _build_paths(infos)

    for num, info in infos.items():
        if info["is_dir"] or not info["data"]:
            continue
        if info["in_use"] and not include_live:
            continue
        if not info["name"]:
            continue
        for stream_name, attr in info["data"]:
            rec = _recover_stream(vol, info, paths[num], stream_name, attr,
                                  out_dir, dry_run, min_size)
            if rec is not None:
                records.append(rec)
                if on_file:
                    on_file(rec)
    return records, vol


def _recover_stream(vol, info, vpath, stream_name, attr, out_dir, dry_run, min_size):
    if attr["resident"]:
        data = attr["content"]
        size = len(data)
        ok = True
    else:
        if attr["runs"] is None:
            return None
        size = attr["real"]
        if attr["flags"] & 0x8001:               # compressed (0x0001) / encrypted (0x4000)
            return None                          # raw clusters would be garbage
        data = None
        ok = all(lcn is None or (lcn + cnt) * vol.cluster <= vol.volume_size
                 for lcn, cnt in attr["runs"])
        if not ok:
            return None
    if size < max(min_size, 1):
        return None

    label = vpath + (f"~{stream_name}" if stream_name else "")
    digest = hashlib.sha256()
    out_path = ""
    if data is None:
        data = vol._read_clusters(attr["runs"], size)
        if len(data) < size:
            data += bytes(size - len(data))      # volume edge: pad, mark low conf
            ok = False
    digest.update(data)
    if not dry_run:
        out_path = os.path.join(out_dir, "ntfs", label.lstrip("/"))
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        if os.path.exists(out_path):             # name collision across records
            stem, ext = os.path.splitext(out_path)
            out_path = f"{stem}_mft{info['num']}{ext}"
        with open(out_path, "wb") as fh:
            fh.write(data)

    ext = os.path.splitext(info["name"])[1].lstrip(".").lower() or "bin"
    return NtfsRecord("ntfs", ext, info["num"], size, digest.hexdigest(),
                      ok and not info["in_use"], out_path, name=label,
                      deleted=not info["in_use"], timestamps=info["timestamps"])


def _locate_volume(reader: Reader, offset: int):
    """NTFS at given offset, else search MBR/GPT partition tables."""
    try:
        return offset, Volume(reader, offset)
    except ValueError:
        if offset:
            raise
    sector0 = reader.pread(0, 512)
    candidates = []
    if sector0[510:512] == b"\x55\xaa":          # MBR (maybe protective)
        for i in range(4):
            e = sector0[446 + i * 16:446 + (i + 1) * 16]
            ptype, lba = e[4], _u32(e, 8)
            if ptype == 0xEE:                    # GPT
                gpt = reader.pread(512, 512)
                if gpt[:8] == b"EFI PART":
                    elba, count, esize = _u64(gpt, 72), _u32(gpt, 80), _u32(gpt, 84)
                    table = reader.pread(elba * 512, count * esize)
                    for j in range(count):
                        first = _u64(table, j * esize + 32)
                        if first:
                            candidates.append(first * 512)
            elif ptype and lba:
                candidates.append(lba * 512)
    for cand in candidates:
        try:
            return cand, Volume(reader, cand)
        except ValueError:
            continue
    raise ValueError("no NTFS volume found (give the partition offset via --offset)")


# ----------------------------------------------------------------------

def run_ntfs(args) -> int:
    """CLI entry for --ntfs mode (args from carvx.cli parser)."""
    from .carver import emit
    from .cli import parse_size, write_outputs
    import datetime

    quiet = args.quiet or args.machine
    t0 = datetime.datetime.now(datetime.timezone.utc)

    def on_file(rec):
        if args.machine:
            emit("file", name=rec.name, mft=rec.offset, size=rec.size,
                 sha256=rec.sha256, deleted=rec.deleted,
                 validated=rec.validated, path=rec.path)
        elif not quiet:
            flag = "" if rec.validated else "  (low confidence)"
            sys.stderr.write(f"[+] {rec.name}  {rec.size:,} B{flag}\n")

    try:
        records, vol = recover_ntfs(
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

    class _O:                                    # minimal opts shim for write_outputs
        dry_run = args.dry_run
    scan_meta = {
        "mode": "ntfs",
        "started": t0.isoformat(),
        "finished": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "cluster_size": vol.cluster,
        "mft_records": vol.record_count,
    }
    report_path = write_outputs(args, _O, records, vol.volume_size, scan_meta)

    if args.machine:
        emit("summary", recovered=len(records),
             bytes=sum(r.size for r in records), manifest=report_path)
    elif not args.quiet:
        print(f"\nrecovered {len(records)} deleted files, "
              f"{sum(r.size for r in records) / (1 << 20):,.1f} MiB "
              f"(MFT: {vol.record_count} records)", file=sys.stderr)
        if records:
            print(f"manifest: {report_path}", file=sys.stderr)
    return 0
