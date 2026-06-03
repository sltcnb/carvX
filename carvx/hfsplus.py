"""HFS+ / HFSX undelete via the catalog B-tree.

The volume header points at the catalog file (a B-tree). Live files are read
by walking leaf nodes; deleted files are recovered from catalog leaf-node
*slack* and from nodes left in the free list, where the original file record
(name + fork extents) often survives after the entry is unlinked from the tree.

Recovers names, sizes, timestamps, and file data via the data-fork extent
records (first 8 extents; extents-overflow file is not followed, so very
fragmented files recover only their first extents - flagged best-effort).
"""

import hashlib
import os
import sys
from dataclasses import dataclass, field

from .images import open_source

HFSP_SIG = b"H+"
HFSX_SIG = b"HX"
HFS_EPOCH = 2082844800          # 1904-01-01 -> 1970-01-01 in seconds


def _u16(b, o=0): return int.from_bytes(b[o:o + 2], "big")
def _u32(b, o=0): return int.from_bytes(b[o:o + 4], "big")
def _u64(b, o=0): return int.from_bytes(b[o:o + 8], "big")


def _hfs_time(t: int) -> int:
    return max(0, t - HFS_EPOCH) if t else 0


@dataclass
class HfsRecord:
    type: str = "hfs+"
    ext: str = "bin"
    offset: int = 0             # catalog node id (CNID)
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


class HfsVolume:
    def __init__(self, reader, base: int):
        self.reader = reader
        self.base = base
        vh = reader.pread(base + 1024, 512)      # volume header at offset 1024
        if vh[:2] not in (HFSP_SIG, HFSX_SIG):
            raise ValueError("no HFS+/HFSX volume header")
        self.block_size = _u32(vh, 40)
        self.total_blocks = _u32(vh, 44)
        if self.block_size < 512 or self.block_size > (1 << 20):
            raise ValueError("implausible HFS+ block size")
        self.volume_size = self.total_blocks * self.block_size
        # catalog file fork data is at offset 272 in the volume header:
        # logicalSize(8) clumpSize(4) totalBlocks(4) then 8 extents(8 bytes each)
        self.catalog_extents = self._fork_extents(vh, 272)
        self.catalog_size = _u64(vh, 272)

    def _fork_extents(self, buf, off):
        # HFSPlusForkData: logicalSize(8) clumpSize(4) totalBlocks(4)
        # extents: 8 * (startBlock(4) blockCount(4))
        exts = []
        eoff = off + 16
        for i in range(8):
            start = _u32(buf, eoff + i * 8)
            count = _u32(buf, eoff + i * 8 + 4)
            if count:
                exts.append((start, count))
        return exts

    def _read_fork(self, extents, size):
        data = bytearray()
        ok = True
        for start, count in extents:
            need = size - len(data)
            if need <= 0:
                break
            off = self.base + start * self.block_size
            data += self.reader.pread(off, min(count * self.block_size, need))
        if len(data) < size:
            data += bytes(size - len(data))
            ok = False
        return bytes(data[:size]), ok

    def _catalog_bytes(self):
        data, _ = self._read_fork(self.catalog_extents, self.catalog_size or
                                  sum(c for _, c in self.catalog_extents) * self.block_size)
        return data

    # -------------------------------------------------------------- B-tree

    def recover(self, out_dir, dry_run=False, include_live=False, min_size=0,
                on_file=None, scan_volume=True):
        catalog = self._catalog_bytes()
        if len(catalog) < 14:
            return []
        # node 0 = header: BTNodeDescriptor(14) + BTHeaderRec; nodeSize at +32
        # (treeDepth2 rootNode4 leafRecords4 firstLeaf4 lastLeaf4 -> +14+18=32).
        node_size = _u16(catalog, 32)
        if node_size < 512 or node_size & (node_size - 1):
            node_size = 4096
        records = []
        names = {}
        # first pass: collect thread records (CNID -> name/parent) for path build
        leaves = []
        n_nodes = len(catalog) // node_size
        for n in range(n_nodes):
            node = catalog[n * node_size:(n + 1) * node_size]
            if len(node) < 14:
                continue
            kind = node[8]                       # -1 leaf, 0 index, 1 header, 2 map
            # treat leaf nodes (kind 0xFF) AND any node for slack scanning
            self._scan_node(node, node_size, names, leaves)
        live_cnids = {r["cnid"] for r in leaves}

        # Whole-volume scan: catalog leaf nodes left in the journal or in
        # unallocated space hold deleted file records compacted out of the live
        # B-tree. Scan every node_size-aligned block across the volume.
        deleted_leaves = []
        if scan_volume:
            self._scan_whole_volume(node_size, names, deleted_leaves, live_cnids)

        paths = _build_paths(names)
        seen = set()
        records = []
        for rec, is_live in ([(r, True) for r in leaves]
                             + [(r, False) for r in deleted_leaves]):
            cnid = rec["cnid"]
            key = (cnid, rec["name"], rec["size"])
            if key in seen:
                continue
            if rec["is_dir"] or rec["size"] == 0 or rec["size"] < max(min_size, 1):
                continue
            if is_live and not include_live:
                continue
            seen.add(key)
            data, ok = self._read_fork(rec["extents"], rec["size"])
            vpath = paths.get(cnid) or rec["name"]
            out = self._emit(rec, vpath, data, ok, out_dir, dry_run,
                             deleted=not is_live)
            if out is not None:
                records.append(out)
                if on_file:
                    on_file(out)
        return records

    def _scan_whole_volume(self, node_size, names, out_leaves, live_cnids):
        """Scan the entire volume for catalog leaf nodes holding file records
        (recovers deleted entries from the journal / old node copies)."""
        seen_keys = set()
        step = max(node_size, 1 << 20)
        pos = 0
        while pos < self.volume_size:
            buf = self.reader.pread(self.base + pos, step)
            if not buf:
                break
            # try every 512-byte boundary as a potential node start (journal
            # copies are not always node_size-aligned to the catalog file)
            for off in range(0, len(buf) - 14, 512):
                node = buf[off:off + node_size]
                if len(node) < 14 or node[8] not in (0xFF,):   # leaf kind = -1
                    continue
                tmp = []
                self._scan_node(node, min(node_size, len(node)), names, tmp)
                for rec in tmp:
                    k = (rec["cnid"], rec["name"], rec["size"])
                    if rec["cnid"] in live_cnids or k in seen_keys:
                        continue
                    seen_keys.add(k)
                    out_leaves.append(rec)
            pos += step

    def _scan_node(self, node, node_size, names, leaves):
        """Parse catalog records from a node, including stale ones in slack.

        Rather than trust the record-offset array (gone for deleted records),
        scan for catalog data records by their key structure: keyLength(2),
        parentCNID(4), nameLength(2), name(UTF-16BE), then recordType(2)."""
        n = len(node)
        pos = 14                                 # past node descriptor
        end = node_size
        while pos + 8 < end:
            key_len = _u16(node, pos)
            if key_len < 6 or key_len > 516 or pos + 2 + key_len + 2 > end:
                pos += 2
                continue
            parent = _u32(node, pos + 2)
            name_len = _u16(node, pos + 6)
            if name_len > 255 or pos + 8 + name_len * 2 > end:
                pos += 2
                continue
            rec_off = pos + 2 + key_len
            rec_off += rec_off & 1               # records are 2-byte aligned
            if rec_off + 2 > end:
                pos += 2
                continue
            rtype = _u16(node, rec_off)
            # 1 = folder, 2 = file, 3/4 = thread records
            if rtype not in (0x0001, 0x0002):
                pos += 2
                continue
            name = node[pos + 8:pos + 8 + name_len * 2].decode("utf-16-be", "replace")
            if not name or "\x00" in name:
                pos += 2
                continue
            if rtype == 0x0001:                  # folder record: folderID at +8
                cnid = _u32(node, rec_off + 8)
                names.setdefault(cnid, (name, parent))
                pos = rec_off + 2
                continue
            # file record (0x0002): parse CNID + data fork
            rec = self._parse_file_record(node, rec_off, name, parent)
            if rec is not None:
                names.setdefault(rec["cnid"], (name, parent))
                leaves.append(rec)
            pos = rec_off + 2

    def _parse_file_record(self, node, off, name, parent):
        # HFSPlusCatalogFile: recordType(2) flags(2) reserved1(4) fileID(4)
        # createDate(4) contentModDate(4) attributeModDate(4) accessDate(4)
        # backupDate(4) ... bsdInfo(16) ... userInfo(16) finderInfo(16)
        # textEncoding(4) reserved2(4) dataFork(80) resourceFork(80)
        if off + 248 > len(node):
            return None
        cnid = _u32(node, off + 8)
        create = _u32(node, off + 12)
        mod = _u32(node, off + 16)
        access = _u32(node, off + 24)
        data_fork_off = off + 88                 # dataFork start
        if data_fork_off + 80 > len(node):
            return None
        logical = _u64(node, data_fork_off)
        exts = []
        eoff = data_fork_off + 16
        for i in range(8):
            start = _u32(node, eoff + i * 8)
            count = _u32(node, eoff + i * 8 + 4)
            if count:
                exts.append((start, count))
        if logical == 0 or logical > self.volume_size or not exts:
            return None
        return {"cnid": cnid, "name": name, "parent": parent, "size": logical,
                "extents": exts, "is_dir": False,
                "timestamps": {"crtime": _hfs_time(create), "mtime": _hfs_time(mod),
                               "atime": _hfs_time(access), "ctime": 0, "dtime": 0}}

    def _emit(self, rec, vpath, data, ok, out_dir, dry_run, deleted=True):
        digest = hashlib.sha256(data).hexdigest()
        name = vpath or rec["name"]
        ext = os.path.splitext(rec["name"])[1].lstrip(".").lower() or "bin"
        out_path = ""
        if not dry_run:
            safe = name.lstrip("/").replace("\x00", "_")
            out_path = os.path.join(out_dir, "hfs+", safe or f"cnid_{rec['cnid']}")
            os.makedirs(os.path.dirname(out_path) or out_path, exist_ok=True)
            if os.path.isdir(out_path):
                out_path = os.path.join(out_path, f"cnid_{rec['cnid']}.{ext}")
            if os.path.exists(out_path):
                stem, e = os.path.splitext(out_path)
                out_path = f"{stem}_{rec['cnid']}{e}"
            with open(out_path, "wb") as fh:
                fh.write(data)
        return HfsRecord(ext=ext, offset=rec["cnid"], size=rec["size"],
                         sha256=digest, validated=ok, path=out_path, name=name,
                         deleted=deleted, timestamps=rec["timestamps"])


# CNID 2 is the root folder
def _build_paths(names: dict) -> dict:
    cache = {2: ""}

    def walk(cnid, depth=0):
        if cnid in cache:
            return cache[cnid]
        if depth > 64 or cnid not in names:
            cache[cnid] = ""
            return ""
        nm, parent = names[cnid]
        prefix = walk(parent, depth + 1)
        safe = nm.replace("/", "_").replace("\x00", "_")
        cache[cnid] = f"{prefix}/{safe}" if prefix else safe
        return cache[cnid]

    return {c: walk(c) for c in names}


def recover_hfs(source, offset, out_dir, dry_run=False, include_live=False,
                min_size=0, on_file=None):
    reader = open_source(source)
    base, vol = _locate(reader, offset)
    records = vol.recover(out_dir, dry_run, include_live, min_size, on_file)
    return records, vol


def _locate(reader, offset):
    try:
        return offset, HfsVolume(reader, offset)
    except ValueError:
        if offset:
            raise
    sector0 = reader.pread(0, 512)
    if sector0[510:512] == b"\x55\xaa":
        for i in range(4):
            e = sector0[446 + i * 16:446 + (i + 1) * 16]
            lba = int.from_bytes(e[8:12], "little")
            if e[4] and lba:
                try:
                    return lba * 512, HfsVolume(reader, lba * 512)
                except ValueError:
                    continue
    raise ValueError("no HFS+ volume found (give the partition offset via --offset)")


def run_hfs(args) -> int:
    from .carver import emit
    from .cli import parse_size, write_outputs
    import datetime

    quiet = args.quiet or args.machine
    t0 = datetime.datetime.now(datetime.timezone.utc)

    def on_file(rec):
        if args.machine:
            emit("file", name=rec.name, cnid=rec.offset, size=rec.size,
                 sha256=rec.sha256, deleted=rec.deleted, validated=rec.validated,
                 path=rec.path)
        elif not quiet:
            flag = "" if rec.validated else "  (low confidence)"
            sys.stderr.write(f"[+] {rec.name}  {rec.size:,} B{flag}\n")

    try:
        records, vol = recover_hfs(
            args.source, parse_size(args.offset), args.output,
            dry_run=args.dry_run, min_size=parse_size(args.min_size),
            on_file=on_file)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    class _O:
        dry_run = args.dry_run
    scan_meta = {"mode": "hfs+", "started": t0.isoformat(),
                 "finished": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                 "block_size": vol.block_size}
    report_path = write_outputs(args, _O, records, vol.volume_size, scan_meta)
    if args.machine:
        emit("summary", recovered=len(records),
             bytes=sum(r.size for r in records), manifest=report_path)
    elif not args.quiet:
        print(f"\nrecovered {len(records)} files (HFS+)", file=sys.stderr)
        if records:
            print(f"manifest: {report_path}", file=sys.stderr)
    return 0
