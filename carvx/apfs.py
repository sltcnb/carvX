"""APFS recovery via a copy-on-write object scan.

APFS never overwrites metadata in place: changing the filesystem writes new
B-tree nodes and leaves the old ones behind until their space is reused. That
makes deletion recoverable - the file-system tree (FS-tree) leaf node that held
a now-deleted file's records usually still exists as a superseded copy.

Rather than replay checkpoints, we scan every block for FS-tree leaf nodes
(validated by their Fletcher-64 checksum), decode the j-objects inside, and
join them across all versions:

    DIR_REC      parent_id + name      -> file_id
    INODE        file_id               -> logical size (DSTREAM xfield)
    FILE_EXTENT  file_id + logical_off -> physical block + length

Files are reassembled from their extents and trimmed to the inode size, so
block-aligned files recover byte-exact. Limits: compressed/encrypted streams
and inline (xattr) data are not decoded; heavily reused space loses old nodes.
"""

import hashlib
import os
import struct
import sys
from dataclasses import dataclass, field

from .images import open_source

NX_MAGIC = b"NXSB"
APSB_MAGIC = b"APSB"

OBJ_TYPE_BTREE = 0x0002         # B-tree root (single-node trees use this)
OBJ_TYPE_BTREE_NODE = 0x0003    # non-root B-tree node
OBJ_TYPE_MASK = 0x0000FFFF
SUBTYPE_FSTREE = 0x0000000E
BTREE_INFO_SIZE = 40            # btree_info trailer present in ROOT nodes

# j-object types (top 4 bits of obj_id_and_type)
J_INODE = 3
J_FILE_EXTENT = 8
J_DIR_REC = 9

INO_EXT_TYPE_DSTREAM = 8        # inode extended field carrying j_dstream
INO_EXT_TYPE_NAME = 4

BTNODE_ROOT = 0x0001
BTNODE_LEAF = 0x0002
BTNODE_FIXED_KV = 0x0004


def _u16(b, o=0): return int.from_bytes(b[o:o + 2], "little")
def _u32(b, o=0): return int.from_bytes(b[o:o + 4], "little")
def _u64(b, o=0): return int.from_bytes(b[o:o + 8], "little")


def fletcher64(data: bytes) -> bytes:
    """APFS object checksum over the block excluding the leading 8-byte field."""
    body = data[8:]
    lo = hi = 0
    # process as 32-bit little-endian words
    n = len(body) // 4
    for i in range(n):
        lo = (lo + _u32(body, i * 4)) % 0xFFFFFFFF
        hi = (hi + lo) % 0xFFFFFFFF
    c1 = (0xFFFFFFFF - ((lo + hi) % 0xFFFFFFFF))
    c2 = (0xFFFFFFFF - ((lo + c1) % 0xFFFFFFFF))
    return struct.pack("<II", c1, c2)


@dataclass
class ApfsRecord:
    type: str = "apfs"
    ext: str = "bin"
    offset: int = 0             # file_id (inode object id)
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


class ApfsContainer:
    def __init__(self, reader, base: int):
        self.reader = reader
        self.base = base
        sb = reader.pread(base, 4096)
        if sb[32:36] != NX_MAGIC:
            raise ValueError("no APFS container superblock (NXSB)")
        self.block_size = _u32(sb, 36)
        if self.block_size < 512 or self.block_size > (1 << 20):
            raise ValueError("implausible APFS block size")
        self.block_count = _u64(sb, 40)
        self.volume_size = self.block_count * self.block_size

    def block(self, n):
        return self.reader.pread(self.base + n * self.block_size, self.block_size)

    # -------------------------------------------------------------- scan

    def recover(self, out_dir, dry_run=False, include_live=False, min_size=0,
                on_file=None):
        inodes = {}          # file_id -> {size, timestamps}
        names = {}           # file_id -> (name, parent)
        extents = {}         # file_id -> {logical_off: (phys, length)}

        bs = self.block_size
        total = self.block_count
        for n in range(total):
            blk = self.block(n)
            if len(blk) < bs:
                break
            if not self._is_fstree_leaf(blk):
                continue
            self._parse_leaf(blk, inodes, names, extents)

        records = []
        seen = set()
        for file_id, exts in extents.items():
            name = names.get(file_id, (None, None))[0]
            meta = inodes.get(file_id, {})
            size = meta.get("size")
            if size is None:
                # fall back to extent coverage (block-aligned, may include slack)
                size = max((lo + ln) for lo, (ph, ln) in exts.items()) if exts else 0
            if size < max(min_size, 1):
                continue
            data, ok = self._read_extents(exts, size)
            if data is None:
                continue
            key = (file_id, size)
            if key in seen:
                continue
            seen.add(key)
            rec = self._emit(file_id, name, size, data, ok, meta, out_dir, dry_run)
            if rec is not None:
                records.append(rec)
                if on_file:
                    on_file(rec)
        return records

    def _is_fstree_leaf(self, blk):
        otype = _u32(blk, 24) & OBJ_TYPE_MASK
        subtype = _u32(blk, 28)
        if otype not in (OBJ_TYPE_BTREE, OBJ_TYPE_BTREE_NODE):
            return False
        if subtype != SUBTYPE_FSTREE:
            return False
        flags = _u16(blk, 32)
        if not (flags & BTNODE_LEAF):
            return False
        return blk[:8] == fletcher64(blk)

    def _parse_leaf(self, blk, inodes, names, extents):
        # btree_node_phys: obj(32) btn_flags(2) btn_level(2) btn_nkeys(4)
        #                  btn_table_space: off(2) len(2)  -> at 40
        flags = _u16(blk, 32)
        nkeys = _u32(blk, 36)
        toc_off = _u16(blk, 40)
        toc_len = _u16(blk, 42)
        fixed = bool(flags & BTNODE_FIXED_KV)
        key_area = 56 + toc_off + toc_len      # keys start after the TOC
        # value offsets count back from the data-area end; ROOT nodes carry a
        # 40-byte btree_info trailer that is not part of the value area.
        val_base = len(blk) - (BTREE_INFO_SIZE if (flags & BTNODE_ROOT) else 0)
        toc_base = 56 + toc_off
        if nkeys > 4096:
            return
        for i in range(nkeys):
            if fixed:
                e = toc_base + i * 4
                if e + 4 > len(blk):
                    break
                k_off = _u16(blk, e)
                v_off = _u16(blk, e + 2)
                k_len = v_len = None
            else:
                e = toc_base + i * 8
                if e + 8 > len(blk):
                    break
                k_off = _u16(blk, e)
                k_len = _u16(blk, e + 2)
                v_off = _u16(blk, e + 4)
                v_len = _u16(blk, e + 6)
            kpos = key_area + k_off
            vpos = val_base - v_off
            if kpos + 8 > len(blk) or vpos < 0 or vpos > len(blk):
                continue
            self._decode_record(blk, kpos, k_len, vpos, v_len,
                                 inodes, names, extents)

    def _decode_record(self, blk, kpos, k_len, vpos, v_len, inodes, names, extents):
        oid_type = _u64(blk, kpos)
        obj_id = oid_type & 0x0FFFFFFFFFFFFFFF
        jtype = (oid_type >> 60) & 0x0F

        if jtype == J_FILE_EXTENT:
            if kpos + 16 > len(blk) or v_len is None or vpos + 16 > len(blk):
                return
            logical = _u64(blk, kpos + 8)
            len_and_flags = _u64(blk, vpos)
            length = len_and_flags & 0x00FFFFFFFFFFFFFF
            phys = _u64(blk, vpos + 8)
            extents.setdefault(obj_id, {})[logical] = (phys, length)

        elif jtype == J_INODE:
            if v_len is None or vpos + 40 > len(blk):
                return
            create = _u64(blk, vpos + 16)
            mod = _u64(blk, vpos + 24)
            access = _u64(blk, vpos + 40) if vpos + 48 <= len(blk) else 0
            size = self._inode_dstream_size(blk, vpos, v_len)
            inodes[obj_id] = {
                "size": size,
                "timestamps": {"crtime": _ns(create), "mtime": _ns(mod),
                               "atime": _ns(access), "ctime": 0, "dtime": 0}}

        elif jtype == J_DIR_REC:
            # key: oid_type(8) name_len_and_hash(4) name(...)
            if kpos + 12 > len(blk):
                return
            nlh = _u32(blk, kpos + 8)
            name_len = nlh & 0x3FF              # low 10 bits = length incl NUL
            name = blk[kpos + 12:kpos + 12 + name_len].split(b"\x00", 1)[0]
            if v_len is None or vpos + 8 > len(blk):
                return
            file_id = _u64(blk, vpos)           # j_drec_val.file_id
            try:
                nm = name.decode("utf-8")
            except UnicodeDecodeError:
                return
            if nm and nm not in (".", ".."):
                names.setdefault(file_id, (nm, obj_id))

    def _inode_dstream_size(self, blk, vpos, v_len):
        """Parse the inode's extended fields for the DSTREAM (logical size)."""
        # j_inode_val fixed part is 92 bytes, then xfields:
        #   xf_blob: xf_num_exts(2) xf_used_data(2) then xfield headers + data
        base = vpos + 92
        if base + 4 > len(blk):
            return None
        num = _u16(blk, base)
        hdr = base + 4
        data = hdr + num * 4
        if data > len(blk):
            return None
        off = data
        for i in range(num):
            xtype = blk[hdr + i * 4]
            xlen = _u16(blk, hdr + i * 4 + 2)
            if xtype == INO_EXT_TYPE_DSTREAM and off + 8 <= len(blk):
                return _u64(blk, off)          # j_dstream.size is first field
            off += (xlen + 7) & ~7             # 8-byte aligned
        return None

    def _read_extents(self, exts, size):
        data = bytearray()
        ok = True
        for logical in sorted(exts):
            phys, length = exts[logical]
            if logical != len(data):           # gap / out-of-order -> best effort
                ok = False
            if phys == 0:
                data += bytes(length)
                ok = False
                continue
            data += self.reader.pread(self.base + phys * self.block_size, length)
        if len(data) < size:
            data += bytes(size - len(data))
            ok = False
        return bytes(data[:size]), ok

    def _emit(self, file_id, name, size, data, ok, meta, out_dir, dry_run):
        digest = hashlib.sha256(data).hexdigest()
        label = name or f"inode_{file_id}"
        ext = os.path.splitext(label)[1].lstrip(".").lower() or "bin"
        out_path = ""
        if not dry_run:
            safe = label.replace("/", "_").replace("\x00", "_")
            out_path = os.path.join(out_dir, "apfs", safe)
            os.makedirs(os.path.dirname(out_path) or out_path, exist_ok=True)
            if os.path.isdir(out_path):
                out_path = os.path.join(out_path, f"inode_{file_id}.{ext}")
            if os.path.exists(out_path):
                stem, e = os.path.splitext(out_path)
                out_path = f"{stem}_{file_id}{e}"
            with open(out_path, "wb") as fh:
                fh.write(data)
        return ApfsRecord(ext=ext, offset=file_id, size=size, sha256=digest,
                          validated=ok and name is not None, path=out_path,
                          name=label, deleted=True,
                          timestamps=meta.get("timestamps", {}))


APFS_EPOCH_NS = 0          # APFS timestamps are nanoseconds since 1970 already


def _ns(t):
    return t // 1_000_000_000 if t else 0


def recover_apfs(source, offset, out_dir, dry_run=False, include_live=False,
                 min_size=0, on_file=None):
    reader = open_source(source)
    base, cont = _locate(reader, offset)
    records = cont.recover(out_dir, dry_run, include_live, min_size, on_file)
    return records, cont


def _locate(reader, offset):
    # NXSB magic sits at +32 of the container's first block.
    if reader.pread(offset + 32, 4) == NX_MAGIC:
        return offset, ApfsContainer(reader, offset)
    if offset:
        raise ValueError("no APFS container at the given offset")
    sector0 = reader.pread(0, 512)
    if sector0[510:512] == b"\x55\xaa":
        # GPT/MBR: try each partition start
        for i in range(4):
            e = sector0[446 + i * 16:446 + (i + 1) * 16]
            lba = int.from_bytes(e[8:12], "little")
            if e[4] and lba and reader.pread(lba * 512 + 32, 4) == NX_MAGIC:
                return lba * 512, ApfsContainer(reader, lba * 512)
        # GPT entries
        gpt = reader.pread(512, 512)
        if gpt[:8] == b"EFI PART":
            elba = int.from_bytes(gpt[72:80], "little")
            count = int.from_bytes(gpt[80:84], "little")
            esize = int.from_bytes(gpt[84:88], "little")
            table = reader.pread(elba * 512, count * esize)
            for j in range(count):
                first = int.from_bytes(table[j * esize + 32:j * esize + 40], "little")
                if first and reader.pread(first * 512 + 32, 4) == NX_MAGIC:
                    return first * 512, ApfsContainer(reader, first * 512)
    raise ValueError("no APFS container found (give the partition offset via --offset)")


def run_apfs(args) -> int:
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
        records, cont = recover_apfs(
            args.source, parse_size(args.offset), args.output,
            dry_run=args.dry_run, min_size=parse_size(args.min_size),
            on_file=on_file)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    class _O:
        dry_run = args.dry_run
    scan_meta = {"mode": "apfs", "started": t0.isoformat(),
                 "finished": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                 "block_size": cont.block_size}
    report_path = write_outputs(args, _O, records, cont.volume_size, scan_meta)
    if args.machine:
        emit("summary", recovered=len(records),
             bytes=sum(r.size for r in records), manifest=report_path)
    elif not args.quiet:
        print(f"\nrecovered {len(records)} files (APFS)", file=sys.stderr)
        if records:
            print(f"manifest: {report_path}", file=sys.stderr)
    return 0
