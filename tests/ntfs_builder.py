"""Build a minimal but structurally valid NTFS volume image for tests.

Layout (cluster = 4096, record = 1024):
  cluster 0      : boot sector
  cluster 4..    : $MFT (record 0 maps itself), records 0..N
  data clusters  : non-resident file content

Records created:
  0  $MFT (self-mapping $DATA runlist)
  5  root directory (.)
  64 live-resident.txt        (in_use,  resident $DATA)
  65 deleted-resident.txt     (deleted, resident $DATA)
  66 deleted-frag.bin         (deleted, non-resident, TWO fragments)

Returns (path, expected) where expected maps mft_num -> (name, sha256, size,
deleted).
"""

import hashlib
import os
import random
import struct

SECTOR = 512
CLUSTER = 4096
REC = 1024
SPC = CLUSTER // SECTOR

FT = 116444736000000000 + 1_700_000_000 * 10_000_000   # some 2023 time


def _runlist(runs):
    """Encode [(lcn, count)] into an NTFS runlist (absolute -> deltas)."""
    out = bytearray()
    prev = 0
    for lcn, count in runs:
        cb = max(1, (count.bit_length() + 7) // 8)
        delta = lcn - prev
        ob = max(1, (delta.bit_length() + 8) // 8)       # signed, room for sign
        out.append((ob << 4) | cb)
        out += count.to_bytes(cb, "little")
        out += delta.to_bytes(ob, "little", signed=True)
        prev = lcn
    out.append(0)
    return bytes(out)


def _attr_header_resident(atype, content, name="", flags=0):
    namelen = len(name)
    nameoff = 24
    coff = nameoff + namelen * 2
    coff += (-coff) % 8
    total = coff + len(content)
    total += (-total) % 8
    h = bytearray(total)
    struct.pack_into("<IIBBHHH", h, 0, atype, total, 0, namelen, nameoff,
                     flags, 0)
    struct.pack_into("<IHBB", h, 16, len(content), coff, 0, 0)
    if namelen:
        h[nameoff:nameoff + namelen * 2] = name.encode("utf-16-le")
    h[coff:coff + len(content)] = content
    return bytes(h)


def _attr_header_nonresident(atype, runs, real_size, name="", flags=0):
    namelen = len(name)
    nameoff = 64
    runoff = nameoff + namelen * 2
    runoff += (-runoff) % 8
    runlist = _runlist(runs)
    total = runoff + len(runlist)
    total += (-total) % 8
    last_vcn = sum(c for _, c in runs) - 1
    alloc = (last_vcn + 1) * CLUSTER
    h = bytearray(total)
    struct.pack_into("<IIBBHHH", h, 0, atype, total, 1, namelen, nameoff, flags, 0)
    struct.pack_into("<QQH", h, 16, 0, last_vcn, runoff)        # start/last vcn, runoff
    struct.pack_into("<QQQ", h, 40, alloc, real_size, real_size)  # alloc/real/init
    if namelen:
        h[nameoff:nameoff + namelen * 2] = name.encode("utf-16-le")
    h[runoff:runoff + len(runlist)] = runlist
    return bytes(h)


def _standard_info():
    c = bytearray(72)
    for off in (0, 8, 16, 24):
        struct.pack_into("<Q", c, off, FT)
    return _attr_header_resident(0x10, bytes(c))


def _filename(parent_ref, name):
    c = bytearray(66 + len(name) * 2)
    struct.pack_into("<Q", c, 0, parent_ref | (1 << 48))       # parent ref + seq
    for off in (8, 16, 24, 32):
        struct.pack_into("<Q", c, off, FT)
    c[64] = len(name)
    c[65] = 1                                                  # Win32 namespace
    c[66:] = name.encode("utf-16-le")
    return _attr_header_resident(0x30, bytes(c))


def _build_record(num, *, seq=1, in_use=True, is_dir=False, attrs=()):
    rec = bytearray(REC)
    body = bytearray()
    for a in attrs:
        body += a
    body += b"\xff\xff\xff\xff" + b"\x00\x00\x00\x00"
    attr_off = 56
    usa_off = 48
    flags = (1 if in_use else 0) | (2 if is_dir else 0)
    used = attr_off + len(body)
    struct.pack_into("<4sHHQHHHHII", rec, 0,
                     b"FILE", usa_off, 3,            # sig, usa off, usa count(=3)
                     0, seq, 1, attr_off, flags, used, REC)
    struct.pack_into("<Q", rec, 32, 0)              # base record ref = 0
    rec[attr_off:attr_off + len(body)] = body
    # update sequence: usn at usa_off, then 2 fixup slots; write usn to each
    # sector tail and stash original tail bytes into the USA.
    usn = b"\x01\x00"
    struct.pack_into("<H", rec, usa_off, 1)
    for i in range(1, 3):
        tail = i * SECTOR - 2
        rec[usa_off + i * 2:usa_off + i * 2 + 2] = rec[tail:tail + 2]
        rec[tail:tail + 2] = usn
    return bytes(rec)


def build(path):
    expected = {}
    # Plan clusters: boot=0; data file lives at clusters 2..; MFT at cluster 8.
    mft_cluster = 8
    data_cluster_a = 4          # fragment 1
    data_cluster_b = 6          # fragment 2 (non-contiguous -> tests runlist)
    n_records = 67

    # deleted-frag.bin content spanning two non-adjacent clusters
    # deterministic so rebuilding the image yields identical content
    frag = random.Random(1234).randbytes(CLUSTER + 1000)   # > 1 cluster -> 2 clusters
    frag_runs = [(data_cluster_a, 1), (data_cluster_b, 1)]

    live_txt = b"i am a live resident file\n"
    del_txt = b"secret deleted note, recover me\n" * 3

    records = {}

    # record 0: $MFT, self-mapping data at mft_cluster, size = n_records*REC
    mft_size = n_records * REC
    mft_clusters = (mft_size + CLUSTER - 1) // CLUSTER
    records[0] = _build_record(
        0, attrs=[_standard_info(),
                  _filename(5, "$MFT"),
                  _attr_header_nonresident(0x80, [(mft_cluster, mft_clusters)], mft_size)])

    records[5] = _build_record(5, is_dir=True,
                               attrs=[_standard_info(), _filename(5, ".")])

    records[64] = _build_record(
        64, attrs=[_standard_info(), _filename(5, "live-resident.txt"),
                   _attr_header_resident(0x80, live_txt)])
    expected[64] = ("/live-resident.txt", hashlib.sha256(live_txt).hexdigest(),
                    len(live_txt), False)

    records[65] = _build_record(
        65, in_use=False,
        attrs=[_standard_info(), _filename(5, "deleted-resident.txt"),
               _attr_header_resident(0x80, del_txt)])
    expected[65] = ("/deleted-resident.txt", hashlib.sha256(del_txt).hexdigest(),
                    len(del_txt), True)

    records[66] = _build_record(
        66, in_use=False,
        attrs=[_standard_info(), _filename(5, "deleted-frag.bin"),
               _attr_header_nonresident(0x80, frag_runs, len(frag))])
    expected[66] = ("/deleted-frag.bin", hashlib.sha256(frag).hexdigest(),
                    len(frag), True)

    # Assemble image
    total_clusters = mft_cluster + mft_clusters + 2
    img = bytearray(total_clusters * CLUSTER)

    # boot sector
    boot = bytearray(512)
    boot[3:11] = b"NTFS    "
    struct.pack_into("<H", boot, 11, SECTOR)
    boot[13] = SPC
    struct.pack_into("<Q", boot, 40, total_clusters * SPC)     # total sectors
    struct.pack_into("<Q", boot, 48, mft_cluster)              # $MFT LCN
    struct.pack_into("<Q", boot, 56, mft_cluster)              # $MFTMirr (reuse)
    boot[64] = 256 - 10                                        # -10 -> 2^10 = 1024
    boot[510:512] = b"\x55\xaa"
    img[0:512] = boot

    # MFT records
    for num, rec in records.items():
        off = mft_cluster * CLUSTER + num * REC
        img[off:off + REC] = rec

    # data clusters
    img[data_cluster_a * CLUSTER:data_cluster_a * CLUSTER + CLUSTER] = \
        frag[:CLUSTER]
    img[data_cluster_b * CLUSTER:data_cluster_b * CLUSTER + (len(frag) - CLUSTER)] = \
        frag[CLUSTER:]

    with open(path, "wb") as fh:
        fh.write(img)
    return path, expected


if __name__ == "__main__":
    import tempfile
    p, exp = build(os.path.join(tempfile.gettempdir(), "carvx_ntfs.img"))
    print("built", p)
    for num, (name, sha, size, deleted) in exp.items():
        print(f"  mft {num}: {name} {size}B deleted={deleted}")
