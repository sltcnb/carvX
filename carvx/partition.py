"""Partition table parsing + filesystem detection.

Supports MBR (incl. extended/logical), GPT, and Apple Partition Map. Detects
the filesystem / encryption type at each partition's start so undelete modes
can route to the right offset, and so --list-partitions can summarize a disk.
"""

import uuid
from dataclasses import dataclass

from .reader import Reader


def _u16(b, o=0): return int.from_bytes(b[o:o + 2], "little")
def _u32(b, o=0): return int.from_bytes(b[o:o + 4], "little")
def _u64(b, o=0): return int.from_bytes(b[o:o + 8], "little")
def _u32be(b, o=0): return int.from_bytes(b[o:o + 4], "big")


@dataclass
class Partition:
    index: int
    scheme: str          # mbr | gpt | apm
    start: int           # byte offset
    size: int            # bytes (0 if unknown)
    type_id: str         # MBR hex / GPT GUID / APM type string
    name: str            # label if known
    fstype: str          # detected filesystem at start, or ""


# MBR partition type byte -> label
_MBR_TYPES = {
    0x01: "FAT12", 0x04: "FAT16", 0x06: "FAT16B", 0x07: "NTFS/exFAT",
    0x0B: "FAT32", 0x0C: "FAT32L", 0x0E: "FAT16L", 0x05: "extended",
    0x0F: "extended", 0x82: "linux-swap", 0x83: "linux", 0x8E: "linux-lvm",
    0xA5: "freebsd", 0xA8: "apple-ufs", 0xAF: "apple-hfs", 0xEE: "gpt-protective",
    0xEF: "efi", 0xFD: "linux-raid",
}

# GPT type GUID -> label
_GPT_TYPES = {
    "c12a7328-f81f-11d2-ba4b-00a0c93ec93b": "efi-system",
    "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7": "basic-data",   # NTFS/exFAT/FAT
    "0fc63daf-8483-4772-8e79-3d69d8477de4": "linux-fs",
    "e6d6d379-f507-44c2-a23c-238f2a3df928": "linux-lvm",
    "a19d880f-05fc-4d3b-a006-743f0f84911e": "linux-raid",
    "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f": "linux-swap",
    "933ac7e1-2eb4-4f13-b844-0e14e2aef915": "linux-home",
    "48465300-0000-11aa-aa11-00306543ecac": "apple-hfs",
    "7c3457ef-0000-11aa-aa11-00306543ecac": "apple-apfs",
    "53746f72-6167-11aa-aa11-00306543ecac": "apple-core-storage",
    "426f6f74-0000-11aa-aa11-00306543ecac": "apple-boot",
}


def detect_fs(reader: Reader, offset: int) -> str:
    """Identify the filesystem/container at a byte offset from its superblock."""
    head = reader.pread(offset, 1024)
    if len(head) < 512:
        return ""
    if head[3:11] == b"NTFS    ":
        return "ntfs"
    if head[3:11] == b"EXFAT   ":
        return "exfat"
    if head[510:512] == b"\x55\xaa":
        # FAT: check FS type strings / BPB
        if head[82:90] == b"FAT32   " or head[54:62] in (b"FAT12   ", b"FAT16   ", b"FAT     "):
            return "fat"
        if _u16(head, 11) in (512, 1024, 2048, 4096) and head[13] and _u16(head, 14):
            return "fat"
    # ext2/3/4 superblock is at +1024
    sb = reader.pread(offset + 1024, 512)
    if len(sb) >= 58 and _u16(sb, 56) == 0xEF53:
        return "ext"
    if head[:4] in (b"H+\x00\x04", b"HX\x00\x05") or head[1024:1026] in (b"H+", b"HX"):
        return "hfs+"
    # APFS container superblock magic "NXSB" at +32
    if reader.pread(offset + 32, 4) == b"NXSB":
        return "apfs"
    # LUKS
    if head[:6] == b"LUKS\xba\xbe":
        return "luks"
    # BitLocker (FVE) - boot sector OEM id
    if head[3:11] in (b"-FVE-FS-", b"MSWIN4.1") and b"-FVE-FS-" in head[:512]:
        return "bitlocker"
    if head[3:11] == b"-FVE-FS-":
        return "bitlocker"
    return ""


def _guid_le(b: bytes) -> str:
    """16-byte mixed-endian GUID -> canonical string."""
    if len(b) < 16:
        return ""
    return str(uuid.UUID(bytes_le=b))


def parse(reader: Reader) -> list[Partition]:
    """Return all partitions found via GPT (preferred) or MBR, else []."""
    sector0 = reader.pread(0, 512)
    if sector0[510:512] != b"\x55\xaa":
        # could still be a raw APM (Apple) disk
        return _parse_apm(reader)
    # GPT if a protective/EE entry exists and the GPT header validates
    gpt = _parse_gpt(reader)
    if gpt:
        return gpt
    return _parse_mbr(reader)


def _parse_mbr(reader: Reader) -> list[Partition]:
    sector0 = reader.pread(0, 512)
    parts = []
    idx = 0
    for i in range(4):
        e = sector0[446 + i * 16:446 + (i + 1) * 16]
        ptype = e[4]
        lba = _u32(e, 8)
        count = _u32(e, 12)
        if ptype == 0 or lba == 0:
            continue
        if ptype in (0x05, 0x0F):                # extended -> walk logical chain
            parts.extend(_parse_ebr(reader, lba, idx))
            idx = len(parts)
            continue
        off = lba * 512
        parts.append(Partition(idx, "mbr", off, count * 512,
                               f"0x{ptype:02X}", _MBR_TYPES.get(ptype, ""),
                               detect_fs(reader, off)))
        idx += 1
    return parts


def _parse_ebr(reader: Reader, ext_lba: int, start_idx: int) -> list[Partition]:
    parts = []
    cur = ext_lba
    idx = start_idx
    seen = set()
    while cur and cur not in seen and len(parts) < 128:
        seen.add(cur)
        ebr = reader.pread(cur * 512, 512)
        if ebr[510:512] != b"\x55\xaa":
            break
        e = ebr[446:462]
        ptype, lba, count = e[4], _u32(e, 8), _u32(e, 12)
        if ptype and lba:
            off = (cur + lba) * 512
            parts.append(Partition(idx, "mbr", off, count * 512,
                                   f"0x{ptype:02X}", _MBR_TYPES.get(ptype, "logical"),
                                   detect_fs(reader, off)))
            idx += 1
        nxt = ebr[462:478]
        nxt_lba = _u32(nxt, 8)
        cur = ext_lba + nxt_lba if nxt_lba else 0
    return parts


def _parse_gpt(reader: Reader) -> list[Partition]:
    hdr = reader.pread(512, 512)
    if hdr[:8] != b"EFI PART":
        return []
    entry_lba = _u64(hdr, 72)
    num = _u32(hdr, 80)
    esize = _u32(hdr, 84)
    if not (1 <= num <= 1024) or esize < 128:
        return []
    table = reader.pread(entry_lba * 512, num * esize)
    parts = []
    idx = 0
    for i in range(num):
        e = table[i * esize:(i + 1) * esize]
        if len(e) < 128:
            break
        type_guid = _guid_le(e[:16])
        if type_guid == "00000000-0000-0000-0000-000000000000":
            continue
        first = _u64(e, 32)
        last = _u64(e, 40)
        name = e[56:128].decode("utf-16-le", "replace").split("\x00", 1)[0]
        off = first * 512
        parts.append(Partition(idx, "gpt", off, (last - first + 1) * 512,
                               type_guid, _GPT_TYPES.get(type_guid, name or ""),
                               detect_fs(reader, off)))
        idx += 1
    return parts


def _parse_apm(reader: Reader) -> list[Partition]:
    # Apple Partition Map: block 0 is "ER", block 1+ are "PM" entries.
    blk1 = reader.pread(512, 512)
    if blk1[:2] != b"PM":
        return []
    parts = []
    total = _u32be(blk1, 4)
    for i in range(min(total, 64)):
        e = reader.pread(512 * (1 + i), 512)
        if e[:2] != b"PM":
            break
        start = _u32be(e, 8) * 512
        size = _u32be(e, 12) * 512
        name = e[16:48].split(b"\x00", 1)[0].decode("ascii", "replace")
        ptype = e[48:80].split(b"\x00", 1)[0].decode("ascii", "replace")
        parts.append(Partition(i, "apm", start, size, ptype, name,
                               detect_fs(reader, start)))
    return parts


# Which undelete handler fits a detected fstype
FS_TO_MODE = {"ntfs": "ntfs", "exfat": "fat", "fat": "fat", "ext": "ext4",
              "hfs+": "hfs", "apfs": "apfs"}


def format_table(parts: list[Partition], sector_size: int = 512) -> str:
    if not parts:
        return "no partitions found (whole-disk filesystem or unknown scheme)"
    lines = [f"{'#':>2}  {'scheme':<6} {'start':>14} {'size':>12}  "
             f"{'type':<24} {'fs':<10} name"]
    for p in parts:
        size_mib = f"{p.size / (1 << 20):,.0f}M" if p.size else "?"
        lines.append(f"{p.index:>2}  {p.scheme:<6} {p.start:>14,} {size_mib:>12}  "
                     f"{p.type_id[:24]:<24} {p.fstype:<10} {p.name}")
    return "\n".join(lines)
