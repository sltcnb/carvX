"""Partition table parsing + filesystem detection + --auto routing."""

import struct


from carvx.partition import parse, detect_fs, FS_TO_MODE
from carvx.reader import Reader


def _mbr_disk(tmp_path, parts):
    """parts: list of (ptype, payload_bytes). Lay out at 1 MiB-aligned LBAs."""
    sector = 512
    entries = []
    lba = 2048
    blobs = []
    for ptype, payload in parts:
        sectors = (len(payload) + sector - 1) // sector
        entries.append((ptype, lba, sectors))
        blobs.append((lba, payload))
        lba += sectors + 2048
    disk = bytearray((lba + 64) * sector)
    mbr = bytearray(512)
    mbr[510:512] = b"\x55\xaa"
    for i, (ptype, start, count) in enumerate(entries):
        off = 446 + i * 16
        mbr[off + 4] = ptype
        struct.pack_into("<I", mbr, off + 8, start)
        struct.pack_into("<I", mbr, off + 12, count)
    disk[0:512] = mbr
    for start, payload in blobs:
        disk[start * sector:start * sector + len(payload)] = payload
    path = tmp_path / "disk.img"
    path.write_bytes(disk)
    return str(path)


def _gpt_disk(tmp_path, type_guid: bytes, payload: bytes):
    sector = 512
    first = 2048
    sectors = (len(payload) + sector - 1) // sector
    disk = bytearray((first + sectors + 64) * sector)
    # protective MBR
    disk[510:512] = b"\x55\xaa"
    disk[446 + 4] = 0xEE
    # GPT header at LBA1
    hdr = bytearray(512)
    hdr[:8] = b"EFI PART"
    struct.pack_into("<Q", hdr, 72, 2)           # entry array LBA
    struct.pack_into("<I", hdr, 80, 1)           # num entries
    struct.pack_into("<I", hdr, 84, 128)         # entry size
    disk[512:1024] = hdr
    # one entry at LBA2
    entry = bytearray(128)
    entry[:16] = type_guid
    entry[16:32] = b"\x11" * 16                  # unique guid
    struct.pack_into("<Q", entry, 32, first)
    struct.pack_into("<Q", entry, 40, first + sectors - 1)
    entry[56:72] = "DATA".encode("utf-16-le")
    disk[1024:1024 + 128] = entry
    disk[first * sector:first * sector + len(payload)] = payload
    path = tmp_path / "gpt.img"
    path.write_bytes(disk)
    return str(path)


def test_mbr_parse_and_fs_detect(tmp_path):
    ntfs = b"\xeb\x52\x90NTFS    " + b"\x00" * 500 + b"\x55\xaa"
    fat = (b"\xeb\x58\x90MSDOS5.0" + b"\x00" * 74 + b"FAT32   "
           + b"\x00" * 420)
    fat = bytearray(512)
    fat[3:11] = b"MSDOS5.0"
    struct.pack_into("<H", fat, 11, 512)
    fat[13] = 8
    struct.pack_into("<H", fat, 14, 32)
    fat[82:90] = b"FAT32   "
    fat[510:512] = b"\x55\xaa"
    path = _mbr_disk(tmp_path, [(0x07, ntfs), (0x0C, bytes(fat))])
    with Reader(path) as r:
        parts = parse(r)
    assert len(parts) == 2
    assert parts[0].scheme == "mbr" and parts[0].fstype == "ntfs"
    assert parts[1].fstype == "fat"


def test_gpt_parse(tmp_path):
    # basic-data GUID with an NTFS boot sector inside
    guid = b"\xa2\xa0\xd0\xeb\xe5\xb9\x33\x44\x87\xc0\x68\xb6\xb7\x26\x99\xc7"
    ntfs = bytearray(512)
    ntfs[3:11] = b"NTFS    "
    ntfs[510:512] = b"\x55\xaa"
    path = _gpt_disk(tmp_path, guid, bytes(ntfs))
    with Reader(path) as r:
        parts = parse(r)
    assert len(parts) == 1
    assert parts[0].scheme == "gpt"
    assert parts[0].type_id == "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7"
    assert parts[0].fstype == "ntfs"


def test_detect_ext(tmp_path):
    vol = bytearray(2048)
    struct.pack_into("<H", vol, 1024 + 56, 0xEF53)   # ext magic at +1024+56
    path = tmp_path / "e.img"
    path.write_bytes(bytes(vol))
    with Reader(path) as r:
        assert detect_fs(r, 0) == "ext"


def test_detect_luks(tmp_path):
    p = tmp_path / "l.img"
    p.write_bytes(b"LUKS\xba\xbe" + b"\x00" * 1018)
    with Reader(p) as r:
        assert detect_fs(str(p) and r, 0) == "luks"


def test_no_partition_table(tmp_path):
    p = tmp_path / "raw.img"
    p.write_bytes(b"\x00" * (1 << 20))
    with Reader(p) as r:
        assert parse(r) == []


def test_fs_to_mode_mapping():
    assert FS_TO_MODE["ntfs"] == "ntfs"
    assert FS_TO_MODE["ext"] == "ext4"
    assert FS_TO_MODE["fat"] == "fat"
    assert FS_TO_MODE["exfat"] == "fat"
