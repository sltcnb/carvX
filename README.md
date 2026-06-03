# carvX

Signature-based file carver for disk images and block devices, in the spirit of
PhotoRec / Sleuth Kit. Recovers deleted files by scanning raw bytes — no
filesystem metadata needed, so it works on formatted, corrupted, or unknown
filesystems and on unallocated space.

Pure Python 3.10+, stdlib only.

## Install

```sh
pip install -e .
# or run without installing:
python3 -m carvx --help
```

Pure Python 3.10+ / stdlib only. Optional extras improve specific features:
`Pillow` (full JPEG/PNG decode for `--validate` + JPEG bifragment), `pyewf`
(robust EWF/E01), `pyahocorasick` (faster matching with huge signature sets).
Disk-image formats (raw, split, EWF/E01, QCOW2, VMDK) are auto-detected.

## Usage

```sh
# carve a disk image
carvx image.dd -o recovered/

# carve a whole disk (raw devices need root; on macOS prefer /dev/diskN
# over /dev/rdiskN — rdisk requires block-aligned reads)
sudo carvx /dev/disk4 -o recovered/          # macOS
sudo carvx /dev/sdb -o recovered/            # Linux
carvx \\.\PhysicalDrive1 -o recovered\       # Windows (admin shell)
carvx \\.\D: -o recovered\                   # Windows, single volume

# only some types
carvx image.dd -t jpg,png,pdf,sqlite -o out/

# scan a region (e.g. one partition: offset + length)
carvx /dev/disk4 --offset 209735680 --length 64G -o out/

# faster scan of a filesystem with known cluster alignment
carvx image.dd --align 4096 -o out/

# inventory only, write nothing
carvx image.dd --dry-run

# go faster: 8 parallel scan processes (0 = all cores)
carvx image.dd -j 8 -o out/

# also emit CSV + Sleuth Kit bodyfile; hash the whole source for custody
carvx image.dd -o out/ --csv out/files.csv --bodyfile out/bodyfile --hash-source

# JSON-lines events on stdout (for wrapping in a GUI/pipeline)
carvx image.dd --machine -o out/

# deep-validate carves (decode JPEG/PNG/ZIP/gzip/SQLite), drop ones that fail
carvx image.dd --validate -o out/
carvx image.dd --drop-failed -o out/

# filesystem-metadata undelete (recovers names, paths, timestamps):
carvx image.dd --ntfs  -o out/    # NTFS  (Windows)
carvx image.dd --ext4  -o out/    # ext2/3/4 (Linux)
carvx image.dd --fat   -o out/    # FAT12/16/32 + exFAT (SD/USB/cameras)

# whole disk: list partitions, then auto-detect FS + undelete each
carvx disk.dd --list-partitions
carvx disk.dd --auto -o out/

# list supported types
carvx --list-types
```

## Modes

**Carving** (default) — scans raw bytes for file signatures. Filesystem-agnostic,
recovers from unallocated space, but only contiguous files and no original names.
`--validate` additionally decodes each carve to confirm integrity and trim tails.

**Filesystem undelete** — parses filesystem metadata for deleted entries,
recovering **original filenames, directory paths, timestamps, and (where the
metadata survives) fragmented files**:

| flag     | filesystems            | fragmentation        | notes |
|----------|------------------------|----------------------|-------|
| `--ntfs` | NTFS                   | yes (MFT runlists)   | skips compressed/encrypted streams |
| `--ext4` | ext2 / ext3 / ext4     | yes (extents + indirect blocks) | names from dir-entry slack |
| `--fat`  | FAT12/16/32, exFAT     | first run only       | long names reconstructed from VFAT/exFAT entries |
| `--hfs`  | HFS+ / HFSX            | yes (extent records) | live files always; deleted only if catalog record survives the journal |
| `--apfs` | APFS                   | yes (file extents)   | copy-on-write scan recovers deleted files (name+size+data) from old node copies |

Each auto-locates its volume through the MBR/GPT/APM partition table, or takes
an explicit `--offset`. Best-effort recoveries (possibly reused clusters,
fragmented FAT files) are flagged low confidence.

> **Note on HFS+:** a clean unmount journals deleted catalog records away, so
> deleted *names* often can't be recovered — but the file *data* still is, via
> carving mode. APFS, being copy-on-write, retains superseded records and
> recovers deleted files with names + exact content far more reliably.

**Whole disk** — `--list-partitions` prints the MBR/GPT/APM table with the
filesystem detected at each partition. `--auto` then runs the matching undelete
mode on every partition (carving any whose filesystem isn't recognized), writing
each to its own `part<N>_<fs>/` subdirectory.

## Options

| flag             | default        | effect                                          |
|------------------|----------------|-------------------------------------------------|
| `-o, --output`   | `./carved`     | output directory                                |
| `-t, --types`    | all            | comma-separated type list (aliases ok: jpeg, docx, mov, ...) |
| `--offset`       | 0              | start offset into source (K/M/G suffixes)       |
| `--length`       | to end         | bytes to scan from offset                       |
| `--align N`      | 1              | accept headers only at N-byte alignment         |
| `--max-size`     | per-type       | global cap on carved file size                  |
| `--min-size`     | 0              | discard smaller carves                          |
| `--chunk`        | 32M            | scan chunk size                                 |
| `-j, --jobs N`   | 1              | parallel scan processes (0 = all cores)         |
| `--ntfs`         | off            | NTFS MFT undelete mode                           |
| `--ext4`         | off            | ext2/3/4 inode + dirent undelete mode            |
| `--fat`          | off            | FAT12/16/32 + exFAT undelete mode                |
| `--hfs`          | off            | HFS+/HFSX catalog undelete mode                  |
| `--apfs`         | off            | APFS copy-on-write recovery mode                 |
| `--auto`         | off            | detect partitions + FS, undelete each            |
| `--list-partitions` |             | print MBR/GPT/APM table and exit                 |
| `--grep PATTERN` |                | keyword/regex search (ASCII+UTF-16); repeatable  |
| `--sig-file FILE`|                | load user-defined signatures (JSON)              |
| `--timeline FILE`|                | write MACB timeline (.csv/.jsonl)                |
| `--html FILE`    |                | write HTML report + image gallery                |
| `--validate`     | off            | deep-decode carves; set verified/failed confidence |
| `--drop-failed`  | off            | with --validate, discard carves that fail decode |
| `--no-bifragment`| off            | disable bifragment gap reassembly                |
| `--no-skip-blank`| off            | scan all-zero (TRIM'd/sparse) regions too        |
| `--matcher`      | auto           | signature matcher backend (auto/regex/aho-corasick) |
| `--no-skip`      | off            | keep scanning inside carved files               |
| `--no-dedup`     | off            | keep hash-identical duplicate carves            |
| `--dry-run`      | off            | report findings, write nothing                  |
| `--report FILE`  | `<out>/manifest.json` | JSON manifest path                       |
| `--csv FILE`     |                | also write findings as CSV                       |
| `--bodyfile FILE`|                | also write Sleuth Kit bodyfile (for mactime)    |
| `--hash-source`  | off            | SHA-256 whole source into manifest (custody)    |
| `--machine`      | off            | JSON-lines events on stdout                      |
| `-q, --quiet`    | off            | suppress progress output                        |
| `--list-types`   |                | print signature table and exit                  |

## Supported types

| type   | files                          | end detection                              |
|--------|--------------------------------|--------------------------------------------|
| jpg    | JPEG                           | marker walk + entropy scan to EOI           |
| png    | PNG                            | chunk walk to IEND                          |
| gif    | GIF87a/89a                     | block walk to trailer                       |
| bmp    | BMP                            | header size field                           |
| tif    | TIFF                           | IFD + strip/tile extent walk                |
| pdf    | PDF                            | last `%%EOF` (bounded by next PDF header)   |
| zip    | ZIP, docx/xlsx/pptx, jar, apk, epub, odf | EOCD record, central-dir cross-check |
| gz     | gzip                           | zlib stream decode (multi-member)           |
| 7z     | 7-Zip                          | next-header offset in signature header      |
| rar    | RAR4/5                         | none — capped carve, unvalidated            |
| sqlite | SQLite 3                       | page_size × page_count                      |
| mp4    | MP4 / MOV                      | top-level box walk                          |
| riff   | WAV, AVI, WebP                 | RIFF size field                             |
| mp3    | MP3 (ID3v2-tagged)             | ID3 size + MPEG frame walk                  |
| exe    | PE (exe/dll)                   | section table + Authenticode cert           |
| elf    | ELF                            | section header table end                    |
| macho  | Mach-O thin + universal        | load command / fat arch extents             |
| ole    | OLE2/CFB (doc, xls, ppt, msi)  | FAT max-used-sector walk                    |
| mp4    | MP4/MOV/HEIC/AVIF/3GP/M4A/M4V   | ISO-BMFF box walk + brand-based extension   |
| mkv    | Matroska / WebM                | EBML element + Segment size                 |
| ogg    | OGG (Vorbis/Opus/Theora)       | page walk to end-of-stream                  |
| flac   | FLAC                           | metadata blocks (frames best-effort)        |
| psd    | Photoshop                      | section walk (image data best-effort)       |
| ico    | ICO / CUR                      | directory entry table extent                |
| evtx   | Windows event log              | header chunk count                          |
| hive   | Windows registry (regf)        | base block + hbins size                     |
| plist  | Apple binary plist             | trailer offset-table identity               |

Every carve gets a SHA-256 and lands in `<out>/<ext>/f_<offset>.<ext>`.
A JSON manifest (`<out>/manifest.json`) records offset, size, hash, and
whether the structure parsed cleanly (`validated`) or the size is a
best-effort fallback.

## Filesystem & OS support

Carving is filesystem-agnostic: it scans raw bytes, so NTFS, ext2/3/4, FAT,
exFAT, APFS, XFS, btrfs, corrupted or unknown filesystems all work the same.
Runs on Linux, macOS, and Windows (raw device access uses sector-aligned
reads and IOCTL size detection automatically).

Inherent carving limits (same for PhotoRec):

- Only **contiguous** files recover intact — fragmented files yield the first
  fragment plus junk.
- NTFS-compressed or EFS-encrypted files are not in raw format on disk.
- Full-disk encryption (BitLocker/LUKS/FileVault): carve the **unlocked**
  device, not the raw one.
- TRIM'd SSD blocks read back as zeros — unrecoverable by any tool.
- No filenames/timestamps — that requires filesystem metadata recovery
  (Sleuth Kit `fls`/`icat` territory), not carving.

## Notes

- By default carvx skips over validated carves (PhotoRec behavior). Use
  `--no-skip` to also find files embedded inside other files.
- Unvalidated carves (rar, legacy sqlite, gz at window edge) may have junk
  appended at the tail — the real data is at the front.
- Throughput is roughly 150–250 MiB/s single-threaded; mostly bounded by
  the regex scan and source read speed.
- Operate on a read-only image (`dd`/`ddrescue` copy) of evidence, never on
  the original — standard forensic practice.

## Output

Each carve lands in `<out>/<ext>/f_<offset>.<ext>` (carving) or
`<out>/ntfs/<recovered/path>` (NTFS), with a SHA-256. The JSON manifest
(`<out>/manifest.json`) records, per file: offset/MFT number, size, hash,
`validated`/`confidence`, `duplicate_of`, and (NTFS) original name + timestamps.
Plus scan metadata: tool version, source path/size, start/finish time, options,
optional whole-source hash. CSV and Sleuth Kit bodyfile exports are optional.

## Tests

```sh
pip install pytest
pytest tests/                     # 150+ tests

# or the standalone integration check (no pytest needed):
python3 tests/make_test_image.py
```

The suite builds synthetic images (one per supported type, a synthetic NTFS
volume, and **real ext4/FAT32/exFAT/HFS+/APFS images** via the OS formatters
when available) with deleted + fragmented files, and verifies every recovery
hash-matches the original. Handler tests also feed truncated, corrupted, and
pure-noise input to confirm no crashes and no false-positive validated carves.
Disk-image readers are checked against `qemu-img`-produced QCOW2/VMDK. Tests
that need an unavailable tool skip cleanly rather than fail.
