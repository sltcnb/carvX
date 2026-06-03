"""carvx command-line interface."""

import argparse
import csv
import datetime
import hashlib
import json
import os
import sys
from collections import Counter

from . import __version__
from .carver import Carver, Options, emit, run_parallel
from .signatures import SIGNATURES, resolve_types


def parse_size(text: str) -> int:
    text = text.strip().upper()
    mult = 1
    for suffix, m in (("KB", 1 << 10), ("MB", 1 << 20), ("GB", 1 << 30),
                      ("TB", 1 << 40), ("K", 1 << 10), ("M", 1 << 20),
                      ("G", 1 << 30), ("T", 1 << 40), ("B", 1)):
        if text.endswith(suffix):
            mult = m
            text = text[:-len(suffix)]
            break
    return int(float(text) * mult)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="carvx",
        description="Signature-based file carver for disk images and block devices "
                    "(photorec-style). Recovers deleted files by scanning raw bytes; "
                    "no filesystem needed.")
    p.add_argument("source", nargs="?",
                   help="disk image file or block device (e.g. image.dd, /dev/disk4)")
    p.add_argument("-o", "--output", default="carved",
                   help="output directory (default: ./carved)")
    p.add_argument("-t", "--types",
                   help="comma-separated types to carve (default: all). See --list-types")
    p.add_argument("--list-types", action="store_true",
                   help="list supported file types and exit")
    p.add_argument("--sig-file", metavar="FILE",
                   help="load extra user-defined signatures from a JSON file "
                        "(merged with built-ins; see README)")
    p.add_argument("--only-custom", action="store_true",
                   help="carve only the --sig-file signatures (skip built-ins)")
    p.add_argument("--ntfs", action="store_true",
                   help="NTFS undelete mode: parse the MFT for deleted files "
                        "(recovers names, timestamps, fragmented files)")
    p.add_argument("--ext4", "--ext", action="store_true", dest="ext4",
                   help="ext2/3/4 undelete mode: parse inodes + directory entries "
                        "for deleted files (recovers names, timestamps, fragments)")
    p.add_argument("--fat", "--exfat", action="store_true", dest="fat",
                   help="FAT12/16/32 + exFAT undelete mode: recover deleted "
                        "directory entries (names, timestamps; contiguous files)")
    p.add_argument("--hfs", "--hfsplus", action="store_true", dest="hfs",
                   help="HFS+/HFSX undelete mode: catalog B-tree walk (live files "
                        "+ deleted records surviving in slack/journal)")
    p.add_argument("--apfs", action="store_true",
                   help="APFS recovery: copy-on-write FS-tree scan recovers "
                        "deleted files (names, sizes, extents) from old node copies")
    p.add_argument("--list-partitions", "--list-parts", action="store_true",
                   dest="list_partitions",
                   help="parse the MBR/GPT/APM partition table, print it, and exit")
    p.add_argument("--grep", action="append", metavar="PATTERN",
                   help="search the raw source for a keyword/regex (ASCII + "
                        "UTF-16LE); repeatable. Reports offsets + context")
    p.add_argument("-i", "--ignore-case", action="store_true",
                   help="case-insensitive --grep")
    p.add_argument("--regex", action="store_true",
                   help="treat --grep patterns as regular expressions")
    p.add_argument("--max-hits", default="0",
                   help="stop --grep after this many hits (0 = unlimited)")
    p.add_argument("--auto", action="store_true",
                   help="auto-detect partitions + filesystems and run the matching "
                        "undelete mode on each (falls back to carving where no FS "
                        "is recognized)")
    p.add_argument("-j", "--jobs", type=int, default=1, metavar="N",
                   help="parallel scan processes (0 = all cores; default 1)")
    p.add_argument("--offset", default="0",
                   help="start offset into source (supports K/M/G suffix)")
    p.add_argument("--length", default="0",
                   help="bytes to scan from offset (default: to end)")
    p.add_argument("--align", type=int, default=1, metavar="N",
                   help="only accept headers at N-byte alignment (e.g. 512 or 4096); "
                        "faster, fewer false positives, misses embedded files")
    p.add_argument("--max-size", default="0",
                   help="global cap on carved file size (overrides per-type default)")
    p.add_argument("--min-size", default="0",
                   help="discard carves smaller than this")
    p.add_argument("--chunk", default="32M",
                   help="scan chunk size (default: 32M)")
    p.add_argument("--no-skip", action="store_true",
                   help="keep scanning inside carved files (finds embedded files, slower, "
                        "more duplicates)")
    p.add_argument("--no-dedup", action="store_true",
                   help="keep hash-identical duplicate carves on disk")
    p.add_argument("--validate", action="store_true",
                   help="deep-decode carves (JPEG/PNG/ZIP/gzip/SQLite) to confirm "
                        "integrity; sets verified/failed confidence, trims tails")
    p.add_argument("--drop-failed", action="store_true",
                   help="with --validate, discard carves that fail to decode")
    p.add_argument("--no-bifragment", action="store_true",
                   help="with --validate, do not attempt bifragment gap "
                        "reassembly of JPEG/PNG that fail contiguous decode")
    p.add_argument("--no-skip-blank", action="store_true",
                   help="do not skip all-zero regions (scan TRIM'd/sparse space too)")
    p.add_argument("--matcher", choices=["auto", "regex", "aho-corasick"],
                   default="auto",
                   help="signature matcher backend (auto: Aho-Corasick if "
                        "pyahocorasick is installed and many patterns, else regex)")
    p.add_argument("--dry-run", action="store_true",
                   help="report findings without writing carved files")
    p.add_argument("--report", metavar="FILE",
                   help="write JSON manifest (default: <output>/manifest.json)")
    p.add_argument("--csv", metavar="FILE", help="also write findings as CSV")
    p.add_argument("--bodyfile", metavar="FILE",
                   help="also write Sleuth Kit body-file format (for mactime)")
    p.add_argument("--hash-source", action="store_true",
                   help="SHA-256 the whole source into the manifest (chain of custody; "
                        "slow on large sources)")
    p.add_argument("--timeline", metavar="FILE",
                   help="write a sorted timeline of recovered-file timestamps "
                        "(.csv or .jsonl) after the scan")
    p.add_argument("--html", metavar="FILE",
                   help="write an HTML report (summary + table + image gallery)")
    p.add_argument("--from-manifest", metavar="FILE",
                   help="skip scanning; build --timeline/--html from an existing "
                        "manifest.json")
    p.add_argument("--machine", action="store_true",
                   help="JSON-lines events on stdout (progress/carve/summary); "
                        "implies no human progress output")
    p.add_argument("-q", "--quiet", action="store_true", help="no progress output")
    p.add_argument("--version", action="version", version=f"carvx {__version__}")
    return p


def hash_source(path: str, quiet: bool) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(8 << 20)
            if not chunk:
                break
            h.update(chunk)
    if not quiet:
        print(f"source sha256: {h.hexdigest()}", file=sys.stderr)
    return h.hexdigest()


def write_outputs(args, opts, records, source_size, scan_meta):
    """Manifest JSON + optional CSV + optional bodyfile."""
    report_path = args.report or os.path.join(args.output, "manifest.json")
    rows = []
    for r in records:
        d = vars(r).copy()
        d["confidence"] = r.confidence
        rows.append(d)
    manifest = {
        "tool": f"carvx {__version__}",
        "source": os.path.abspath(args.source),
        "source_size": source_size,
        **scan_meta,
        "files": rows,
    }
    if records or not opts.dry_run:
        os.makedirs(os.path.dirname(report_path) or ".", exist_ok=True)
        with open(report_path, "w") as fh:
            json.dump(manifest, fh, indent=2)

    if args.csv:
        cols = ["type", "ext", "offset", "size", "sha256", "validated",
                "confidence", "duplicate_of", "path"]
        with open(args.csv, "w", newline="") as fh:
            wr = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
            wr.writeheader()
            wr.writerows(rows)

    if args.bodyfile:
        # body v3: MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime
        # carving has no timestamps; offset stands in for inode.
        with open(args.bodyfile, "w") as fh:
            for r in records:
                name = r.path or f"carved_{r.offset:#x}.{r.ext}"
                ts = vars(r).get("timestamps") or {}
                fh.write(f"{r.sha256}|{name}|{r.offset}|0|0|0|{r.size}"
                         f"|{ts.get('atime', 0)}|{ts.get('mtime', 0)}"
                         f"|{ts.get('ctime', 0)}|{ts.get('crtime', 0)}\n")
    return report_path


def run_auto(args) -> int:
    """Detect partitions + filesystems and dispatch the right undelete mode per
    partition, carving any partition whose filesystem is not recognized."""
    from .partition import parse, detect_fs, FS_TO_MODE
    from .images import open_source

    try:
        r = open_source(args.source)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    parts = parse(r)
    whole = []
    if not parts:                                  # whole-disk filesystem?
        fs = detect_fs(r, 0)
        whole = [(0, fs)]
    r.close()

    targets = whole or [(p.start, p.fstype) for p in parts]
    if not args.quiet:
        print(f"carvx auto: {len(targets)} target(s) on {args.source}",
              file=sys.stderr)

    base_out = args.output
    rc = 0
    for i, (offset, fstype) in enumerate(targets):
        mode = FS_TO_MODE.get(fstype)
        sub = os.path.join(base_out, f"part{i}_{fstype or 'raw'}")
        if not args.quiet:
            print(f"\n== partition {i} @ {offset:,} fs={fstype or 'unknown'} "
                  f"-> {mode or 'carve'}", file=sys.stderr)
        args.output = sub
        args.offset = str(offset)
        if mode == "ntfs":
            from .ntfs import run_ntfs
            rc |= run_ntfs(args)
        elif mode == "ext4":
            from .ext4 import run_ext4
            rc |= run_ext4(args)
        elif mode == "fat":
            from .fat import run_fat
            rc |= run_fat(args)
        elif mode == "hfs":
            from .hfsplus import run_hfs
            rc |= run_hfs(args)
        elif mode == "apfs":
            from .apfs import run_apfs
            rc |= run_apfs(args)
        else:
            # no recognized FS: fall back to signature carving of this region
            args.ntfs = args.ext4 = args.fat = args.hfs = args.apfs = False
            args.auto = False
            rc |= main_carve(args)
    args.output = base_out
    return rc


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_types:
        print(f"{'type':<8} {'magic(s)':<40} max size")
        for sig in SIGNATURES:
            magics = ", ".join(m.hex() for m in sig.magics)
            print(f"{sig.name:<8} {magics:<40} {sig.max_size >> 20:,} MiB")
        return 0

    if args.from_manifest:                       # no source needed
        from .report import run_report
        return run_report(args)

    if not args.source:
        print("error: source image or device required (or use --list-types)",
              file=sys.stderr)
        return 2

    # Stdin/pipe: handlers need random access, so spool to a temp file once and
    # let every downstream open_source() reopen that seekable path (parallel-safe).
    spool = None
    if args.source in ("-", "/dev/stdin"):
        import tempfile
        fd, spool = tempfile.mkstemp(prefix="carvx_stdin_")
        if not args.quiet:
            print("reading from stdin (spooling to temp file)...", file=sys.stderr)
        with os.fdopen(fd, "wb") as out:
            stream = sys.stdin.buffer
            while True:
                chunk = stream.read(8 << 20)
                if not chunk:
                    break
                out.write(chunk)
        args.source = spool
        args.hash_source = False                 # source path is the spool, not evidence

    try:
        rc = _dispatch(args)
    finally:
        if spool:
            try:
                os.unlink(spool)
            except OSError:
                pass

    # Post-scan derived artifacts from the manifest just written.
    if rc == 0 and (args.timeline or args.html) and not args.auto:
        from .report import run_report
        run_report(args)
    return rc


def _dispatch(args) -> int:
    if args.list_partitions:
        from .partition import parse, format_table
        from .images import open_source
        try:
            r = open_source(args.source)
        except (OSError, ValueError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        try:
            print(format_table(parse(r)))
        finally:
            r.close()
        return 0

    if args.from_manifest:
        from .report import run_report
        return run_report(args)

    if args.grep:
        from .grep import run_grep
        return run_grep(args)

    if args.auto:
        return run_auto(args)

    if args.ntfs:
        from .ntfs import run_ntfs
        return run_ntfs(args)

    if args.ext4:
        from .ext4 import run_ext4
        return run_ext4(args)

    if args.fat:
        from .fat import run_fat
        return run_fat(args)

    if args.hfs:
        from .hfsplus import run_hfs
        return run_hfs(args)

    if args.apfs:
        from .apfs import run_apfs
        return run_apfs(args)

    return main_carve(args)


def main_carve(args) -> int:
    """Signature-carving path (default mode, and the --auto fallback)."""
    try:
        sigs = resolve_types(args.types) if args.types else list(SIGNATURES)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if args.sig_file:
        from . import customsig
        try:
            custom = customsig.load(args.sig_file)
        except (OSError, ValueError, json.JSONDecodeError) as e:
            print(f"error: --sig-file: {e}", file=sys.stderr)
            return 2
        sigs = custom if args.only_custom else sigs + custom
        if not args.quiet:
            print(f"loaded {len(custom)} custom signature(s) from {args.sig_file}",
                  file=sys.stderr)

    jobs = args.jobs if args.jobs > 0 else os.cpu_count() or 1
    if args.sig_file and jobs > 1:
        # custom signatures are not importable in spawned workers
        if not args.quiet:
            print("note: --sig-file forces single-process scan", file=sys.stderr)
        jobs = 1

    opts = Options(
        out_dir=args.output,
        chunk_size=max(parse_size(args.chunk), 1 << 20),
        align=max(args.align, 1),
        skip_carved=not args.no_skip,
        min_size=parse_size(args.min_size),
        max_size=parse_size(args.max_size),
        start=parse_size(args.offset),
        length=parse_size(args.length),
        dry_run=args.dry_run,
        quiet=args.quiet or args.machine,
        machine=args.machine,
        dedup=not args.no_dedup,
        validate=args.validate or args.drop_failed,
        drop_failed=args.drop_failed,
        bifragment=not args.no_bifragment,
        skip_blank=not args.no_skip_blank,
        extra={"matcher": args.matcher},
    )

    try:
        carver = Carver(args.source, sigs, opts)
    except PermissionError:
        print(f"error: permission denied opening {args.source!r} "
              "(raw devices usually need sudo)", file=sys.stderr)
        return 1
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    source_size = carver.reader.size
    if not opts.quiet:
        kind = "device" if carver.reader.is_device else "image"
        print(f"carvx {__version__}: scanning {kind} {args.source} "
              f"({source_size / (1 << 20):,.0f} MiB), "
              f"{len(sigs)} signatures, {jobs} process(es)", file=sys.stderr)

    scan_meta = {
        "started": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "offset": opts.start, "length": opts.length,
        "types": [s.name for s in sigs], "align": opts.align, "jobs": jobs,
    }
    if args.hash_source and not carver.reader.is_device:
        scan_meta["source_sha256"] = hash_source(args.source, opts.quiet)
    elif args.hash_source:
        print("warning: --hash-source skipped for devices", file=sys.stderr)

    t0 = datetime.datetime.now(datetime.timezone.utc)
    interrupted = False
    try:
        if jobs > 1:
            carver.close()
            records, rejected = run_parallel(args.source, sigs, opts, jobs)
        else:
            opts.machine = args.machine
            records = carver.run()
            rejected = carver.rejected
            carver.close()
    except KeyboardInterrupt:
        print("\ninterrupted — partial results kept", file=sys.stderr)
        records, rejected = carver.records, carver.rejected
        carver.close()
        interrupted = True

    scan_meta["finished"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    scan_meta["duration_s"] = round(
        (datetime.datetime.now(datetime.timezone.utc) - t0).total_seconds(), 2)
    scan_meta["interrupted"] = interrupted

    report_path = write_outputs(args, opts, records, source_size, scan_meta)

    dupes = sum(1 for r in records if r.duplicate_of is not None)
    if args.machine:
        emit("summary", carved=len(records), duplicates=dupes,
             rejected=rejected, bytes=sum(r.size for r in records),
             manifest=report_path)
    elif not args.quiet:
        counts = Counter(r.ext for r in records)
        total = sum(r.size for r in records)
        extra = f", {dupes} duplicates" if dupes else ""
        print(f"\ncarved {len(records)} files, {total / (1 << 20):,.1f} MiB total "
              f"({rejected} candidates rejected{extra})", file=sys.stderr)
        if args.validate:
            conf = Counter(r.confidence for r in records)
            print("  confidence: " + ", ".join(f"{k}={v}" for k, v in conf.items()),
                  file=sys.stderr)
        skipped = getattr(carver, "skipped_blank", 0)
        if skipped:
            print(f"  skipped {skipped / (1 << 20):,.0f} MiB of blank space",
                  file=sys.stderr)
        for ext, n in counts.most_common():
            print(f"  {ext:<8} {n}", file=sys.stderr)
        if records:
            print(f"manifest: {report_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
