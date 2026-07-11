"""Scan engine: stream the source, match signatures, carve hits to disk."""

import hashlib
import json
import os
import sys
import time
from dataclasses import dataclass, field

from .reader import Window
from .images import open_source
from .signatures import Signature


@dataclass
class CarveRecord:
    type: str
    ext: str
    offset: int
    size: int
    sha256: str
    validated: bool
    path: str
    duplicate_of: int | None = None     # offset of identical earlier carve
    verified: bool | None = None        # deep-decode result (None = not run/NA)
    fragments: list | None = None       # bifragment layout if reassembled

    @property
    def confidence(self) -> str:
        if self.verified is True:
            return "verified"
        if self.verified is False:
            return "failed"
        return "high" if self.validated else "low"


@dataclass
class Options:
    out_dir: str = "carved"
    chunk_size: int = 32 << 20
    align: int = 1
    skip_carved: bool = True        # don't rescan inside validated carves
    min_size: int = 0
    max_size: int = 0               # 0 = per-type default
    start: int = 0
    length: int = 0                 # 0 = to end
    window_end: int = 0             # carve windows may extend to here (0 = source end);
                                    # lets parallel range workers carve past their range
    dry_run: bool = False
    quiet: bool = False
    machine: bool = False           # emit JSON-lines events on stdout
    dedup: bool = True
    validate: bool = False          # deep-decode carves to confirm integrity
    drop_failed: bool = False       # discard carves whose deep validation fails
    bifragment: bool = True         # try bifragment recovery on failed decode
    skip_blank: bool = True         # skip all-zero scan chunks
    extra: dict = field(default_factory=dict)


def emit(event: str, **payload):
    """JSON-lines machine event on stdout."""
    sys.stdout.write(json.dumps({"event": event, **payload}) + "\n")
    sys.stdout.flush()


_BIFRAG_EXTS = {"png", "jpg", "jpeg"}     # types bifragment reassembly supports


class Carver:
    VALIDATE_CAP = 512 << 20        # don't slurp files larger than this to validate

    def __init__(self, source: str, sigs: list[Signature], opts: Options):
        self.reader = open_source(source)
        self.sigs = sigs
        self.opts = opts
        self.records: list[CarveRecord] = []
        self.rejected = 0
        self.skipped_blank = 0
        # Map each magic to its signature; longest magics first so the regex
        # alternation prefers the most specific match.
        self.by_magic = {}
        for sig in sigs:
            for magic in sig.magics:
                self.by_magic.setdefault(magic, []).append(sig)
        from .matcher import build as build_matcher
        self.matcher = build_matcher(self.by_magic.keys(),
                                     backend=opts.extra.get("matcher", "auto"))
        self._last_progress = 0.0

    # ------------------------------------------------------------------

    def run(self) -> list[CarveRecord]:
        o = self.opts
        scan_end = self.reader.size
        if o.length:
            scan_end = min(scan_end, o.start + o.length)
        self.window_end = o.window_end or scan_end
        pos = o.start
        next_allowed = o.start
        overlap = max(len(m) for m in self.by_magic) - 1 + 4  # +4 for ftyp lookback
        t0 = time.monotonic()

        while pos < scan_end:
            want = min(o.chunk_size + overlap, scan_end - pos + overlap)
            buf = self.reader.pread(pos, want)
            if not buf:
                break
            limit = min(len(buf), o.chunk_size)   # hits past limit handled next chunk
            # Blank-block skip: an all-zero chunk (TRIM'd/sparse) holds no headers.
            # strip() is a C-speed scan that stops at the first non-zero byte.
            if o.skip_blank and not buf[:limit].strip(b"\x00"):
                self.skipped_blank += limit
                self._progress(pos + limit - o.start, scan_end - o.start, t0)
                pos += limit
                continue
            for i, magic in self.matcher.finditer(buf):
                if i >= limit:
                    continue
                abs_magic = pos + i
                for sig in self.by_magic[magic]:
                    start = abs_magic - sig.header_offset
                    if start < o.start or abs_magic >= scan_end:
                        continue
                    if start < next_allowed and o.skip_carved:
                        continue
                    if o.align > 1 and start % o.align:
                        continue
                    if sig.precheck and not sig.precheck(buf, i):
                        continue
                    rec = self._try_carve(sig, start)
                    if rec is not None:
                        self.records.append(rec)
                        if o.skip_carved and rec.validated:
                            next_allowed = rec.offset + rec.size
                        break
            self._progress(pos + limit - o.start, scan_end - o.start, t0)
            pos += limit
        self._progress(scan_end - o.start, scan_end - o.start, t0, final=True)
        if o.dedup:
            dedupe(self.records, dry_run=o.dry_run)
        return self.records

    # ------------------------------------------------------------------

    def _try_carve(self, sig: Signature, start: int):
        o = self.opts
        cap = sig.max_size
        if o.max_size:
            cap = min(cap, o.max_size)
        cap = min(cap, self.window_end - start)
        if cap <= 0:
            return None
        window = Window(self.reader, start, cap)
        try:
            carve = sig.handler(window)
        except Exception:
            carve = None
        # Handler rejected (e.g. fragmentation broke the structure walk): try
        # bifragment reassembly directly from the header before giving up.
        if carve is None or carve.size < max(o.min_size, 1):
            if o.validate and o.bifragment and sig.name in _BIFRAG_EXTS:
                blob, fragments = self._try_bifragment(sig.name, start, cap)
                if blob is not None and len(blob) >= max(o.min_size, 1):
                    return self._emit_blob(sig, start, sig.name, blob, fragments)
            self.rejected += 1
            return None

        size = carve.size
        verified = None
        frag_blob = None        # in-memory reassembled bytes (bifragment)
        fragments = None
        # Deep validation: decode the bytes in memory (bounded), maybe tighten
        # the size, optionally drop on failure.
        if o.validate and size <= self.VALIDATE_CAP:
            from . import validate as _v
            blob = self.reader.pread(start, size)
            verified, tight = _v.validate(carve.ext, blob)
            if tight and tight <= size:
                size = tight
            # Contiguous decode failed: try bifragment gap reassembly.
            if verified is False and o.bifragment:
                frag_blob, fragments = self._try_bifragment(carve.ext, start, cap)
                if frag_blob is not None:
                    verified = True
                    size = len(frag_blob)
            if verified is False and o.drop_failed and frag_blob is None:
                self.rejected += 1
                return None

        path = ""
        digest = hashlib.sha256()
        if frag_blob is not None:
            digest.update(frag_blob)
            if not o.dry_run:
                sub = os.path.join(o.out_dir, carve.ext)
                os.makedirs(sub, exist_ok=True)
                path = os.path.join(sub, f"f_{start:012x}.{carve.ext}")
                with open(path, "wb") as fh:
                    fh.write(frag_blob)
        elif o.dry_run:
            self._hash_region(start, size, digest)
        else:
            sub = os.path.join(o.out_dir, carve.ext)
            os.makedirs(sub, exist_ok=True)
            path = os.path.join(sub, f"f_{start:012x}.{carve.ext}")
            with open(path, "wb") as fh:
                remaining, off = size, start
                while remaining:
                    chunk = self.reader.pread(off, min(remaining, 4 << 20))
                    if not chunk:
                        break
                    fh.write(chunk)
                    digest.update(chunk)
                    off += len(chunk)
                    remaining -= len(chunk)
        rec = CarveRecord(sig.name, carve.ext, start, size,
                          digest.hexdigest(), carve.validated, path,
                          verified=verified, fragments=fragments)
        if o.machine:
            emit("carve", type=rec.type, ext=rec.ext, offset=rec.offset,
                 size=rec.size, sha256=rec.sha256, validated=rec.validated,
                 verified=rec.verified, confidence=rec.confidence, path=rec.path)
        elif not o.quiet:
            flag = {"verified": "  (verified)", "failed": "  (FAILED decode)",
                    "low": "  (unvalidated)"}.get(rec.confidence, "")
            sys.stderr.write(f"\r\x1b[K[+] {carve.ext:<6} @ {start:#014x}  "
                             f"{carve.size:>12,} B{flag}\n")
        return rec

    def _emit_blob(self, sig, start, ext, blob, fragments):
        """Write an in-memory reassembled blob as a verified carve record."""
        o = self.opts
        digest = hashlib.sha256(blob)
        path = ""
        if not o.dry_run:
            sub = os.path.join(o.out_dir, ext)
            os.makedirs(sub, exist_ok=True)
            path = os.path.join(sub, f"f_{start:012x}.{ext}")
            with open(path, "wb") as fh:
                fh.write(blob)
        rec = CarveRecord(sig.name, ext, start, len(blob), digest.hexdigest(),
                          True, path, verified=True, fragments=fragments)
        if o.machine:
            emit("carve", type=rec.type, ext=rec.ext, offset=rec.offset,
                 size=rec.size, sha256=rec.sha256, validated=rec.validated,
                 verified=rec.verified, confidence=rec.confidence,
                 fragments=fragments, path=rec.path)
        elif not o.quiet:
            sys.stderr.write(f"\r\x1b[K[+] {ext:<6} @ {start:#014x}  "
                             f"{rec.size:>12,} B  (bifragment)\n")
        return rec

    def _try_bifragment(self, ext, start, cap):
        from .fragment import bifragment_carve
        window = Window(self.reader, start, cap)
        result = bifragment_carve(window, ext)
        if result is None:
            return None, None
        blob, layout = result
        frags = [{"offset": start, "length": layout.frag1_len},
                 {"offset": start + layout.frag1_len + layout.gap,
                  "length": layout.frag2_len}]
        return blob, frags

    def _hash_region(self, start: int, size: int, digest):
        remaining, off = size, start
        while remaining:
            chunk = self.reader.pread(off, min(remaining, 4 << 20))
            if not chunk:
                break
            digest.update(chunk)
            off += len(chunk)
            remaining -= len(chunk)

    # ------------------------------------------------------------------

    def _progress(self, done: int, total: int, t0: float, final: bool = False):
        o = self.opts
        if total <= 0:
            return
        done = min(done, total)
        now = time.monotonic()
        if not final and now - self._last_progress < 0.5:
            return
        self._last_progress = now
        elapsed = max(now - t0, 1e-6)
        rate = done / elapsed
        eta = (total - done) / rate if rate > 0 else 0
        if o.machine:
            emit("progress", done=done, total=total,
                 rate_mibs=round(rate / (1 << 20), 1), eta_s=round(eta),
                 carved=len(self.records))
            return
        if o.quiet:
            return
        sys.stderr.write(f"\r\x1b[K{done * 100 // total:3d}%  "
                         f"{done / (1 << 20):,.0f}/{total / (1 << 20):,.0f} MiB  "
                         f"{rate / (1 << 20):,.0f} MiB/s  "
                         f"ETA {_fmt_eta(eta)}  {len(self.records)} carved")
        if final:
            sys.stderr.write("\n")
        sys.stderr.flush()

    def close(self):
        self.reader.close()


def _fmt_eta(seconds: float) -> str:
    s = int(seconds)
    if s >= 3600:
        return f"{s // 3600}h{s % 3600 // 60:02d}m"
    if s >= 60:
        return f"{s // 60}m{s % 60:02d}s"
    return f"{s}s"


# ----------------------------------------------------------------------
# Post-processing shared by serial and parallel paths

def dedupe(records: list[CarveRecord], dry_run: bool = False):
    """Keep one copy per sha256; later duplicates lose their file on disk."""
    first_by_hash: dict[str, CarveRecord] = {}
    for rec in sorted(records, key=lambda r: r.offset):
        orig = first_by_hash.get(rec.sha256)
        if orig is None:
            first_by_hash[rec.sha256] = rec
            continue
        rec.duplicate_of = orig.offset
        if rec.path and not dry_run:
            try:
                os.unlink(rec.path)
            except OSError:
                pass
        rec.path = ""


def containment_filter(records: list[CarveRecord]) -> list[CarveRecord]:
    """Drop carves fully inside an earlier validated carve (parallel ranges
    can't see each other's skip-ahead state)."""
    out: list[CarveRecord] = []
    covered_end = -1
    for rec in sorted(records, key=lambda r: (r.offset, -r.size)):
        if rec.offset + rec.size <= covered_end:
            if rec.path:
                try:
                    os.unlink(rec.path)
                except OSError:
                    pass
            continue
        out.append(rec)
        if rec.validated:
            covered_end = max(covered_end, rec.offset + rec.size)
    return out


# ----------------------------------------------------------------------
# Parallel scan

def _scan_range(payload):
    """Worker: scan [start, start+length) of source; carve windows may extend
    to window_end. Runs in a separate process (spawn-safe)."""
    source, sig_names, opts_dict, start, length, window_end = payload
    from .signatures import BY_NAME
    sigs = [BY_NAME[n] for n in sig_names]
    opts = Options(**opts_dict)
    opts.start = start
    opts.length = length
    opts.window_end = window_end
    opts.quiet = True
    opts.machine = False
    opts.dedup = False                 # dedup once, after the merge
    carver = Carver(source, sigs, opts)
    try:
        recs = carver.run()
        return recs, carver.rejected
    finally:
        carver.close()


def run_parallel(source: str, sigs: list[Signature], opts: Options, jobs: int):
    """Split the scan range across processes; merge + filter records.

    Returns (records, rejected_count).
    """
    import multiprocessing as mp

    reader = open_source(source)
    scan_end = reader.size
    if opts.length:
        scan_end = min(scan_end, opts.start + opts.length)
    total = scan_end - opts.start
    reader.close()

    # ~4 ranges per worker for load balancing, aligned to chunk size.
    n_ranges = max(jobs * 4, 1)
    span = max(total // n_ranges, opts.chunk_size)
    span += -span % max(opts.align, 1)
    ranges = []
    pos = opts.start
    while pos < scan_end:
        ranges.append((pos, min(span, scan_end - pos)))
        pos += span

    opts_dict = {k: v for k, v in vars(opts).items()
                 if k not in ("start", "length", "window_end", "extra")}
    opts_dict["extra"] = dict(opts.extra)
    payloads = [(source, [s.name for s in sigs], opts_dict, r0, rlen, scan_end)
                for r0, rlen in ranges]

    records: list[CarveRecord] = []
    rejected = 0
    done_bytes = 0
    t0 = time.monotonic()
    ctx = mp.get_context("spawn")
    with ctx.Pool(jobs) as pool:
        for (recs, rej), (r0, rlen) in zip(
                pool.imap(_scan_range, payloads), ranges):
            records.extend(recs)
            rejected += rej
            done_bytes += rlen
            elapsed = max(time.monotonic() - t0, 1e-6)
            rate = done_bytes / elapsed
            eta = (total - done_bytes) / rate if rate > 0 else 0
            if opts.machine:
                emit("progress", done=done_bytes, total=total,
                     rate_mibs=round(rate / (1 << 20), 1), eta_s=round(eta),
                     carved=len(records))
                for rec in recs:
                    emit("carve", type=rec.type, ext=rec.ext, offset=rec.offset,
                         size=rec.size, sha256=rec.sha256,
                         validated=rec.validated, path=rec.path)
            elif not opts.quiet:
                for rec in recs:
                    flag = "" if rec.validated else "  (unvalidated)"
                    sys.stderr.write(f"\r\x1b[K[+] {rec.ext:<6} @ {rec.offset:#014x}  "
                                     f"{rec.size:>12,} B{flag}\n")
                sys.stderr.write(f"\r\x1b[K{done_bytes * 100 // total:3d}%  "
                                 f"{done_bytes / (1 << 20):,.0f}/{total / (1 << 20):,.0f} MiB  "
                                 f"{rate / (1 << 20):,.0f} MiB/s  ETA {_fmt_eta(eta)}  "
                                 f"{len(records)} carved")
                sys.stderr.flush()
    if not opts.quiet and not opts.machine:
        sys.stderr.write("\n")
    records = containment_filter(records)
    if opts.dedup:
        dedupe(records, dry_run=opts.dry_run)
    return records, rejected
