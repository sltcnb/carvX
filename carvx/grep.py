"""Keyword/regex search across the raw source.

Scans for one or more patterns in both ASCII/Latin-1 and UTF-16LE encodings,
reporting each hit's byte offset with surrounding context. Optionally carves
the file that encloses each hit (by walking back to a known signature).
"""

import re
import sys
from dataclasses import dataclass


@dataclass
class Hit:
    offset: int
    pattern: str
    encoding: str        # "ascii" | "utf-16le"
    context: str


def _compile(patterns, ignore_case, regex):
    flags = re.IGNORECASE if ignore_case else 0
    compiled = []
    for p in patterns:
        pat = p if regex else re.escape(p)
        ascii_re = re.compile(pat.encode("latin-1", "ignore"), flags)
        # UTF-16LE: literal patterns are matched by their UTF-16LE byte form.
        if not regex:
            u16 = re.compile(re.escape(p.encode("utf-16-le")), flags)
        else:
            u16 = None
        compiled.append((p, ascii_re, u16))
    return compiled


def search(reader, patterns, start=0, length=0, ignore_case=False,
           regex=False, context=32, on_hit=None, max_hits=0):
    """Yield Hit objects (also calls on_hit if given)."""
    end = reader.size
    if length:
        end = min(end, start + length)
    compiled = _compile(patterns, ignore_case, regex)
    chunk = 8 << 20
    overlap = 256
    hits = []
    pos = start
    while pos < end:
        buf = reader.pread(pos, min(chunk + overlap, end - pos + overlap))
        if not buf:
            break
        limit = min(len(buf), chunk)
        for pname, ascii_re, u16 in compiled:
            for m in ascii_re.finditer(buf):
                if m.start() >= limit:
                    break
                h = _make_hit(buf, m.start(), m.end(), pos, pname, "ascii", context)
                hits.append(h)
                if on_hit:
                    on_hit(h)
                if max_hits and len(hits) >= max_hits:
                    return hits
            if u16 is not None:
                for m in u16.finditer(buf):
                    if m.start() >= limit:
                        break
                    h = _make_hit(buf, m.start(), m.end(), pos, pname,
                                  "utf-16le", context)
                    hits.append(h)
                    if on_hit:
                        on_hit(h)
                    if max_hits and len(hits) >= max_hits:
                        return hits
        pos += limit
    return hits


def _make_hit(buf, s, e, base, pname, enc, ctx):
    lo = max(0, s - ctx)
    hi = min(len(buf), e + ctx)
    snippet = buf[lo:hi]
    if enc == "utf-16le":
        text = snippet.decode("utf-16-le", "replace")
    else:
        text = snippet.decode("latin-1", "replace")
    text = "".join(c if 0x20 <= ord(c) < 0x7F else "." for c in text)
    return Hit(base + s, pname, enc, text)


def run_grep(args) -> int:
    from .images import open_source
    from .cli import parse_size
    import json

    patterns = [p for p in (args.grep or []) if p]
    if not patterns:
        print("error: --grep requires at least one pattern", file=sys.stderr)
        return 2
    try:
        reader = open_source(args.source)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    count = 0

    def on_hit(h):
        nonlocal count
        count += 1
        if args.machine:
            sys.stdout.write(json.dumps({
                "event": "hit", "offset": h.offset, "pattern": h.pattern,
                "encoding": h.encoding, "context": h.context}) + "\n")
        else:
            print(f"{h.offset:#014x}  {h.encoding:<9} {h.pattern!r}: {h.context}")

    try:
        search(reader, patterns, start=parse_size(args.offset),
               length=parse_size(args.length), ignore_case=args.ignore_case,
               regex=args.regex, on_hit=on_hit,
               max_hits=int(args.max_hits) if args.max_hits else 0)
    finally:
        reader.close()
    if not args.quiet and not args.machine:
        print(f"\n{count} hit(s)", file=sys.stderr)
    return 0
