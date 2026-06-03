"""User-defined signatures loaded from a JSON config.

Schema (a list, or {"signatures": [...]}):
  {
    "name": "myfmt",            # type key
    "ext": "mft",              # output extension (default: name)
    "magic": "DEADBEEF",       # hex, or list of hex strings
    "header_offset": 0,         # bytes from file start to the magic (default 0)
    "footer": "0a2525454f46",  # optional hex end marker; carve ends after it
    "max_size": "16M",          # cap (default 64M); K/M/G suffixes ok
    "footer_optional": false    # if true and footer absent, carve to max_size
  }

A footer-based handler is generated automatically: it finds the first footer
after the header and carves through it (validated). Without a footer, it carves
the full capped window (unvalidated).
"""

import json

from .handlers import Carve
from .reader import Window
from .signatures import Signature

_MULT = {"K": 1 << 10, "M": 1 << 20, "G": 1 << 30, "T": 1 << 40, "B": 1}


def _size(v) -> int:
    if isinstance(v, int):
        return v
    s = str(v).strip().upper()
    for suf, m in _MULT.items():
        if s.endswith(suf):
            return int(float(s[:-1]) * m)
    return int(s)


def _hex(s: str) -> bytes:
    return bytes.fromhex(s.replace(" ", "").replace("0x", ""))


def _make_handler(ext, header_offset, footer, footer_optional):
    def handler(w: Window):
        if footer:
            idx = w.find(footer, header_offset + 1)
            if idx >= 0:
                return Carve(idx + len(footer), ext, True)
            if not footer_optional:
                return None
        return Carve(w.limit, ext, False)
    return handler


def load(path: str) -> list[Signature]:
    with open(path) as fh:
        doc = json.load(fh)
    if isinstance(doc, dict):
        doc = doc.get("signatures", [])
    sigs = []
    for i, entry in enumerate(doc):
        try:
            name = entry["name"]
            magic_field = entry["magic"]
        except (KeyError, TypeError):
            raise ValueError(f"signature #{i}: 'name' and 'magic' are required")
        magics = magic_field if isinstance(magic_field, list) else [magic_field]
        magics = tuple(_hex(m) for m in magics)
        if any(len(m) == 0 for m in magics):
            raise ValueError(f"signature {name!r}: empty magic")
        ext = entry.get("ext", name)
        header_offset = int(entry.get("header_offset", 0))
        footer = _hex(entry["footer"]) if entry.get("footer") else None
        max_size = _size(entry.get("max_size", 64 << 20))
        handler = _make_handler(ext, header_offset, footer,
                                bool(entry.get("footer_optional", False)))
        sigs.append(Signature(name, magics, header_offset, handler, max_size))
    return sigs
