"""Bifragment gap carving for JPEG/PNG.

When a file carves but fails to decode as a single contiguous run, it is often
split into two fragments separated by a gap (other file's clusters). Following
Garfinkel's bifragment gap carving: assume two fragments and a single
cluster-aligned gap, then search candidate (fragment-1 end, gap length) pairs,
assembling and validating each by decoding, until one passes.

Bounded by cluster alignment and caps on gap size and attempt count so it stays
practical. Returns (assembled_bytes, layout) or None.
"""

from dataclasses import dataclass

from .reader import Window
from . import validate as _v


@dataclass
class FragmentLayout:
    frag1_len: int          # bytes from base that belong to fragment 1
    gap: int                # bytes skipped
    frag2_len: int          # bytes of fragment 2 appended
    total: int              # frag1_len + gap + frag2_len (span on disk)


# Footer markers per type; carve must end right after the footer.
_FOOTERS = {
    "jpg": b"\xff\xd9",
    "jpeg": b"\xff\xd9",
    "png": b"IEND\xaeB`\x82",          # IEND + its fixed CRC
}


def bifragment_carve(window: Window, ext: str, *, block: int = 512,
                     max_gap: int = 8 << 20, max_attempts: int = 4000):
    """Attempt 2-fragment recovery within `window` (based at the header).

    Strategy: the footer ends fragment 2. For each cluster-aligned fragment-1
    length g1 and each cluster-aligned gap, assemble [0:g1] + [g1+gap:footer_end]
    and decode-validate. Accept the first assembly that validates.
    """
    ext = ext.lower()
    footer = _FOOTERS.get(ext)
    validator = _v.VALIDATORS.get("jpg" if ext == "jpeg" else ext)
    if footer is None or validator is None:
        return None

    limit = window.limit
    # All footer occurrences are candidate fragment-2 ends.
    footer_ends = _find_all(window, footer, limit, cap=64)
    if not footer_ends:
        return None

    attempts = 0
    # Fragment 1 must contain at least the header; step by block size.
    for footer_pos in footer_ends:
        end = footer_pos + len(footer)
        # g1: end of fragment 1, cluster-aligned, strictly inside (block, end-block)
        g1 = block
        while g1 < end:
            max_g2_start = end                       # fragment 2 starts at g1+gap
            gap = block
            while g1 + gap < end and gap <= max_gap:
                frag2_start = g1 + gap
                frag2_len = end - frag2_start
                if frag2_len <= 0:
                    break
                blob = window.read(0, g1) + window.read(frag2_start, frag2_len)
                ok, _ = _safe_validate(validator, blob)
                attempts += 1
                if ok:
                    return blob, FragmentLayout(g1, gap, frag2_len, end)
                if attempts >= max_attempts:
                    return None
                gap += block
            g1 += block
    return None


def _safe_validate(validator, blob):
    try:
        res = validator(blob)
    except Exception:
        return (None, None)
    if res is None:
        return (None, None)
    return res


def _find_all(window: Window, needle: bytes, end: int, cap: int):
    out = []
    pos = 0
    while len(out) < cap:
        idx = window.find(needle, pos, end)
        if idx < 0:
            break
        out.append(idx)
        pos = idx + 1
    return out
