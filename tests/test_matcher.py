"""Signature matcher backend tests."""
from carvx.matcher import build, RegexMatcher


def test_regex_finditer_positions():
    m = build([b"PK\x03\x04", b"\xff\xd8\xff"], backend="regex")
    buf = b"....PK\x03\x04....\xff\xd8\xff.."
    hits = sorted(m.finditer(buf))
    assert hits == [(4, b"PK\x03\x04"), (12, b"\xff\xd8\xff")]


def test_auto_defaults_to_regex_without_lib():
    m = build([b"AB", b"CD"], backend="auto")
    # without pyahocorasick installed, auto -> regex
    assert m.backend in ("regex", "aho-corasick")
    if m.backend == "regex":
        assert isinstance(m, RegexMatcher)


def test_longest_magic_preferred():
    m = build([b"RIFF", b"RIFFWAVE"], backend="regex")
    hits = list(m.finditer(b"xxRIFFWAVExx"))
    assert (2, b"RIFFWAVE") in hits
