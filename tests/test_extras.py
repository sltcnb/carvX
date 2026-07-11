"""Tests for grep, custom signatures, timeline + HTML report."""

import json

import pytest

from carvx import customsig, grep, report
from carvx.carver import Carver, Options
from carvx.reader import Reader


# ---------------------------------------------------------------- grep

@pytest.fixture
def grep_img(tmp_path):
    p = tmp_path / "g.img"
    p.write_bytes(b"\x00" * 100 + b"TOP SECRET token=abc" + b"\x00" * 40
                  + "héllo".encode("utf-16-le") + b"\x00" * 40
                  + b"more SECRET data")
    return str(p)


def test_grep_ascii(grep_img):
    with Reader(grep_img) as r:
        hits = grep.search(r, ["SECRET"])
    assert len(hits) == 2
    assert all(h.encoding == "ascii" for h in hits)
    assert hits[0].offset < hits[1].offset


def test_grep_utf16(grep_img):
    with Reader(grep_img) as r:
        hits = grep.search(r, ["héllo"])
    assert len(hits) == 1 and hits[0].encoding == "utf-16le"


def test_grep_regex_and_max_hits(grep_img):
    with Reader(grep_img) as r:
        hits = grep.search(r, [r"SECRET|token"], regex=True)
        assert len(hits) >= 2
        capped = grep.search(r, ["SECRET"], max_hits=1)
    assert len(capped) == 1


def test_grep_ignore_case(grep_img):
    with Reader(grep_img) as r:
        assert grep.search(r, ["secret"]) == []
        assert len(grep.search(r, ["secret"], ignore_case=True)) == 2


# ---------------------------------------------------------------- custom sigs

def test_customsig_footer(tmp_path):
    cfg = tmp_path / "sig.json"
    cfg.write_text(json.dumps([{
        "name": "foofmt", "ext": "foo", "magic": "464F4F21",
        "footer": "454E4421", "max_size": "1M"}]))
    sigs = customsig.load(str(cfg))
    assert len(sigs) == 1 and sigs[0].name == "foofmt"

    img = tmp_path / "c.img"
    payload = b"FOO!hello world payloadEND!"
    img.write_bytes(b"\x00" * 64 + payload + b"\x00" * 64)
    c = Carver(str(img), sigs, Options(out_dir=str(tmp_path / "o"), quiet=True))
    try:
        recs = c.run()
    finally:
        c.close()
    assert len(recs) == 1
    assert recs[0].size == len(payload)
    assert open(recs[0].path, "rb").read() == payload


def test_customsig_multi_magic_and_no_footer(tmp_path):
    cfg = tmp_path / "sig.json"
    cfg.write_text(json.dumps({"signatures": [{
        "name": "multi", "magic": ["AABB", "CCDD"], "max_size": "4K"}]}))
    sigs = customsig.load(str(cfg))
    assert sigs[0].magics == (b"\xaa\xbb", b"\xcc\xdd")
    # no footer -> best-effort carve to window cap (unvalidated)
    from carvx.reader import Window

    class BR:
        def __init__(self, d): self.data, self.size = d, len(d)
        def pread(self, o, n): return self.data[o:o + n]
    w = Window(BR(b"\xaa\xbb" + b"x" * 500), 0, 502)
    carve = sigs[0].handler(w)
    assert carve is not None and not carve.validated


def test_customsig_invalid_raises(tmp_path):
    cfg = tmp_path / "bad.json"
    cfg.write_text(json.dumps([{"ext": "x"}]))     # missing name/magic
    with pytest.raises(ValueError):
        customsig.load(str(cfg))


# ---------------------------------------------------------------- report

def _manifest_with_times():
    return {
        "tool": "carvx test", "source": "/dev/null", "source_size": 1000,
        "files": [
            {"ext": "txt", "offset": 5, "size": 100, "sha256": "a" * 64,
             "validated": True, "name": "a.txt", "deleted": True,
             "timestamps": {"mtime": 1700000000, "atime": 1700000500,
                            "ctime": 0, "crtime": 0}},
            {"ext": "jpg", "offset": 9, "size": 200, "sha256": "b" * 64,
             "validated": True, "name": "pic.jpg", "deleted": True,
             "path": "", "timestamps": {"mtime": 1690000000}},
        ],
    }


def test_timeline_events_sorted():
    events = report.build_timeline(_manifest_with_times())
    # mtime(1690),  then a.txt's mtime(1700) + atime(1700.5)
    times = [e["time"] for e in events]
    assert times == sorted(times)
    macbs = {e["macb"] for e in events}
    assert "m..." in macbs and ".a.." in macbs


def test_timeline_csv_and_jsonl(tmp_path):
    m = _manifest_with_times()
    csv_path = tmp_path / "t.csv"
    n = report.write_timeline_csv(m, str(csv_path))
    assert n == 3                                  # 2 + 1 timestamps
    assert "a.txt" in csv_path.read_text()

    jl = tmp_path / "t.jsonl"
    report.write_timeline_jsonl(m, str(jl))
    lines = [json.loads(x) for x in jl.read_text().splitlines()]
    assert len(lines) == 3 and all("macb" in e for e in lines)


def test_html_report(tmp_path):
    m = _manifest_with_times()
    out = tmp_path / "r.html"
    report.write_html_report(m, str(out))
    doc = out.read_text()
    assert "carvX recovery report" in doc
    assert "a.txt" in doc and "pic.jpg" in doc
    assert "<table" in doc
