"""Integration tests: scan engine over synthetic images."""

import hashlib
import json
import os
import random
import subprocess
import sys

import pytest

import builders
from carvx.carver import Carver, Options
from carvx.signatures import SIGNATURES, resolve_types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture
def image(tmp_path):
    """Synthetic image: every builder's file at a sector-aligned offset."""
    random.seed(7)
    expected = {}
    path = tmp_path / "test.img"
    with open(path, "wb") as img:
        img.write(b"\x00" * 4096)
        for name, builder in builders.BUILDERS.items():
            img.write(os.urandom(random.randint(1000, 5000)))
            img.write(b"\x00" * (-img.tell() % 512))
            offset = img.tell()
            data = builder()
            img.write(data)
            expected[name] = (offset, len(data), hashlib.sha256(data).hexdigest())
        img.write(os.urandom(3000))
    return str(path), expected


def run_carver(path, out, **kw):
    opts = Options(out_dir=str(out), quiet=True, **kw)
    c = Carver(path, list(SIGNATURES), opts)
    try:
        return c.run()
    finally:
        c.close()


def test_all_types_recovered_hash_exact(image, tmp_path):
    path, expected = image
    records = run_carver(path, tmp_path / "out")
    by_offset = {r.offset: r for r in records}
    for name, (offset, size, sha) in expected.items():
        rec = by_offset.get(offset)
        assert rec is not None, f"{name}: nothing carved at {offset:#x}"
        assert rec.size == size, f"{name}: {rec.size} != {size}"
        assert rec.sha256 == sha, f"{name}: hash mismatch"
        assert os.path.getsize(rec.path) == size


def test_dry_run_writes_nothing(image, tmp_path):
    path, expected = image
    out = tmp_path / "out"
    records = run_carver(path, out, dry_run=True)
    assert len(records) == len(expected)
    assert not out.exists()
    # hashes still computed in dry run
    shas = {r.sha256 for r in records}
    assert all(sha in shas for _, _, sha in expected.values())


def test_offset_and_length_restrict_scan(image, tmp_path):
    path, expected = image
    offsets = sorted(off for off, _, _ in expected.values())
    third = offsets[2]
    records = run_carver(path, tmp_path / "out", start=third, length=1)
    # only headers at start offset can match a 1-byte scan window
    assert all(r.offset == third for r in records)
    records = run_carver(path, tmp_path / "out2", start=third)
    assert {r.offset for r in records} == set(offsets[2:])


def test_align_filters_unaligned(image, tmp_path):
    path, expected = image
    records = run_carver(path, tmp_path / "out", align=512)
    assert len(records) == len(expected)       # all planted sector-aligned
    assert all(r.offset % 512 == 0 for r in records)


def test_min_size_filters_small(image, tmp_path):
    path, expected = image
    records = run_carver(path, tmp_path / "out", min_size=1000)
    assert records and all(r.size >= 1000 for r in records)


def test_type_filter(image, tmp_path):
    path, expected = image
    sigs = resolve_types("jpeg,png")           # alias resolution included
    opts = Options(out_dir=str(tmp_path / "out"), quiet=True)
    c = Carver(path, sigs, opts)
    try:
        records = c.run()
    finally:
        c.close()
    assert {r.type for r in records} == {"jpg", "png"}


def test_resolve_types_rejects_unknown():
    with pytest.raises(ValueError):
        resolve_types("jpg,nosuchtype")


def test_skip_vs_no_skip(tmp_path):
    """A PNG embedded in a ZIP shows up only with skip_carved=False."""
    import io
    import zipfile
    png = builders.make_png()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        z.writestr("img.png", png)
    data = buf.getvalue()
    path = tmp_path / "img.bin"
    path.write_bytes(b"\x00" * 512 + data + b"\x00" * 512)

    recs = run_carver(str(path), tmp_path / "a", skip_carved=True)
    assert [r.ext for r in recs] == ["zip"]
    recs = run_carver(str(path), tmp_path / "b", skip_carved=False)
    assert sorted(r.ext for r in recs) == ["png", "zip"]


def test_chunk_boundary_straddling_file(tmp_path):
    """File whose header sits just before a chunk boundary must carve whole."""
    png = builders.make_png()
    chunk = 1 << 20
    data = bytearray(os.urandom(chunk - 2))    # header straddles 1 MiB boundary
    data = bytes(data) + png + os.urandom(1000)
    path = tmp_path / "img.bin"
    path.write_bytes(data)
    records = run_carver(str(path), tmp_path / "out", chunk_size=chunk)
    pngs = [r for r in records if r.ext == "png" and r.offset == chunk - 2]
    assert pngs and pngs[0].size == len(png)


def test_random_noise_image_no_false_positives(tmp_path):
    path = tmp_path / "noise.img"
    path.write_bytes(os.urandom(8 << 20))
    records = run_carver(str(path), tmp_path / "out")
    assert [r for r in records if r.validated] == []


def test_parallel_matches_serial(image, tmp_path):
    path, expected = image
    serial = run_carver(path, tmp_path / "s")
    from carvx.carver import run_parallel
    opts = Options(out_dir=str(tmp_path / "p"), quiet=True,
                   chunk_size=1 << 20)         # small chunks: force many ranges
    parallel, _ = run_parallel(path, list(SIGNATURES), opts, jobs=4)
    key = lambda rs: sorted((r.offset, r.size, r.sha256) for r in rs)
    assert key(serial) == key(parallel)


def test_dedup_marks_duplicates(tmp_path):
    png = builders.make_png()
    blob = b"\x00" * 512 + png + b"\x00" * (512 - len(png) % 512) + png + b"\x00" * 64
    path = tmp_path / "dup.img"
    path.write_bytes(blob)
    records = run_carver(str(path), tmp_path / "out", dedup=True)
    dups = [r for r in records if r.duplicate_of is not None]
    originals = [r for r in records if r.duplicate_of is None]
    assert len(dups) == 1 and len(originals) == 1
    assert dups[0].path == "" and os.path.exists(originals[0].path)
    assert dups[0].duplicate_of == originals[0].offset


def test_cli_end_to_end(image, tmp_path):
    path, expected = image
    out = tmp_path / "out"
    r = subprocess.run([sys.executable, "-m", "carvx", path, "-o", str(out), "-q"],
                       cwd=ROOT, capture_output=True)
    assert r.returncode == 0, r.stderr.decode()
    manifest = json.loads((out / "manifest.json").read_text())
    assert len(manifest["files"]) == len(expected)
    shas = {f["sha256"] for f in manifest["files"]}
    assert all(sha in shas for _, _, sha in expected.values())
