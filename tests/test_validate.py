"""Deep validation + blank-skip tests."""


import builders
from carvx import validate
from carvx.carver import Carver, Options
from carvx.signatures import SIGNATURES


def run(path, out, **kw):
    c = Carver(path, list(SIGNATURES), Options(out_dir=str(out), quiet=True, **kw))
    try:
        return c.run(), c
    finally:
        c.close()


def test_validate_valid_files():
    assert validate.validate("png", builders.make_png())[0] is True
    assert validate.validate("jpg", builders.make_jpeg())[0] is True
    assert validate.validate("gif", builders.make_gif())[0] is True
    assert validate.validate("zip", builders.make_zip())[0] is True
    assert validate.validate("gz", builders.make_gzip())[0] is True
    assert validate.validate("sqlite", builders.make_sqlite())[0] is True


def test_validate_detects_corruption():
    png = bytearray(builders.make_png())
    png[20:24] = b"\xde\xad\xbe\xef"        # break IHDR CRC
    assert validate.validate("png", bytes(png))[0] is False

    z = bytearray(builders.make_zip())
    mid = len(z) // 2                      # corrupt deep in a compressed stream
    z[mid - 10:mid + 10] = b"\xff" * 20
    assert validate.validate("zip", bytes(z))[0] is False


def test_validate_unknown_ext_inconclusive():
    assert validate.validate("xyz", b"whatever")[0] is None
    assert validate.validate("png", b"not a png")[0] is None


def test_validate_png_tightens_to_iend():
    data = builders.make_png()
    ok, size = validate.validate("png", data + b"junkjunkjunk")
    assert ok is True and size == len(data)


def test_carver_sets_confidence(tmp_path):
    png = builders.make_png()
    bad = bytearray(png)
    bad[20:24] = b"\x00\x00\x00\x00"
    blob = (b"\x00" * 512 + png + b"\x00" * (512 - len(png) % 512)
            + bytes(bad) + b"\x00" * 512)
    path = tmp_path / "v.img"
    path.write_bytes(blob)
    records, _ = run(str(path), tmp_path / "o", validate=True)
    conf = sorted(r.confidence for r in records)
    assert conf == ["failed", "verified"]


def test_drop_failed_discards_bad(tmp_path):
    bad = bytearray(builders.make_png())
    bad[20:24] = b"\x00\x00\x00\x00"
    path = tmp_path / "v.img"
    path.write_bytes(b"\x00" * 512 + bytes(bad) + b"\x00" * 512)
    records, _ = run(str(path), tmp_path / "o", validate=True, drop_failed=True)
    assert records == []


def test_blank_skip_counts(tmp_path):
    jpg = builders.make_jpeg()
    blob = bytearray(64 << 20)             # 64 MiB zeros
    blob[10 << 20:10 << 20 + len(jpg)] = jpg
    path = tmp_path / "sparse.img"
    path.write_bytes(bytes(blob))
    records, c = run(str(path), tmp_path / "o", chunk_size=1 << 20)
    assert any(r.ext == "jpg" for r in records)
    assert c.skipped_blank > 0

    records2, c2 = run(str(path), tmp_path / "o2", chunk_size=1 << 20,
                       skip_blank=False)
    assert c2.skipped_blank == 0
    # same files found either way
    assert {r.offset for r in records} == {r.offset for r in records2}
