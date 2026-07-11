"""BitLocker unlock + transparent-decrypt tests.

These build a synthetic FVE image (real metadata layout) and verify the full
recover-VMK -> recover-FVEK -> decrypt-sectors pipeline for every supported
cipher, plus the CLI/env integration. STRETCH_COUNT is patched down so the
key-stretch does not take seconds per test.
"""

import os

import pytest

from carvx import _aes, bitlocker
from carvx.images import open_source, BitLockerDecryptingReader
from tests.bitlocker_builder import build_image, SS

# each group must be divisible by 11 and < 65536*11; build valid ones.
RECOVERY = "-".join(f"{v * 11:06d}" for v in (1000, 2000, 3000, 4000,
                                              5000, 6000, 7000, 8000))


@pytest.fixture(autouse=True)
def _fast_stretch(monkeypatch):
    monkeypatch.setattr(bitlocker, "STRETCH_COUNT", 8)


def _plaintext_volume(n_sectors=8):
    boot = bytearray(SS)
    boot[3:11] = b"NTFS    "
    boot[510:512] = b"\x55\xaa"
    vol = bytearray(bytes(boot))
    for i in range(1, n_sectors):
        vol += bytes(((i * 13 + b) & 0xFF) for b in range(SS))
    return bytes(vol)


# -- crypto primitives -----------------------------------------------------

def test_aes_fips_vectors():
    a = _aes._PyAES(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    assert a.encrypt(pt).hex() == "69c4e0d86a7b0430d8cdb78070b4c55a"
    assert a.decrypt(a.encrypt(pt)) == pt


def test_ccm_roundtrip():
    key = bytes(range(16))
    nonce = b"\x09" * 12
    pt = b"the volume master key padding!!!"
    blob = _aes.ccm_encrypt(key, nonce, pt)
    assert _aes.ccm_decrypt(key, nonce, blob) == pt
    with pytest.raises(ValueError):
        _aes.ccm_decrypt(bytes(16), nonce, blob)        # wrong key -> MAC fail


def test_recovery_password_parse():
    inter = bitlocker.parse_recovery_password(RECOVERY)
    assert len(inter) == 16
    with pytest.raises(bitlocker.BitLockerError):
        bitlocker.parse_recovery_password("123-456")
    with pytest.raises(bitlocker.BitLockerError):
        bitlocker.parse_recovery_password("000001-" * 7 + "000001")  # not /11


# -- full unlock per cipher ------------------------------------------------

@pytest.mark.parametrize("method", [
    bitlocker.M_AES_XTS_128, bitlocker.M_AES_XTS_256,
    bitlocker.M_AES_CBC_128, bitlocker.M_AES_CBC_256,
    bitlocker.M_AES_CBC_128_DIFFUSER, bitlocker.M_AES_CBC_256_DIFFUSER,
])
def test_unlock_each_method(method, tmp_path):
    pt = _plaintext_volume()
    img = build_image(pt, RECOVERY, method=method)
    path = tmp_path / "disk.dd"
    path.write_bytes(img)

    from carvx.reader import Reader
    r = Reader(str(path))
    creds = bitlocker.Credentials(recovery=RECOVERY)
    vol = bitlocker.unlock_volume(r, 0, creds)
    assert vol is not None
    # whole decrypted volume must match the original plaintext, incl. sector 0
    # (served from the relocated header backup).
    assert vol.read(0, len(pt)) == pt
    r.close()


def test_wrong_recovery_key_fails(tmp_path):
    pt = _plaintext_volume()
    img = build_image(pt, RECOVERY)
    path = tmp_path / "disk.dd"
    path.write_bytes(img)
    from carvx.reader import Reader
    r = Reader(str(path))
    wrong = "-".join(f"{9000 * 11:06d}" for _ in range(8))   # valid format, wrong key
    with pytest.raises(bitlocker.BitLockerError):
        bitlocker.unlock_volume(r, 0, bitlocker.Credentials(recovery=wrong))
    r.close()


# -- raw FVEK path ---------------------------------------------------------

def test_fvek_direct(tmp_path):
    pt = _plaintext_volume()
    method = bitlocker.M_AES_XTS_128
    img = build_image(pt, RECOVERY, method=method)
    # pull the FVEK out via the recovery path, then re-unlock using only --fvek
    path = tmp_path / "disk.dd"
    path.write_bytes(img)
    from carvx.reader import Reader
    r = Reader(str(path))
    meta = None
    boot = r.pread(0, 512)
    for off in bitlocker._metadata_offsets(boot):
        blk = r.pread(off, 0x10000)
        if blk[:8] == bitlocker.FVE_SIGNATURE:
            meta = bitlocker.parse_metadata(blk)
            break
    fvek = bitlocker.recover_fvek(meta, bitlocker.Credentials(recovery=RECOVERY))
    vol = bitlocker.unlock_volume(r, 0, bitlocker.Credentials(fvek=fvek))
    assert vol.read(0, len(pt)) == pt
    r.close()


# -- env / open_source integration -----------------------------------------

def test_open_source_transparent_decrypt(tmp_path, monkeypatch):
    pt = _plaintext_volume()
    img = build_image(pt, RECOVERY)
    path = tmp_path / "disk.dd"
    path.write_bytes(img)

    creds = bitlocker.Credentials(recovery=RECOVERY)
    monkeypatch.setenv("CARVX_BITLOCKER", creds.to_env())
    r = open_source(str(path))
    assert isinstance(r, BitLockerDecryptingReader)
    # reads at absolute offset 0 now yield decrypted NTFS boot in place
    assert r.pread(0, 11)[3:11] == b"NTFS    "
    assert r.pread(0, len(pt)) == pt
    r.close()


def test_open_source_no_creds_passthrough(tmp_path):
    pt = _plaintext_volume()
    img = build_image(pt, RECOVERY)
    path = tmp_path / "disk.dd"
    path.write_bytes(img)
    os.environ.pop("CARVX_BITLOCKER", None)
    r = open_source(str(path))
    assert not isinstance(r, BitLockerDecryptingReader)
    assert r.pread(3, 8) == bitlocker.FVE_SIGNATURE       # still encrypted
    r.close()


def test_cli_carve_through_bitlocker(tmp_path):
    from carvx.cli import main
    from tests.builders import make_jpeg
    jpeg = make_jpeg()
    vol = bytearray(_plaintext_volume(2) + bytes(SS * 8))
    vol[600:600 + len(jpeg)] = jpeg
    vol = bytes(vol[:len(vol) - len(vol) % SS])
    img = build_image(vol, RECOVERY, method=bitlocker.M_AES_XTS_256)
    path = tmp_path / "disk.dd"
    path.write_bytes(img)
    out = tmp_path / "carved"
    rc = main([str(path), "-o", str(out), "-t", "jpg", "-q",
               "--bitlocker-recovery-key", RECOVERY])
    assert rc == 0
    carved = list(out.rglob("*.jpg"))
    assert carved, "no JPEG carved from the decrypted volume"
    assert carved[0].read_bytes().startswith(b"\xff\xd8")
    os.environ.pop("CARVX_BITLOCKER", None)


def test_credentials_env_roundtrip():
    c = bitlocker.Credentials(recovery="r", password="p",
                              bek=b"\x01\x02", fvek=b"\xaa\xbb")
    env = c.to_env()
    os.environ["CARVX_BITLOCKER"] = env
    try:
        got = bitlocker.Credentials.from_env()
        assert got.recovery == "r" and got.password == "p"
        assert got.bek == b"\x01\x02" and got.fvek == b"\xaa\xbb"
    finally:
        os.environ.pop("CARVX_BITLOCKER", None)
