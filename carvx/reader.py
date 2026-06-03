"""Low-level read access to disk images and block devices."""

import os
import stat
import sys
import threading

_HAS_PREAD = hasattr(os, "pread")          # POSIX; absent on Windows
_WIN_SECTOR = 512                          # raw \\.\ devices need aligned I/O


def _windows_device_size(fd: int) -> int:
    r"""IOCTL_DISK_GET_LENGTH_INFO via ctypes for \\.\PhysicalDriveN / \\.\C:."""
    import ctypes
    import msvcrt
    handle = msvcrt.get_osfhandle(fd)
    out = ctypes.c_int64(0)
    returned = ctypes.c_uint32(0)
    ok = ctypes.windll.kernel32.DeviceIoControl(
        ctypes.c_void_p(handle), 0x0007405C,   # IOCTL_DISK_GET_LENGTH_INFO
        None, 0, ctypes.byref(out), 8, ctypes.byref(returned), None)
    return out.value if ok else 0


class Reader:
    """Random-access reader over a regular file or a block/character device.

    POSIX: pread(), naturally thread-safe. Windows: seek+read under a lock,
    with sector-aligned access for raw devices (PhysicalDriveN / volume paths).
    """

    def __init__(self, path: str):
        self.path = path
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        self.fd = os.open(path, flags)
        self._lock = threading.Lock()
        st = os.fstat(self.fd)
        if stat.S_ISREG(st.st_mode):
            self.size = st.st_size
            self.is_device = False
        else:
            self.is_device = True
            self.size = os.lseek(self.fd, 0, os.SEEK_END)
            if self.size <= 0 and sys.platform == "win32":
                self.size = _windows_device_size(self.fd)
        if self.size <= 0:
            raise ValueError(f"cannot determine size of {path!r} (got {self.size})")
        # Raw Windows devices (\\.\PhysicalDriveN, \\.\C:) reject unaligned reads.
        self._win_device = self.is_device and sys.platform == "win32"

    def _read_at(self, offset: int, length: int) -> bytes:
        if _HAS_PREAD:
            return os.pread(self.fd, length, offset)
        with self._lock:
            os.lseek(self.fd, offset, os.SEEK_SET)
            return os.read(self.fd, length)

    def pread(self, offset: int, length: int) -> bytes:
        if offset >= self.size or length <= 0:
            return b""
        length = min(length, self.size - offset)
        if self._win_device:
            # Raw Windows devices reject unaligned reads: round out, trim back.
            lo = offset - offset % _WIN_SECTOR
            hi = offset + length
            hi += -hi % _WIN_SECTOR
            hi = min(hi, self.size)
            buf = self._read_loop(lo, hi - lo)
            return buf[offset - lo:offset - lo + length]
        return self._read_loop(offset, length)

    def _read_loop(self, offset: int, length: int) -> bytes:
        out = bytearray()
        while length > 0:
            chunk = self._read_at(offset, length)
            if not chunk:
                break
            out += chunk
            offset += len(chunk)
            length -= len(chunk)
        return bytes(out)

    def close(self):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class Window:
    """Bounded, cached view of the source starting at a candidate header.

    Handlers use it to parse structure without slurping max_size into RAM.
    All positions are relative to the window base.
    """

    BLOCK = 1 << 16  # 64 KiB cache blocks
    MAX_BLOCKS = 64

    def __init__(self, reader: Reader, base: int, limit: int):
        self.reader = reader
        self.base = base
        self.limit = min(limit, reader.size - base)
        self._cache: dict[int, bytes] = {}

    def _block(self, idx: int) -> bytes:
        blk = self._cache.get(idx)
        if blk is None:
            if len(self._cache) >= self.MAX_BLOCKS:
                self._cache.pop(next(iter(self._cache)))
            blk = self.reader.pread(self.base + idx * self.BLOCK, self.BLOCK)
            self._cache[idx] = blk
        return blk

    def read(self, pos: int, n: int) -> bytes:
        """Read up to n bytes at pos; short result means EOF/limit reached."""
        if pos < 0 or n <= 0 or pos >= self.limit:
            return b""
        n = min(n, self.limit - pos)
        out = bytearray()
        while n > 0:
            idx, rel = divmod(pos, self.BLOCK)
            blk = self._block(idx)
            piece = blk[rel:rel + n]
            if not piece:
                break
            out += piece
            pos += len(piece)
            n -= len(piece)
        return bytes(out)

    def find(self, needle: bytes, start: int = 0, end: int | None = None) -> int:
        """First occurrence of needle fully inside [start, end); -1 if absent."""
        if end is None:
            end = self.limit
        end = min(end, self.limit)
        nl = len(needle)
        step = 1 << 20
        pos = max(start, 0)
        while pos < end:
            buf = self.read(pos, min(step, end - pos) + nl - 1)
            if len(buf) < nl:
                return -1
            i = buf.find(needle)
            if i >= 0 and pos + i + nl <= end:
                return pos + i
            pos += step
        return -1

    def find_last(self, needle: bytes, start: int = 0, end: int | None = None) -> int:
        """Last occurrence of needle fully inside [start, end); -1 if absent."""
        if end is None:
            end = self.limit
        end = min(end, self.limit)
        nl = len(needle)
        step = 1 << 20
        pos = max(start, 0)
        last = -1
        while pos < end:
            buf = self.read(pos, min(step, end - pos) + nl - 1)
            if len(buf) < nl:
                break
            i = buf.find(needle)
            while i >= 0:
                if pos + i + nl <= end:
                    last = pos + i
                i = buf.find(needle, i + 1)
            pos += step
        return last
