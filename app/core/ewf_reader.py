"""libewf-python wrapper with graceful fallback.

Per the May 2026 review:
- libewf reads are single-threaded *per handle*, but per-handle state
  is independent — open N handles for N workers and partition by byte
  range.
- Ex01 AES-256 encryption is not supported by libewf; detect and tag
  the volume as 'encrypted, no usable text' rather than indexing zeros.
- E01 segment glob: 'image.E01' is segment 1; subsequent segments are
  E02, E03, ... up to E?? then EAA, EAB, ...
"""
from __future__ import annotations

import concurrent.futures
import glob
import hashlib
import os
import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Sequence

try:
    import pyewf  # type: ignore
    HAS_PYEWF = True
except Exception:  # noqa: BLE001
    HAS_PYEWF = False


@dataclass
class EwfInfo:
    segment_files: list[str]
    media_size: int
    sectors_per_chunk: int | None
    bytes_per_sector: int | None
    md5: str | None
    sha1: str | None
    acquiry_date: str | None
    is_encrypted: bool
    format: str  # "E01", "Ex01", "L01", "Lx01"


def glob_segments(first_segment: str) -> list[str]:
    """Given e.g. 'foo.E01' return the full glob list in order."""
    p = Path(first_segment)
    stem = p.stem  # 'foo'
    parent = p.parent
    # libewf provides a helper but we implement it manually to work
    # without the lib for the UI preview.
    pattern = re.compile(
        rf"^{re.escape(stem)}\.(E\d{{2}}|Ex\d{{2}}|E[A-Z]{{2}}|Ex[A-Z]{{2}}|L\d{{2}}|Lx\d{{2}})$",
        re.IGNORECASE,
    )
    candidates = sorted(parent.iterdir())
    return [str(c) for c in candidates if c.is_file() and pattern.match(c.name)]


# Raw / dd image extensions — a flat sector-for-sector dump of a disk.
_RAW_EXTS = {".dd", ".raw", ".img", ".bin", ".001", ".000", ".ima", ".flp"}


def detect_format(first_segment: str) -> str:
    ext = Path(first_segment).suffix.lower()
    if ext.startswith(".ex"):
        return "Ex01"
    if ext.startswith(".l") and "x" in ext:
        return "Lx01"
    if ext.startswith(".l"):
        return "L01"
    return "E01"


def _is_ewf_signature(path: str) -> bool:
    """True if the file begins with an EWF/EWF2/LEWF signature."""
    try:
        with open(path, "rb") as f:
            head = f.read(8)
        return head[:3] in (b"EVF", b"LVF") or head[:4] == b"EVF2"
    except Exception:  # noqa: BLE001
        return False


def _is_aff4(path: str) -> bool:
    """AFF4 v1.0 is a ZIP container; the ZIP comment / first member
    names carry an 'aff4' marker. Detect cheaply from the first bytes.
    """
    try:
        with open(path, "rb") as f:
            head = f.read(512)
        if head[:4] != b"PK\x03\x04":
            return False
        return b"aff4" in head.lower() or b"container.description" in head.lower()
    except Exception:  # noqa: BLE001
        return False


def inspect(first_segment: str) -> EwfInfo:
    """Return metadata about a forensic image.

    Handles three input kinds:
      * EWF / EnCase  (.E01 / .Ex01 / .L01 …)  — full metadata via pyewf
      * raw / dd      (.dd / .raw / .img / .001 …) — flat disk dump
      * AFF4          — detected and reported as unsupported

    Works even without pyewf (returns a best-effort estimate).
    """
    ext = Path(first_segment).suffix.lower()

    # --- AFF4 — detected, not supported (see note in EwfInfo) ----------
    if ext == ".aff4" or _is_aff4(first_segment):
        size = os.path.getsize(first_segment) if os.path.exists(first_segment) else 0
        return EwfInfo(
            segment_files=[first_segment], media_size=size,
            sectors_per_chunk=None, bytes_per_sector=None,
            md5=None, sha1=None, acquiry_date=None,
            is_encrypted=False, format="AFF4",
        )

    # --- raw / dd — a flat image, not EWF ------------------------------
    is_raw = (ext in _RAW_EXTS or
              (os.path.isfile(first_segment) and not _is_ewf_signature(first_segment)
               and ext not in (".e01", ".ex01", ".l01", ".lx01")))
    if is_raw and os.path.isfile(first_segment):
        size = os.path.getsize(first_segment)
        return EwfInfo(
            segment_files=[first_segment], media_size=size,
            sectors_per_chunk=None, bytes_per_sector=512,
            md5=None, sha1=None, acquiry_date=None,
            is_encrypted=False, format="RAW",
        )

    segs = glob_segments(first_segment)
    fmt = detect_format(first_segment)
    total = sum(os.path.getsize(s) for s in segs) if segs else 0
    if not HAS_PYEWF:
        return EwfInfo(
            segment_files=segs, media_size=total,
            sectors_per_chunk=None, bytes_per_sector=None,
            md5=None, sha1=None, acquiry_date=None,
            is_encrypted=(fmt == "Ex01"),  # best-effort guess
            format=fmt,
        )
    h = pyewf.handle()
    try:
        h.open(segs)
        try:
            return EwfInfo(
                segment_files=segs,
                media_size=int(h.get_media_size()),
                sectors_per_chunk=getattr(h, "get_sectors_per_chunk", lambda: None)(),
                bytes_per_sector=getattr(h, "get_bytes_per_sector", lambda: None)(),
                md5=_safe_hashval(h, "MD5"),
                sha1=_safe_hashval(h, "SHA1"),
                acquiry_date=_safe_hdr(h, "acquiry_date"),
                is_encrypted=False,
                format=fmt,
            )
        finally:
            h.close()
    except Exception:
        return EwfInfo(
            segment_files=segs, media_size=total,
            sectors_per_chunk=None, bytes_per_sector=None,
            md5=None, sha1=None, acquiry_date=None,
            is_encrypted=(fmt == "Ex01"), format=fmt,
        )


def _safe_hashval(h, name: str) -> str | None:
    try:
        v = h.get_hash_value(name)
        return v if v else None
    except Exception:
        return None


def _safe_hdr(h, name: str) -> str | None:
    try:
        v = h.get_header_value(name)
        return v if v else None
    except Exception:
        return None


class EwfHandle:
    """Thin file-like wrapper over a single pyewf handle.

    One instance per worker thread. Do not share across threads —
    per-handle state is per-instance and that's how we get parallelism
    despite libewf's single-threaded-per-handle reads.
    """

    def __init__(self, segments: Sequence[str]):
        if not HAS_PYEWF:
            raise RuntimeError("libewf-python (pyewf) is not installed")
        self.segments = list(segments)
        self._handle = pyewf.handle()
        self._handle.open(self.segments)
        self._size = int(self._handle.get_media_size())
        self._pos = 0

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def read(self, n: int = -1) -> bytes:
        if n < 0:
            n = self._size - self._pos
        data = self._handle.read(n)
        # Track position ourselves — pyewf.read() returns the bytes but
        # we maintain our own offset for tell()/seek() bookkeeping.
        self._pos += len(data)
        return data

    def seek(self, offset: int, whence: int = 0) -> int:
        # IMPORTANT: pyewf.handle.seek() returns None on success, not the
        # new offset. Compute the new position ourselves so subsequent
        # read()/tell() calls work. Without this, self._pos becomes None
        # and the next `self._pos += len(data)` raises TypeError —
        # which propagates through pytsk3 as the cryptic
        # "Volume_Info_Con / unsupported operand types for +=: NoneType
        # and int" error.
        self._handle.seek(offset, whence)
        if whence == 0:
            self._pos = int(offset)
        elif whence == 1:
            self._pos = (self._pos or 0) + int(offset)
        elif whence == 2:
            self._pos = self._size + int(offset)
        return self._pos

    def tell(self) -> int:
        return self._pos

    @property
    def size(self) -> int:
        return self._size

    def get_size(self) -> int:
        # libyal `open_file_object()` expects a get_size() method on the
        # file-like object it is handed.
        return self._size

    def get_offset(self) -> int:
        return self._pos

    def close(self) -> None:
        try:
            self._handle.close()
        except Exception:
            pass


class RawHandle:
    """File-like wrapper over a flat raw / dd disk image.

    Presents the exact same interface as `EwfHandle` (read / seek /
    tell / size / get_size / close + context manager) so every layer
    above — the filesystem walker, encryption/VSS detection, hashing —
    consumes a raw image and an E01 identically.

    A raw image has no compression and no segments, so this is just a
    thin, position-tracking view over an ordinary file.
    """

    def __init__(self, path: str):
        self.path = str(path)
        self._fh = open(self.path, "rb")
        self._fh.seek(0, os.SEEK_END)
        self._size = self._fh.tell()
        self._fh.seek(0)
        self._pos = 0
        self.segments = [self.path]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0:
            n = self._size - self._pos
        self._fh.seek(self._pos)
        data = self._fh.read(n)
        self._pos += len(data)
        return data

    def seek(self, offset: int, whence: int = 0) -> int:
        if whence == 0:
            self._pos = int(offset)
        elif whence == 1:
            self._pos += int(offset)
        elif whence == 2:
            self._pos = self._size + int(offset)
        self._pos = max(0, min(self._pos, self._size))
        return self._pos

    def tell(self) -> int:
        return self._pos

    @property
    def size(self) -> int:
        return self._size

    def get_size(self) -> int:
        return self._size

    def get_offset(self) -> int:
        return self._pos

    def close(self) -> None:
        try:
            self._fh.close()
        except Exception:  # noqa: BLE001
            pass


def open_handle(info: "EwfInfo"):
    """Return the right image handle for an inspected image.

    `EwfInfo.format` is one of E01/Ex01/L01/Lx01 (EWF) or RAW. AFF4 is
    rejected here — the caller should check for it before ingesting.
    """
    if info.format == "RAW":
        return RawHandle(info.segment_files[0])
    if info.format == "AFF4":
        raise RuntimeError(
            "AFF4 images are not supported by this build — see the README "
            "(the only Python AFF4 library, pyaff4, has an abandoned "
            "dependency chain). Convert to E01 or raw/dd first."
        )
    return EwfHandle(info.segment_files)


def raw_media_hash(path: str, algos: Sequence[str],
                   block_size: int = 16 * 1024 * 1024,
                   progress_cb: Optional[Callable[[int, int], None]] = None,
                   cancel_cb: Optional[Callable[[], bool]] = None
                   ) -> dict[str, object]:
    """Hash a raw / dd image — a flat file, no decompression, so a single
    streaming pass. Same return shape as `parallel_hash`.
    """
    size = os.path.getsize(path)
    hashers = {a: _new_hasher(a) for a in algos}
    done = 0
    with open(path, "rb") as fh:
        while True:
            if cancel_cb and cancel_cb():
                raise _Cancelled()
            chunk = fh.read(block_size)
            if not chunk:
                break
            for h in hashers.values():
                h.update(chunk)
            done += len(chunk)
            if progress_cb:
                progress_cb(done, size)
    result: dict[str, object] = {a: h.hexdigest() for a, h in hashers.items()}
    result["size_bytes"] = size
    return result


# ---- parallel multi-handle hashing ----------------------------------------

def _new_hasher(algo: str):
    algo = algo.lower()
    if algo == "blake2b":
        return hashlib.blake2b()
    return hashlib.new(algo)


def parallel_hash(segments: Sequence[str], algos: Sequence[str],
                  n_workers: int = 4,
                  block_size: int = 16 * 1024 * 1024,
                  progress_cb: Optional[Callable[[int, int], None]] = None,
                  cancel_cb: Optional[Callable[[], bool]] = None
                  ) -> dict[str, object]:
    """Hash the full media content of an E01 set using multiple libewf
    handles in parallel.

    libewf decompresses chunks single-threaded *per handle*, but each
    handle has independent state, so N handles give N-way parallel
    decompression. Hashing itself is order-dependent, so a sliding
    window of read-ahead futures is consumed strictly in offset order
    and fed to the hashers sequentially — the result is bit-identical
    to a single-threaded read.

    Memory is bounded to roughly (n_workers * 2) * block_size.

    Returns {algo: hexdigest, ..., 'size_bytes': N}.
    Raises RuntimeError if pyewf is unavailable.
    """
    if not HAS_PYEWF:
        raise RuntimeError("libewf-python (pyewf) is not installed")

    # media size from a probe handle
    probe = pyewf.handle()
    probe.open(list(segments))
    size = int(probe.get_media_size())
    probe.close()

    if size == 0:
        out: dict[str, object] = {a: _new_hasher(a).hexdigest() for a in algos}
        out["size_bytes"] = 0
        return out

    n_blocks = (size + block_size - 1) // block_size

    # one libewf handle per worker thread, created lazily, tracked for cleanup
    tls = threading.local()
    all_handles: list = []
    handles_lock = threading.Lock()

    def _handle():
        h = getattr(tls, "h", None)
        if h is None:
            h = pyewf.handle()
            h.open(list(segments))
            tls.h = h
            with handles_lock:
                all_handles.append(h)
        return h

    def _read_block(idx: int) -> bytes:
        off = idx * block_size
        n = min(block_size, size - off)
        h = _handle()
        h.seek(off, 0)
        return h.read(n)

    hashers = {a: _new_hasher(a) for a in algos}
    done = 0
    window = max(2, n_workers * 2)

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=n_workers) as ex:
            futures: dict[int, concurrent.futures.Future] = {}
            next_submit = 0
            next_consume = 0
            while next_consume < n_blocks:
                # keep the read-ahead window full
                while next_submit < n_blocks and len(futures) < window:
                    futures[next_submit] = ex.submit(_read_block, next_submit)
                    next_submit += 1
                if cancel_cb and cancel_cb():
                    for f in futures.values():
                        f.cancel()
                    raise _Cancelled()
                # consume strictly in order so the hash is deterministic
                data = futures.pop(next_consume).result()
                next_consume += 1
                for hh in hashers.values():
                    hh.update(data)
                done += len(data)
                if progress_cb:
                    progress_cb(done, size)
    except _Cancelled:
        raise
    finally:
        with handles_lock:
            for h in all_handles:
                try:
                    h.close()
                except Exception:  # noqa: BLE001
                    pass

    result: dict[str, object] = {a: hh.hexdigest() for a, hh in hashers.items()}
    result["size_bytes"] = size
    return result


class _Cancelled(Exception):
    """Internal — raised to unwind parallel_hash on cancellation."""
