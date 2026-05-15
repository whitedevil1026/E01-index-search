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

import glob
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

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


def detect_format(first_segment: str) -> str:
    ext = Path(first_segment).suffix.lower()
    if ext.startswith(".ex"):
        return "Ex01"
    if ext.startswith(".l") and "x" in ext:
        return "Lx01"
    if ext.startswith(".l"):
        return "L01"
    return "E01"


def inspect(first_segment: str) -> EwfInfo:
    """Return metadata about an E01 set. Works even without pyewf —
    returns segment list, format guess, and size estimate from disk only.
    """
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

    def close(self) -> None:
        try:
            self._handle.close()
        except Exception:
            pass
