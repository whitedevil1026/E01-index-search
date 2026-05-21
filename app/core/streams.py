"""File-like stream adapters used to chain image / volume layers.

The forensic stack layers like this:

    E01 file  ->  EwfHandle
              ->  OffsetStream (a partition byte-range slice)
              ->  pybde / pyluksde / pyfvde volume   (if encrypted)
              ->  pyvshadow store                    (if a VSS snapshot)
              ->  pytsk3 FS_Info  /  pyfsntfs volume  (the filesystem)

Every layer must present a consistent file-like interface so the next
layer can consume it. libyal's `open_file_object()` wants an object
with `read(size)`, `seek(offset, whence)` and `get_size()`. pytsk3
wants an `Img_Info` subclass whose `read(offset, size)` takes an
absolute offset. These helpers bridge the two.

libyal volume / store objects already expose `read` / `seek` / `tell`
/ `get_size`, so they can be passed straight into the next libyal
`open_file_object()` or wrapped by `pytsk_img_from_stream()`.
"""
from __future__ import annotations

from typing import Any

try:
    import pytsk3
    HAS_PYTSK3 = True
except Exception:  # noqa: BLE001
    HAS_PYTSK3 = False


def stream_size(obj: Any) -> int:
    """Best-effort size of any stream-ish object."""
    for attr in ("get_size", "size"):
        v = getattr(obj, attr, None)
        if v is None:
            continue
        try:
            return int(v() if callable(v) else v)
        except Exception:  # noqa: BLE001
            continue
    # last resort: seek to end
    try:
        cur = obj.tell()
        obj.seek(0, 2)
        end = obj.tell()
        obj.seek(cur, 0)
        return int(end)
    except Exception:  # noqa: BLE001
        return 0


class OffsetStream:
    """A read-only byte-range *window* over an underlying seekable stream.

    Used to present a single partition of a whole-disk image as if it
    were a standalone volume, so libyal / pytsk3 can open it directly.

    Exposes the full file-like surface libyal expects: read / seek /
    tell / get_size.
    """

    def __init__(self, base: Any, start: int, length: int):
        self._base = base
        self._start = int(start)
        self._length = int(length)
        self._pos = 0

    # ---- file-like API --------------------------------------------------

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            size = self._length - self._pos
        size = max(0, min(size, self._length - self._pos))
        if size == 0:
            return b""
        self._base.seek(self._start + self._pos)
        data = self._base.read(size)
        self._pos += len(data)
        return data

    def seek(self, offset: int, whence: int = 0) -> int:
        if whence == 0:
            self._pos = offset
        elif whence == 1:
            self._pos += offset
        elif whence == 2:
            self._pos = self._length + offset
        self._pos = max(0, min(self._pos, self._length))
        return self._pos

    def tell(self) -> int:
        return self._pos

    def get_size(self) -> int:
        return self._length

    def get_offset(self) -> int:
        return self._pos

    def close(self) -> None:
        # do not close the shared base stream
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def pytsk_img_from_stream(file_like: Any):
    """Wrap any file-like (read/seek + get_size/size) in a pytsk3.Img_Info
    so it can be handed to pytsk3.Volume_Info / FS_Info.

    Returns the Img_Info instance, or raises if pytsk3 is unavailable.
    """
    if not HAS_PYTSK3:
        raise RuntimeError("pytsk3 is not installed")

    size = stream_size(file_like)
    Base = pytsk3.Img_Info

    class _Img(Base):
        def __init__(inner):
            super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

        def close(inner):
            pass

        def read(inner, off, length):
            file_like.seek(off)
            return file_like.read(length)

        def get_size(inner):
            return size

    return _Img()
