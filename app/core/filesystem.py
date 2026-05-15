"""pytsk3 filesystem walker with graceful fallback.

Wraps an EwfHandle (or any file-like) into a TSK Img_Info and walks
each volume's filesystem yielding file records.

If pytsk3 is not installed we still yield a synthetic 'no filesystem
parse' record so the UI is testable.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator

try:
    import pytsk3  # type: ignore
    HAS_PYTSK3 = True
except Exception:  # noqa: BLE001
    HAS_PYTSK3 = False


@dataclass
class FileRec:
    inode: int | None
    path: str
    name: str
    size_bytes: int | None
    mtime: float | None = None
    atime: float | None = None
    ctime: float | None = None
    crtime: float | None = None
    is_allocated: bool = True
    ads_name: str | None = None
    extra: dict = field(default_factory=dict)


class EwfImgInfo:
    """Adapt an EwfHandle (or any file-like) to pytsk3.Img_Info."""

    def __init__(self, ewf_handle):
        if not HAS_PYTSK3:
            raise RuntimeError("pytsk3 is not installed")
        self._h = ewf_handle
        Base = pytsk3.Img_Info

        class _Inner(Base):
            def __init__(inner):
                super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

            def close(inner):
                pass

            def read(inner, off, length):
                self._h.seek(off)
                return self._h.read(length)

            def get_size(inner):
                return self._h.size

        self._inner = _Inner()

    def get(self):
        return self._inner


def walk_image(ewf_handle, max_files: int | None = None) -> Iterator[FileRec]:
    """Walk every filesystem in the image and yield FileRec rows."""
    if not HAS_PYTSK3:
        yield FileRec(
            inode=None, path="/", name="(pytsk3 not installed)",
            size_bytes=ewf_handle.size if ewf_handle else None,
            is_allocated=False,
            extra={"note": "Install pytsk3 to enumerate filesystem contents"},
        )
        return

    img = EwfImgInfo(ewf_handle).get()
    try:
        vol = pytsk3.Volume_Info(img)
    except Exception:  # noqa: BLE001  pytsk3 raises IOError, RuntimeError, OSError
        # No partition table (single-FS image) OR partition-probe error.
        # Fall through to "treat as one filesystem at offset 0".
        try:
            yield from _walk_fs(img, offset=0, max_files=max_files)
        except Exception as fs_exc:  # noqa: BLE001
            yield FileRec(
                inode=None, path="/", name=f"(fs-parse-error: {fs_exc})",
                size_bytes=ewf_handle.size, is_allocated=False,
                extra={"note": "No partition table and FS parse failed at offset 0"},
            )
        return

    count = 0
    for part in vol:
        if part.len <= 0 or (part.flags & pytsk3.TSK_VS_PART_FLAG_UNALLOC):
            continue
        try:
            for rec in _walk_fs(img, offset=part.start * vol.info.block_size,
                                max_files=max_files):
                yield rec
                count += 1
                if max_files and count >= max_files:
                    return
        except Exception as exc:  # noqa: BLE001
            yield FileRec(
                inode=None, path=f"/(partition_err_{part.addr})",
                name=str(exc), size_bytes=None, is_allocated=False,
                extra={"partition_addr": part.addr},
            )


def _walk_fs(img, offset: int, max_files: int | None) -> Iterator[FileRec]:
    fs = pytsk3.FS_Info(img, offset=offset)
    root = fs.open_dir(path="/")
    yield from _walk_dir(fs, root, "/", max_files, {"count": 0})


def _walk_dir(fs, directory, path: str, max_files: int | None, counter: dict) -> Iterator[FileRec]:
    for entry in directory:
        if max_files and counter["count"] >= max_files:
            return
        if not hasattr(entry, "info") or not entry.info.name:
            continue
        name_bytes = entry.info.name.name
        try:
            name = name_bytes.decode("utf-8", errors="replace") if isinstance(name_bytes, bytes) else name_bytes
        except Exception:
            name = repr(name_bytes)
        if name in (".", ".."):
            continue
        full = path.rstrip("/") + "/" + name
        meta = entry.info.meta
        size = meta.size if meta else None
        is_alloc = bool(entry.info.name.flags & getattr(__import__("pytsk3"),
                                                       "TSK_FS_NAME_FLAG_ALLOC", 1))
        counter["count"] += 1
        yield FileRec(
            inode=meta.addr if meta else None,
            path=full, name=name, size_bytes=size,
            mtime=getattr(meta, "mtime", None) if meta else None,
            atime=getattr(meta, "atime", None) if meta else None,
            ctime=getattr(meta, "ctime", None) if meta else None,
            crtime=getattr(meta, "crtime", None) if meta else None,
            is_allocated=is_alloc,
        )
        # Recurse into subdirs
        try:
            if meta and meta.type == __import__("pytsk3").TSK_FS_META_TYPE_DIR:
                sub = entry.as_directory()
                yield from _walk_dir(fs, sub, full, max_files, counter)
        except Exception:
            continue
