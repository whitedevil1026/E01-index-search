"""Filesystem enumeration across an E01 image.

Layered design (Phase 1 complete):

    EwfHandle (raw image)
      -> partition slicing            (OffsetStream per partition)
      -> encryption unlock            (BitLocker / FileVault / LUKS)
      -> VSS snapshot enumeration     (live volume + shadow copies)
      -> filesystem walk:
             primary  : The Sleuth Kit via pytsk3
             fallback : direct libfsntfs (NTFS) / libfsapfs (APFS)

Every layer is a file-like stream so the next layer can consume it.

The walk yields one FileRec at a time (generator) so memory stays
bounded regardless of image size, even with content reading enabled.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Iterator, Optional

from app.core.streams import OffsetStream, pytsk_img_from_stream, stream_size
from app.core import encryption as enc_mod
from app.core import vss as vss_mod

try:
    import pytsk3
    HAS_PYTSK3 = True
except Exception:  # noqa: BLE001
    HAS_PYTSK3 = False

try:
    import pyfsntfs
    HAS_PYFSNTFS = True
except Exception:  # noqa: BLE001
    HAS_PYFSNTFS = False

try:
    import pyfsapfs
    HAS_PYFSAPFS = True
except Exception:  # noqa: BLE001
    HAS_PYFSAPFS = False


# ---- data shapes ----------------------------------------------------------

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
    is_regular: bool = False
    vss_snapshot_id: str | None = None     # set when walking a shadow copy
    fs_backend: str = "tsk"                # tsk / fsntfs / fsapfs
    # Raw file bytes, only populated when walk_image(read_content=True).
    content: bytes | None = None
    extra: dict = field(default_factory=dict)


@dataclass
class VolumeInfo:
    """One partition / volume discovered by scan_volumes()."""
    index: int
    offset: int               # byte offset of the volume in the image
    length: int               # byte length
    description: str = ""     # partition-table description
    encryption: str = ""      # '' / bitlocker / luks / filevault
    has_vss: bool = False
    note: str = ""


# ---- helpers --------------------------------------------------------------

def _filetime_to_unix(ft: int | None) -> float | None:
    """Windows FILETIME (100 ns ticks since 1601) -> Unix seconds."""
    if not ft:
        return None
    try:
        u = ft / 10_000_000.0 - 11644473600.0
        return u if 0 < u < 4_102_444_800 else None
    except Exception:  # noqa: BLE001
        return None


def _apfs_ns_to_unix(ns: int | None) -> float | None:
    """APFS timestamp (ns since Unix epoch) -> Unix seconds."""
    if not ns:
        return None
    try:
        u = ns / 1_000_000_000.0
        return u if 0 < u < 4_102_444_800 else None
    except Exception:  # noqa: BLE001
        return None


def _noop_log(_msg: str) -> None:
    pass


# ---- partition enumeration ------------------------------------------------

def _iter_partitions(ewf_handle) -> list[VolumeInfo]:
    """Return the partitions of the image. If there is no partition
    table, returns a single VolumeInfo spanning the whole image.
    """
    size = stream_size(ewf_handle)
    if not HAS_PYTSK3:
        return [VolumeInfo(0, 0, size, "whole image (pytsk3 missing)")]
    img = pytsk_img_from_stream(ewf_handle)
    try:
        vol = pytsk3.Volume_Info(img)
    except Exception:  # noqa: BLE001
        # no partition table — single filesystem spanning the image
        return [VolumeInfo(0, 0, size, "whole image (no partition table)")]
    parts: list[VolumeInfo] = []
    block = vol.info.block_size or 512
    for part in vol:
        if part.len <= 0:
            continue
        if part.flags & getattr(pytsk3, "TSK_VS_PART_FLAG_UNALLOC", 0):
            continue
        desc = part.desc
        if isinstance(desc, bytes):
            desc = desc.decode("utf-8", errors="replace")
        parts.append(VolumeInfo(
            index=part.addr,
            offset=part.start * block,
            length=part.len * block,
            description=desc or "",
        ))
    if not parts:
        return [VolumeInfo(0, 0, size, "whole image (no usable partitions)")]
    return parts


def scan_volumes(ewf_handle) -> list[VolumeInfo]:
    """Enumerate volumes and probe each for encryption + VSS WITHOUT
    walking the filesystem. The UI calls this first so it can prompt
    the examiner for keys before the (slow) ingest walk.
    """
    parts = _iter_partitions(ewf_handle)
    for vi in parts:
        try:
            vs = OffsetStream(ewf_handle, vi.offset, vi.length)
            vi.encryption = enc_mod.detect_encryption(vs)
            # VSS lives inside the *decrypted* volume; if encrypted we
            # cannot probe VSS until it is unlocked, so only probe VSS
            # on cleartext volumes here.
            if not vi.encryption:
                vi.has_vss = vss_mod.has_vss(vs)
        except Exception as exc:  # noqa: BLE001
            vi.note = f"probe error: {exc}"
    return parts


# ---- top-level walk -------------------------------------------------------

def walk_image(ewf_handle, max_files: int | None = None,
               read_content: bool = False,
               max_content_bytes: int = 32 * 1024 * 1024,
               credentials: Optional[enc_mod.Credentials] = None,
               include_vss: bool = False,
               vss_dedup: bool = True,
               log: Optional[Callable[[str], None]] = None) -> Iterator[FileRec]:
    """Walk every filesystem in the image.

    credentials   — applied to any encrypted volume found. If None (or
                    unlock fails) the volume is tagged "encrypted, no
                    usable text" and skipped.
    include_vss   — also walk Volume Shadow Copy snapshots.
    vss_dedup     — skip snapshot files identical to one already seen.
    log           — optional callback for human-readable progress lines.
    """
    log = log or _noop_log
    if not HAS_PYTSK3 and not HAS_PYFSNTFS:
        yield FileRec(
            inode=None, path="/", name="(no filesystem library installed)",
            size_bytes=stream_size(ewf_handle), is_allocated=False,
            extra={"note": "Install pytsk3 (and/or libfsntfs-python)"},
        )
        return

    counter = {"count": 0}
    dedup = vss_mod.SnapshotDedup() if (include_vss and vss_dedup) else None

    parts = _iter_partitions(ewf_handle)
    log(f"partitions found: {len(parts)}")

    for vi in parts:
        if max_files and counter["count"] >= max_files:
            return
        label = f"vol{vi.index}"
        vstream = OffsetStream(ewf_handle, vi.offset, vi.length)

        # ---- encryption ------------------------------------------------
        volume_stream = vstream
        try:
            kind = enc_mod.detect_encryption(vstream)
        except Exception:  # noqa: BLE001
            kind = ""
        if kind:
            human = enc_mod.human_name(kind)
            log(f"{label}: {human}-encrypted volume detected")
            if credentials is None or credentials.is_empty():
                log(f"{label}: no key supplied — tagged 'encrypted, no usable text'")
                yield FileRec(
                    inode=None, path=f"/{label}",
                    name=f"({human} encrypted — no key supplied)",
                    size_bytes=vi.length, is_allocated=False,
                    extra={"encryption": kind, "volume": label},
                )
                continue
            try:
                dec = enc_mod.unlock_volume(vstream, kind, credentials)
                volume_stream = dec
                log(f"{label}: {human} volume unlocked")
            except enc_mod.EncryptionError as exc:
                log(f"{label}: unlock FAILED — {exc}")
                yield FileRec(
                    inode=None, path=f"/{label}",
                    name=f"({human} encrypted — unlock failed: {exc})",
                    size_bytes=vi.length, is_allocated=False,
                    extra={"encryption": kind, "volume": label,
                           "unlock_error": str(exc)},
                )
                continue

        # ---- VSS snapshots --------------------------------------------
        snapshots = []
        if include_vss:
            try:
                if vss_mod.has_vss(volume_stream):
                    snapshots = vss_mod.open_snapshots(volume_stream)
                    log(f"{label}: {len(snapshots)} VSS snapshot(s)")
            except Exception as exc:  # noqa: BLE001
                log(f"{label}: VSS probe error — {exc}")

        # ---- walk the live volume -------------------------------------
        for rec in _walk_volume(volume_stream, label, max_files, counter,
                                read_content, max_content_bytes, log,
                                snapshot_id=None, dedup=dedup):
            yield rec
            if max_files and counter["count"] >= max_files:
                return

        # ---- walk each VSS snapshot -----------------------------------
        for snap in snapshots:
            if max_files and counter["count"] >= max_files:
                return
            sid = f"vss{snap.index}"
            ts = snap.creation_time or "?"
            log(f"{label}/{sid}: walking shadow copy from {ts}")
            for rec in _walk_volume(snap, f"{label}/{sid}", max_files, counter,
                                    read_content, max_content_bytes, log,
                                    snapshot_id=sid, dedup=dedup):
                yield rec
                if max_files and counter["count"] >= max_files:
                    return

    if dedup is not None:
        s = dedup.stats()
        log(f"VSS dedup: {s['unique_files']} unique, "
            f"{s['duplicate_files_skipped']} duplicates skipped")


# ---- per-volume walk: pytsk3 primary, direct libyal fallback --------------

def _walk_volume(stream, label: str, max_files: int | None, counter: dict,
                 read_content: bool, max_content_bytes: int,
                 log: Callable[[str], None],
                 snapshot_id: str | None = None,
                 dedup: Optional[vss_mod.SnapshotDedup] = None
                 ) -> Iterator[FileRec]:
    """Walk one volume stream. Tries The Sleuth Kit first; on failure
    falls back to direct libfsntfs / libfsapfs.
    """
    # --- attempt 1: pytsk3 ---------------------------------------------
    if HAS_PYTSK3:
        try:
            img = pytsk_img_from_stream(stream)
            fs = pytsk3.FS_Info(img, offset=0)
            yield from _walk_dir_tsk(fs, fs.open_dir(path="/"), "",
                                     max_files, counter, read_content,
                                     max_content_bytes, snapshot_id, dedup)
            return
        except Exception as exc:  # noqa: BLE001
            log(f"{label}: TSK could not parse this volume ({exc}); "
                f"trying direct filesystem libraries")

    # --- attempt 2: direct libfsntfs -----------------------------------
    if HAS_PYFSNTFS:
        try:
            stream.seek(0)
            if pyfsntfs.check_volume_signature_file_object(stream):
                stream.seek(0)
                log(f"{label}: walking via direct libfsntfs")
                yield from _walk_fsntfs(stream, max_files, counter,
                                        read_content, max_content_bytes,
                                        snapshot_id, dedup)
                return
        except Exception as exc:  # noqa: BLE001
            log(f"{label}: libfsntfs failed ({exc})")

    # --- attempt 3: direct libfsapfs -----------------------------------
    if HAS_PYFSAPFS:
        try:
            stream.seek(0)
            if pyfsapfs.check_container_signature_file_object(stream):
                stream.seek(0)
                log(f"{label}: walking via direct libfsapfs")
                yield from _walk_fsapfs(stream, max_files, counter,
                                        read_content, max_content_bytes,
                                        snapshot_id, dedup)
                return
        except Exception as exc:  # noqa: BLE001
            log(f"{label}: libfsapfs failed ({exc})")

    yield FileRec(
        inode=None, path=f"/{label}", name="(no filesystem parser succeeded)",
        size_bytes=None, is_allocated=False, vss_snapshot_id=snapshot_id,
        extra={"volume": label},
    )


# ---- The Sleuth Kit walk --------------------------------------------------

def _dedup_skip(dedup, rec_path, size, mtime) -> bool:
    """Return True if this file should be skipped as a VSS duplicate."""
    if dedup is None:
        return False
    key = f"{rec_path}|{size}|{mtime}"
    return not dedup.is_new(key)


def _walk_dir_tsk(fs, directory, path: str, max_files: int | None,
                  counter: dict, read_content: bool, max_content_bytes: int,
                  snapshot_id: str | None,
                  dedup: Optional[vss_mod.SnapshotDedup]) -> Iterator[FileRec]:
    type_reg = getattr(pytsk3, "TSK_FS_META_TYPE_REG", 1)
    type_dir = getattr(pytsk3, "TSK_FS_META_TYPE_DIR", 2)
    alloc_flag = getattr(pytsk3, "TSK_FS_NAME_FLAG_ALLOC", 1)
    for entry in directory:
        if max_files and counter["count"] >= max_files:
            return
        if not hasattr(entry, "info") or not entry.info.name:
            continue
        name_bytes = entry.info.name.name
        try:
            name = name_bytes.decode("utf-8", errors="replace") \
                if isinstance(name_bytes, bytes) else name_bytes
        except Exception:  # noqa: BLE001
            name = repr(name_bytes)
        if name in (".", ".."):
            continue
        full = path.rstrip("/") + "/" + name
        meta = entry.info.meta
        size = meta.size if meta else None
        is_alloc = bool(entry.info.name.flags & alloc_flag)
        is_reg = bool(meta and meta.type == type_reg)
        mtime = getattr(meta, "mtime", None) if meta else None

        if is_reg and _dedup_skip(dedup, full, size, mtime):
            continue
        counter["count"] += 1

        content = None
        if read_content and is_reg and is_alloc and size and size > 0:
            read_n = min(size, max_content_bytes)
            try:
                content = entry.read_random(0, read_n)
            except Exception:  # noqa: BLE001
                content = None

        yield FileRec(
            inode=meta.addr if meta else None,
            path=full, name=name, size_bytes=size,
            mtime=mtime,
            atime=getattr(meta, "atime", None) if meta else None,
            ctime=getattr(meta, "ctime", None) if meta else None,
            crtime=getattr(meta, "crtime", None) if meta else None,
            is_allocated=is_alloc, is_regular=is_reg,
            vss_snapshot_id=snapshot_id, fs_backend="tsk",
            content=content,
        )
        try:
            if meta and meta.type == type_dir:
                yield from _walk_dir_tsk(fs, entry.as_directory(), full,
                                         max_files, counter, read_content,
                                         max_content_bytes, snapshot_id, dedup)
        except Exception:  # noqa: BLE001
            continue


# ---- direct libfsntfs walk ------------------------------------------------

_NTFS_DIR_FLAG = 0x10000000   # libfsntfs file-attribute directory flag


def _walk_fsntfs(stream, max_files: int | None, counter: dict,
                 read_content: bool, max_content_bytes: int,
                 snapshot_id: str | None,
                 dedup: Optional[vss_mod.SnapshotDedup]) -> Iterator[FileRec]:
    vol = pyfsntfs.volume()
    vol.open_file_object(stream)
    root = vol.get_root_directory()
    yield from _walk_fsntfs_dir(root, "", max_files, counter, read_content,
                                max_content_bytes, snapshot_id, dedup)


def _walk_fsntfs_dir(entry, path: str, max_files: int | None, counter: dict,
                     read_content: bool, max_content_bytes: int,
                     snapshot_id: str | None,
                     dedup: Optional[vss_mod.SnapshotDedup]) -> Iterator[FileRec]:
    try:
        n_sub = entry.get_number_of_sub_file_entries()
    except Exception:  # noqa: BLE001
        return
    for i in range(n_sub):
        if max_files and counter["count"] >= max_files:
            return
        try:
            sub = entry.get_sub_file_entry(i)
        except Exception:  # noqa: BLE001
            continue
        try:
            name = sub.get_name() or ""
        except Exception:  # noqa: BLE001
            name = ""
        if name in ("", ".", ".."):
            continue
        full = path.rstrip("/") + "/" + name

        is_dir = False
        try:
            is_dir = bool(sub.has_directory_entries_index())
        except Exception:  # noqa: BLE001
            try:
                is_dir = bool(sub.get_file_attribute_flags() & _NTFS_DIR_FLAG)
            except Exception:  # noqa: BLE001
                is_dir = False
        size = None
        try:
            size = sub.get_size()
        except Exception:  # noqa: BLE001
            pass
        is_alloc = True
        try:
            is_alloc = bool(sub.is_allocated())
        except Exception:  # noqa: BLE001
            pass
        mtime = _filetime_to_unix(_safe_call(sub, "get_modification_time_as_integer"))

        if not is_dir and _dedup_skip(dedup, full, size, mtime):
            continue
        counter["count"] += 1

        content = None
        if read_content and not is_dir and is_alloc and size and size > 0:
            read_n = min(size, max_content_bytes)
            try:
                sub.seek_offset(0, 0)
                content = sub.read_buffer(read_n)
            except Exception:  # noqa: BLE001
                content = None

        inode = None
        try:
            inode = int(sub.get_file_reference()) & 0xFFFFFFFFFFFF
        except Exception:  # noqa: BLE001
            pass

        yield FileRec(
            inode=inode, path=full, name=name, size_bytes=size,
            mtime=mtime,
            atime=_filetime_to_unix(_safe_call(sub, "get_access_time_as_integer")),
            ctime=_filetime_to_unix(_safe_call(sub, "get_entry_modification_time_as_integer")),
            crtime=_filetime_to_unix(_safe_call(sub, "get_creation_time_as_integer")),
            is_allocated=is_alloc, is_regular=not is_dir,
            vss_snapshot_id=snapshot_id, fs_backend="fsntfs",
            content=content,
        )
        if is_dir:
            yield from _walk_fsntfs_dir(sub, full, max_files, counter,
                                        read_content, max_content_bytes,
                                        snapshot_id, dedup)


# ---- direct libfsapfs walk ------------------------------------------------

def _walk_fsapfs(stream, max_files: int | None, counter: dict,
                 read_content: bool, max_content_bytes: int,
                 snapshot_id: str | None,
                 dedup: Optional[vss_mod.SnapshotDedup]) -> Iterator[FileRec]:
    container = pyfsapfs.container()
    container.open_file_object(stream)
    try:
        n_vol = container.get_number_of_volumes()
    except Exception:  # noqa: BLE001
        n_vol = 0
    for vi in range(n_vol):
        if max_files and counter["count"] >= max_files:
            return
        try:
            volume = container.get_volume(vi)
        except Exception:  # noqa: BLE001
            continue
        try:
            root = volume.get_root_directory()
        except Exception:  # noqa: BLE001
            continue
        vname = ""
        try:
            vname = volume.get_name() or ""
        except Exception:  # noqa: BLE001
            pass
        base = f"/{vname}" if vname else ""
        yield from _walk_fsapfs_dir(root, base, max_files, counter,
                                    read_content, max_content_bytes,
                                    snapshot_id, dedup)


def _walk_fsapfs_dir(entry, path: str, max_files: int | None, counter: dict,
                     read_content: bool, max_content_bytes: int,
                     snapshot_id: str | None,
                     dedup: Optional[vss_mod.SnapshotDedup]) -> Iterator[FileRec]:
    try:
        n_sub = entry.get_number_of_sub_file_entries()
    except Exception:  # noqa: BLE001
        return
    for i in range(n_sub):
        if max_files and counter["count"] >= max_files:
            return
        try:
            sub = entry.get_sub_file_entry(i)
        except Exception:  # noqa: BLE001
            continue
        try:
            name = sub.get_name() or ""
        except Exception:  # noqa: BLE001
            name = ""
        if name in ("", ".", ".."):
            continue
        full = path.rstrip("/") + "/" + name

        is_dir = False
        try:
            is_dir = sub.get_number_of_sub_file_entries() > 0
        except Exception:  # noqa: BLE001
            pass
        # APFS reports type more reliably via the entry; an empty
        # directory still needs detecting — fall back to the size test.
        size = None
        try:
            size = sub.get_size()
        except Exception:  # noqa: BLE001
            pass
        mtime = _apfs_ns_to_unix(_safe_call(sub, "get_modification_time_as_integer"))

        if not is_dir and _dedup_skip(dedup, full, size, mtime):
            continue
        counter["count"] += 1

        content = None
        if read_content and not is_dir and size and size > 0:
            read_n = min(size, max_content_bytes)
            try:
                sub.seek_offset(0, 0)
                content = sub.read_buffer(read_n)
            except Exception:  # noqa: BLE001
                content = None

        inode = None
        try:
            inode = int(sub.get_identifier())
        except Exception:  # noqa: BLE001
            pass

        yield FileRec(
            inode=inode, path=full, name=name, size_bytes=size,
            mtime=mtime,
            atime=_apfs_ns_to_unix(_safe_call(sub, "get_access_time_as_integer")),
            ctime=_apfs_ns_to_unix(_safe_call(sub, "get_inode_change_time_as_integer")),
            crtime=_apfs_ns_to_unix(_safe_call(sub, "get_creation_time_as_integer")),
            is_allocated=True, is_regular=not is_dir,
            vss_snapshot_id=snapshot_id, fs_backend="fsapfs",
            content=content,
        )
        if is_dir:
            yield from _walk_fsapfs_dir(sub, full, max_files, counter,
                                        read_content, max_content_bytes,
                                        snapshot_id, dedup)


def _safe_call(obj, method: str):
    fn = getattr(obj, method, None)
    if fn is None:
        return None
    try:
        return fn()
    except Exception:  # noqa: BLE001
        return None
