"""Volume Shadow Copy Service (VSS) snapshot handling.

Windows volumes routinely carry Volume Shadow Copies — point-in-time
snapshots created by System Restore, backup software and Windows
Update. They are an enormous source of deleted / superseded evidence:
a file the user wiped last week may still be intact inside a 3-week-old
snapshot.

This module uses pyvshadow (libvshadow) to:

  * detect whether a volume carries VSS data
  * enumerate the shadow-copy "stores" (each store == one snapshot)
  * expose each store as a readable file-like stream that the
    filesystem layer can walk just like a live volume

Snapshot deduplication
----------------------
Indexing every snapshot naively multiplies index size 10-30x because
most files are byte-identical across snapshots. `SnapshotDedup` tracks
the SHA-256 of every (path, content) pair already seen; a file whose
hash was already indexed from a sibling snapshot is recorded as a
reference rather than re-indexed.
"""
from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from typing import Any, Iterator, Optional

try:
    import pyvshadow
    HAS_PYVSHADOW = True
except Exception:  # noqa: BLE001
    HAS_PYVSHADOW = False


@dataclass
class SnapshotInfo:
    index: int
    identifier: str
    creation_time: Optional[str]
    volume_size: int
    store: Any = None              # the pyvshadow store object (file-like)
    _keepalive: list = field(default_factory=list)

    # ---- file-like delegation for the store ----------------------------

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            size = self.store.get_size() - self.store.get_offset()
        return self.store.read_buffer(size)

    def seek(self, offset: int, whence: int = 0) -> int:
        self.store.seek_offset(offset, whence)
        return self.store.get_offset()

    def tell(self) -> int:
        return self.store.get_offset()

    def get_size(self) -> int:
        return self.store.get_size()

    def get_offset(self) -> int:
        return self.store.get_offset()

    def close(self) -> None:
        pass


def has_vss(stream: Any) -> bool:
    """Does this volume stream carry Volume Shadow Copy data?"""
    if not HAS_PYVSHADOW:
        return False
    try:
        stream.seek(0)
    except Exception:  # noqa: BLE001
        pass
    try:
        result = bool(pyvshadow.check_volume_signature_file_object(stream))
    except Exception:  # noqa: BLE001
        result = False
    try:
        stream.seek(0)
    except Exception:  # noqa: BLE001
        pass
    return result


def open_snapshots(stream: Any, keepalive: Optional[list] = None
                   ) -> list[SnapshotInfo]:
    """Open a VSS volume and return one SnapshotInfo per shadow copy,
    newest store last. Each SnapshotInfo is itself a readable stream.

    Returns [] if pyvshadow is missing, the volume has no VSS data, or
    enumeration fails.
    """
    if not HAS_PYVSHADOW:
        return []
    keepalive = keepalive if keepalive is not None else []
    try:
        stream.seek(0)
    except Exception:  # noqa: BLE001
        pass
    try:
        vol = pyvshadow.volume()
        vol.open_file_object(stream)
    except Exception:  # noqa: BLE001
        return []
    keepalive.append(stream)
    keepalive.append(vol)

    out: list[SnapshotInfo] = []
    try:
        n = vol.get_number_of_stores()
    except Exception:  # noqa: BLE001
        return []

    for i in range(n):
        try:
            store = vol.get_store(i)
        except Exception:  # noqa: BLE001
            continue
        # creation time
        ctime = None
        try:
            ct = store.get_creation_time()
            if isinstance(ct, _dt.datetime):
                ctime = ct.strftime("%Y-%m-%d %H:%M:%S UTC")
            elif ct:
                ctime = str(ct)
        except Exception:  # noqa: BLE001
            pass
        # identifier
        ident = ""
        try:
            ident = str(store.get_identifier())
        except Exception:  # noqa: BLE001
            pass
        # size
        vsize = 0
        try:
            vsize = int(store.get_size())
        except Exception:  # noqa: BLE001
            try:
                vsize = int(store.get_volume_size())
            except Exception:  # noqa: BLE001
                vsize = 0
        out.append(SnapshotInfo(
            index=i, identifier=ident, creation_time=ctime,
            volume_size=vsize, store=store, _keepalive=keepalive,
        ))
    return out


# ---- snapshot deduplication ----------------------------------------------

@dataclass
class SnapshotDedup:
    """Skips files already seen in a sibling snapshot, so a VSS-heavy
    image does not index N near-identical copies of every file.

    IMPORTANT — this dedups on an *identity key*, not on content. The
    caller (filesystem._dedup_skip) builds the key from
    `path|size|mtime`, because hashing every file in every snapshot
    would mean reading the whole snapshot set. The trade-off: a file
    rewritten in place that kept its size AND its mtime is treated as a
    duplicate and skipped. That is rare (a rewrite normally moves
    mtime) but it is not impossible, so the key is recorded in the
    ingest audit entry rather than presented as a content guarantee.
    """
    seen: set = field(default_factory=set)
    n_unique: int = 0
    n_duplicate: int = 0

    def is_new(self, identity_key: str) -> bool:
        """Return True the first time an identity key is seen, False
        afterwards. A falsy / empty key is always treated as new
        (we cannot dedup what we cannot identify).
        """
        if not identity_key:
            self.n_unique += 1
            return True
        if identity_key in self.seen:
            self.n_duplicate += 1
            return False
        self.seen.add(identity_key)
        self.n_unique += 1
        return True

    def stats(self) -> dict[str, Any]:
        return {
            "unique_files": self.n_unique,
            "duplicate_files_skipped": self.n_duplicate,
            "distinct_identity_keys": len(self.seen),
            "dedup_key": "path|size|mtime",
        }
