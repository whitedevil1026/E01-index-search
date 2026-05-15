"""MD5 + SHA-256 + TLSH triple hash.

MD5 is cryptographically broken but still required by NSRL and most
evidence SOPs. TLSH gives fuzzy/locality similarity. ssdeep deferred
(legacy, NSRL backward-compat — try2).
"""
from __future__ import annotations

import hashlib
from typing import BinaryIO

try:
    import tlsh as _tlsh  # python-tlsh
    HAS_TLSH = True
except Exception:  # noqa: BLE001
    HAS_TLSH = False


def hash_stream(stream: BinaryIO, chunk: int = 1 << 20) -> dict[str, str | None]:
    md5 = hashlib.md5()
    sha = hashlib.sha256()
    tl = _tlsh.Tlsh() if HAS_TLSH else None
    size = 0
    while True:
        buf = stream.read(chunk)
        if not buf:
            break
        size += len(buf)
        md5.update(buf)
        sha.update(buf)
        if tl is not None:
            tl.update(buf)
    tlsh_digest: str | None = None
    if tl is not None and size >= 50:
        try:
            tl.final()
            tlsh_digest = tl.hexdigest() or None
        except Exception:
            tlsh_digest = None
    return {
        "md5": md5.hexdigest(),
        "sha256": sha.hexdigest(),
        "tlsh": tlsh_digest,
        "size_bytes": size,
    }


def hash_bytes(data: bytes) -> dict[str, str | None]:
    import io
    return hash_stream(io.BytesIO(data))


def tlsh_distance(a: str, b: str) -> int | None:
    if not HAS_TLSH or not a or not b:
        return None
    try:
        return int(_tlsh.diff(a, b))
    except Exception:
        return None
