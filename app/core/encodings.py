"""Parallel encoding sweep for raw/unallocated streams.

Per the May 2026 review: do NOT trust charset autodetection on raw
streams. Index in ASCII + UTF-8 + UTF-16LE + UTF-16BE + the major
Windows codepages in parallel, deduplicate at the offset level later.
"""
from __future__ import annotations

from typing import Iterator

# Order matters only for cost — UTF-8 is cheap and likely; CJK pages are heavier.
RAW_ENCODINGS: tuple[str, ...] = (
    "ascii",
    "utf-8",
    "utf-16-le",
    "utf-16-be",
    "cp1252",     # Western Windows
    "cp932",      # Japanese (Shift-JIS)
    "cp936",      # Simplified Chinese (GBK)
    "cp949",      # Korean (EUC-KR-like)
    "cp950",      # Traditional Chinese (Big5)
)

# Minimum run-length to emit a candidate string (in characters).
MIN_RUN = 4


def decode_runs(data: bytes, encoding: str, min_run: int = MIN_RUN) -> Iterator[tuple[int, str]]:
    """Yield (byte_offset, decoded_run) for each printable run in `data`
    when interpreted as `encoding`. Falls back silently on decode error.
    """
    try:
        decoded = data.decode(encoding, errors="replace")
    except LookupError:
        return
    buf: list[str] = []
    start = 0
    pos = 0
    for ch in decoded:
        if ch.isprintable() and not ch.isspace() or ch in (" ", "\t"):
            if not buf:
                start = pos
            buf.append(ch)
        else:
            if len(buf) >= min_run:
                yield (start, "".join(buf))
            buf = []
        pos += 1
    if len(buf) >= min_run:
        yield (start, "".join(buf))


def file_level_detect(data: bytes) -> tuple[str, float]:
    """For a *file*-level blob (not raw stream), call charset-normalizer
    if available. Returns (encoding, confidence). Falls back to utf-8.
    """
    try:
        from charset_normalizer import from_bytes
        best = from_bytes(data).best()
        if best is not None:
            return best.encoding, float(getattr(best, "chaos", 0.0))
    except Exception:
        pass
    return "utf-8", 0.0
