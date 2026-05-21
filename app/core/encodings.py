"""Parallel multi-encoding string extraction for raw streams.

Per the May 2026 review: do NOT trust charset autodetection on raw
streams. Extract printable strings under several encodings in
parallel and index them all.

Performance
-----------
String extraction here is **regex-based**, not a Python character
loop. A char-by-char scan of a 16 MiB page is ~16 M Python iterations;
over a 100 GB image across 9 encodings that is hundreds of billions of
iterations — unusable. `re` runs in C, so:

  * ASCII / UTF-16LE / UTF-16BE  -> a regex straight over the raw bytes
  * UTF-8 / CP125x / CJK codepages -> one C-level decode, then a
    C-level regex over the decoded string

This makes a full-image sweep practical.
"""
from __future__ import annotations

import re
from typing import Iterator


# Encodings swept by default. The first three are matched directly on
# raw bytes (fastest); the rest are decode-then-regex.
RAW_ENCODINGS: tuple[str, ...] = (
    "ascii",
    "utf-16-le",
    "utf-16-be",
    "utf-8",
    "cp1252",     # Western Windows
    "cp932",      # Japanese (Shift-JIS)
    "cp936",      # Simplified Chinese (GBK)
    "cp949",      # Korean
    "cp950",      # Traditional Chinese (Big5)
)

# Fast subset — ASCII + UTF-16 catch the overwhelming majority of
# useful text on Windows images at a fraction of the cost.
FAST_ENCODINGS: tuple[str, ...] = ("ascii", "utf-16-le", "utf-16-be")

MIN_RUN = 4

# printable ASCII byte (incl. tab); excludes other control bytes
_ASCII_BYTE = rb"[\x09\x20-\x7e]"


def _ascii_regex(min_run: int) -> re.Pattern:
    return re.compile(_ASCII_BYTE + b"{" + str(min_run).encode() + b",}")


def _utf16le_regex(min_run: int) -> re.Pattern:
    # printable ASCII char followed by a NUL low byte
    return re.compile(b"(?:" + _ASCII_BYTE + rb"\x00){" +
                      str(min_run).encode() + b",}")


def _utf16be_regex(min_run: int) -> re.Pattern:
    return re.compile(b"(?:\\x00" + _ASCII_BYTE + b"){" +
                      str(min_run).encode() + b",}")


# printable run inside an already-decoded string: anything that is not
# a control char and not the replacement char
_STR_RUN = re.compile(r"[^\x00-\x08\x0b-\x1f\x7f�]{%d,}")


def decode_runs(data: bytes, encoding: str,
                min_run: int = MIN_RUN) -> Iterator[tuple[int, str]]:
    """Yield (offset, printable_run) for `data` interpreted as `encoding`.

    `offset` is a byte offset for the raw-byte encodings (ascii,
    utf-16le, utf-16be) and an approximate offset for the decode-based
    encodings — accurate enough for page-boundary de-duplication.
    """
    enc = encoding.lower().replace("_", "-")

    if enc in ("ascii", "us-ascii"):
        rx = _ascii_regex(min_run)
        for m in rx.finditer(data):
            yield (m.start(), m.group().decode("ascii", errors="replace"))
        return

    if enc in ("utf-16-le", "utf-16le", "utf16-le"):
        rx = _utf16le_regex(min_run)
        for m in rx.finditer(data):
            raw = m.group()
            # drop the NUL high bytes
            text = raw[0::2].decode("ascii", errors="replace")
            yield (m.start(), text)
        return

    if enc in ("utf-16-be", "utf-16be", "utf16-be"):
        rx = _utf16be_regex(min_run)
        for m in rx.finditer(data):
            raw = m.group()
            text = raw[1::2].decode("ascii", errors="replace")
            yield (m.start(), text)
        return

    # decode-then-regex for UTF-8 / CP125x / CJK code pages
    try:
        decoded = data.decode(enc, errors="replace")
    except LookupError:
        return
    except Exception:  # noqa: BLE001
        return
    pattern = re.compile(_STR_RUN.pattern % min_run)
    for m in pattern.finditer(decoded):
        yield (m.start(), m.group())


def file_level_detect(data: bytes) -> tuple[str, float]:
    """For a *file*-level blob (not a raw stream), call
    charset-normalizer if available. Returns (encoding, confidence).
    """
    try:
        from charset_normalizer import from_bytes
        best = from_bytes(data).best()
        if best is not None:
            return best.encoding, float(getattr(best, "chaos", 0.0))
    except Exception:  # noqa: BLE001
        pass
    return "utf-8", 0.0
