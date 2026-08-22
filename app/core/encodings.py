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
from functools import lru_cache
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

# Named presets the examiner picks from in the Ingest tab. Each extra
# encoding is a real cost on a multi-hundred-GB image, and the CJK code
# pages are mostly noise unless the case actually involves CJK content,
# so the set is a per-case decision rather than a fixed constant.
#
# Measured on a 150 MB E01 (see PROJECT_HANDOFF §9):
#   ascii_utf16  ~15.7 MB/s     windows  ~12.3 MB/s     full  ~6.7 MB/s
ENCODING_SETS: dict[str, tuple[str, ...]] = {
    "ascii_utf16": ("ascii", "utf-16-le", "utf-16-be"),
    "windows": ("ascii", "utf-16-le", "utf-16-be", "utf-8", "cp1252"),
    "full": RAW_ENCODINGS,
}

ENCODING_SET_LABELS: dict[str, str] = {
    "ascii_utf16": "ASCII + UTF-16 (fastest)",
    "windows": "Windows / Western (recommended)",
    "full": "Full incl. CJK code pages (slowest)",
}

DEFAULT_ENCODING_SET = "windows"

# Code pages that are ASCII supersets. A run they produce containing no
# non-ASCII character is byte-for-byte what the `ascii` pass already
# yielded, so indexing it again is pure duplication — it inflates the
# index and, under a per-encoding budget, crowds out the genuinely
# different text the code page exists to find.
ASCII_SUPERSET_ENCODINGS: frozenset[str] = frozenset({
    "utf-8", "cp1252", "cp932", "cp936", "cp949", "cp950",
})


def resolve_encodings(name_or_tuple) -> tuple[str, ...]:
    """Accept a preset name or an explicit tuple; always return a tuple."""
    if isinstance(name_or_tuple, str):
        return ENCODING_SETS.get(name_or_tuple, ENCODING_SETS[DEFAULT_ENCODING_SET])
    return tuple(name_or_tuple) if name_or_tuple else RAW_ENCODINGS

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


# One printable character inside an already-decoded string: anything
# that is not a control char and not the replacement char.
_PRINTABLE = "[^\\x00-\\x08\\x0b-\\x1f\\x7f\\ufffd]"

# printable run inside an already-decoded string
_STR_RUN = re.compile(_PRINTABLE + "{%d,}")

# NOTE — do not "optimise" the ASCII-duplicate filter into the pattern.
# The obvious form, `PRINT* [non-ascii] PRINT*`, is catastrophically
# backtracking: on a printable run with no high character the engine
# retries every split point, which is quadratic in the run length.
# Measured on a single pure-ASCII run: 2,000 chars 26 ms, 4,000 chars
# 108 ms, 8,000 chars 412 ms — against ~0 ms for matching the run and
# calling str.isascii(), which is a C-level O(n) scan. The filter stays
# in the caller.
@lru_cache(maxsize=64)
def _str_run_regex(min_run: int) -> re.Pattern:
    """Compiled printable-run pattern, cached per min_run."""
    return re.compile(_STR_RUN.pattern % min_run)


def decode_runs(data: bytes, encoding: str,
                min_run: int = MIN_RUN,
                require_nonascii: bool = False) -> Iterator[tuple[int, str]]:
    """Yield (offset, printable_run) for `data` interpreted as `encoding`.

    `offset` is a byte offset for the raw-byte encodings (ascii,
    utf-16le, utf-16be) and an approximate offset for the decode-based
    encodings — accurate enough for page-boundary de-duplication.

    `require_nonascii` yields only runs containing a non-ASCII
    character. For an ASCII-superset code page every other run is a
    verbatim duplicate of what the `ascii` pass already produced, so
    dropping them here keeps the caller from re-indexing the same text
    once per code page. Ignored for the raw-byte encodings, whose runs
    are ASCII by construction.
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
    pattern = _str_run_regex(min_run)
    if require_nonascii:
        for m in pattern.finditer(decoded):
            run = m.group()
            if not run.isascii():       # C-level, O(n), no backtracking
                yield (m.start(), run)
        return
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
