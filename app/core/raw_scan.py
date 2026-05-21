"""Raw-stream scanning — paged multi-encoding string sweep.

This is the Phase 2 "parallel encoding indexing for raw streams" item:
unallocated space, file slack and otherwise un-parsed regions of an
image still hold enormous amounts of recoverable text (deleted
documents, chat fragments, browser cache, registry remnants). The
filesystem walk never sees that data — only a raw byte scan does.

Model
-----
The image is read in fixed pages (default 16 MiB) with an overlap
*margin* (default 4 KiB) so a string or pattern straddling a page
boundary is still captured — the same `sbuf` design bulk_extractor
uses. To avoid double-counting, a match is only kept if it *starts*
within the non-margin part of its page.

Each page is decoded under several encodings in parallel:
ASCII, UTF-8, UTF-16LE, UTF-16BE, CP1252 and the major CJK code
pages. Raw bytes have no reliable charset, so indexing under all of
them in parallel — rather than guessing one — is the only defensible
approach.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterator, Optional

from app.core.encodings import RAW_ENCODINGS, decode_runs


DEFAULT_PAGE = 16 * 1024 * 1024     # 16 MiB sbuf page
DEFAULT_MARGIN = 4096               # overlap so boundary matches survive

# Minimum string length for the raw sweep. The `strings` default is 4,
# but for *indexing* a higher floor cuts an order of magnitude of
# random-byte noise while still catching real words / identifiers.
MIN_RUN = 6

# Cap on text harvested per page. The page index doc is capped at ~1 MB
# anyway, so there is no point extracting tens of MB of strings from a
# pathologically text-dense page — stop early.
MAX_PAGE_TEXT = 1_400_000


@dataclass
class RawPage:
    offset: int                     # absolute byte offset of the page
    length: int                     # bytes in the non-margin body
    data: bytes                     # body + margin


def iter_pages(stream: Any, page_size: int = DEFAULT_PAGE,
               margin: int = DEFAULT_MARGIN,
               cancel_cb: Optional[Callable[[], bool]] = None
               ) -> Iterator[RawPage]:
    """Yield RawPage objects covering the whole stream.

    Each page carries `page_size` body bytes plus up to `margin` extra
    overlap bytes from the next page.
    """
    try:
        size = stream.get_size()
    except Exception:  # noqa: BLE001
        size = getattr(stream, "size", 0)
    if not size:
        return
    offset = 0
    while offset < size:
        if cancel_cb and cancel_cb():
            return
        body = min(page_size, size - offset)
        want = min(page_size + margin, size - offset)
        stream.seek(offset)
        data = stream.read(want)
        if not data:
            break
        yield RawPage(offset=offset, length=body, data=data)
        offset += page_size


@dataclass
class StringHit:
    page_offset: int
    rel_offset: int        # offset within the page body
    encoding: str
    text: str

    @property
    def abs_offset(self) -> int:
        return self.page_offset + self.rel_offset


@dataclass
class RawScanStats:
    pages: int = 0
    bytes_scanned: int = 0
    strings: int = 0
    per_encoding: dict = field(default_factory=dict)


def scan_page_strings(page: RawPage, encodings: tuple[str, ...] = RAW_ENCODINGS,
                      min_run: int = MIN_RUN) -> list[StringHit]:
    """Extract printable strings from one page under every encoding,
    with offset metadata. Use when per-string offsets are needed.

    A run is only kept if it starts within the page body — runs
    starting inside the overlap margin belong to the next page.
    """
    hits: list[StringHit] = []
    for enc in encodings:
        for rel, run in decode_runs(page.data, enc, min_run=min_run):
            if rel >= page.length:
                continue
            hits.append(StringHit(page.offset, rel, enc, run))
    return hits


def scan_page_text(page: RawPage, encodings: tuple[str, ...] = RAW_ENCODINGS,
                   min_run: int = MIN_RUN,
                   max_chars: int = MAX_PAGE_TEXT) -> tuple[str, int]:
    """Extract printable strings from one page and return them already
    joined into a single indexable blob — no per-string objects.

    Stops once `max_chars` of text has been collected (the page index
    doc is capped anyway). Returns (joined_text, n_strings).
    """
    parts: list[str] = []
    total = 0
    n = 0
    body_len = page.length
    for enc in encodings:
        for rel, run in decode_runs(page.data, enc, min_run=min_run):
            if rel >= body_len:
                continue
            parts.append(run)
            n += 1
            total += len(run) + 1
            if total >= max_chars:
                return "\n".join(parts), n
    return "\n".join(parts), n


def raw_string_sweep(stream: Any, *,
                     page_size: int = DEFAULT_PAGE,
                     margin: int = DEFAULT_MARGIN,
                     encodings: tuple[str, ...] = RAW_ENCODINGS,
                     min_run: int = MIN_RUN,
                     on_page: Optional[Callable[[RawPage, str, int], None]] = None,
                     progress_cb: Optional[Callable[[int, int], None]] = None,
                     cancel_cb: Optional[Callable[[], bool]] = None
                     ) -> RawScanStats:
    """Sweep an entire image stream, extracting strings page by page.

    For each page `on_page(page, joined_text, n_strings)` is invoked so
    the caller can index the text immediately and free the page —
    memory stays bounded to one page at a time.
    """
    stats = RawScanStats()
    try:
        total = stream.get_size()
    except Exception:  # noqa: BLE001
        total = getattr(stream, "size", 0)

    for page in iter_pages(stream, page_size, margin, cancel_cb):
        if cancel_cb and cancel_cb():
            break
        text, n = scan_page_text(page, encodings, min_run)
        stats.pages += 1
        stats.bytes_scanned += page.length
        stats.strings += n
        if on_page is not None:
            on_page(page, text, n)
        if progress_cb is not None and total:
            progress_cb(page.offset + page.length, total)
    return stats
