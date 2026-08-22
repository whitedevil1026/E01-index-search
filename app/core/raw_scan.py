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
from typing import Any, Callable, Iterator, Optional, Sequence

from app.core.encodings import (
    ASCII_SUPERSET_ENCODINGS, RAW_ENCODINGS, decode_runs, resolve_encodings,
)


DEFAULT_PAGE = 16 * 1024 * 1024     # 16 MiB sbuf page
DEFAULT_MARGIN = 4096               # overlap so boundary matches survive

# Minimum string length for the raw sweep. The `strings` default is 4,
# but for *indexing* a higher floor cuts an order of magnitude of
# random-byte noise while still catching real words / identifiers.
MIN_RUN = 6

# Cap on text harvested per page, PER ENCODING. A 16 MiB page of a real
# image yields several MB of printable runs, so some cap is needed or a
# text-dense page produces an enormous index doc.
#
# The budget is per encoding, not a shared pool split between them. An
# earlier revision divided one total across the encoding set, which
# starved ASCII — the encoding carrying most real text — down to a fifth
# of its previous coverage as soon as the examiner selected more
# encodings. Picking a wider encoding set must never reduce what is
# found under the encodings already selected.
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
        # Advance by what was actually delivered, not by the nominal
        # page size. If a read comes up short on a damaged image, a
        # fixed stride would step over the shortfall and those bytes
        # would never be scanned — a silent hole in the sweep.
        if len(data) < body:
            body = len(data)
        yield RawPage(offset=offset, length=body, data=data)
        offset += body


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
    # The encoding set actually swept — recorded so the audit log and
    # the manifest state which encodings the case was searched under.
    encodings: tuple = ()


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

    Each encoding gets its **own** `max_chars` budget. A single shared
    budget meant the first encoding (ASCII) exhausted it on most real
    pages and every later encoding — UTF-16LE/BE, UTF-8, the CJK code
    pages — was never scanned at all. On a Windows image that silently
    loses UTF-16 text, which is the native encoding of filenames and
    much document content, in exactly the unallocated space this sweep
    exists to search.

    Splitting one total between the encodings would fix that but create
    the opposite fault: selecting a wider encoding set would shrink what
    is found under ASCII. Per-encoding budgets mean adding an encoding
    only ever adds coverage. The cost is that the indexed text per page
    scales with the size of the chosen set — which is exactly the
    trade-off the examiner makes when picking that set.

    Runs from ASCII-superset code pages that contain no non-ASCII
    character are skipped: the `ascii` pass already produced them
    verbatim, so re-indexing them only crowds out the different text
    the code page was added to find.

    Returns (joined_text, n_strings).
    """
    parts: list[str] = []
    n = 0
    body_len = page.length
    encodings = tuple(encodings) or RAW_ENCODINGS
    per_encoding = max(1, max_chars)
    for enc in encodings:
        used = 0
        dedup = enc in ASCII_SUPERSET_ENCODINGS
        # The ASCII-duplicate filter is pushed into the regex rather than
        # applied here, so the discarded runs are never built at all.
        for rel, run in decode_runs(page.data, enc, min_run=min_run,
                                    require_nonascii=dedup):
            if rel >= body_len:
                continue
            parts.append(run)
            n += 1
            used += len(run) + 1
            if used >= per_encoding:
                break
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
    # `encodings` may be a preset name ("windows") or an explicit tuple.
    encodings = resolve_encodings(encodings)
    stats.encodings = encodings
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


# ---- parallel sweep -------------------------------------------------------
#
# The sweep is the dominant ingest stage and its cost is regex scanning,
# which in CPython holds the GIL — threads cannot help. Processes can:
# each worker opens its own image handle (libewf decompresses per handle,
# the same property `parallel_hash` already exploits) and scans one page.
#
# Determinism is preserved by consuming results strictly in offset order,
# so the indexed documents, the string counts and the first-seen offset of
# every IoC are identical to a sequential run. The tests assert that.

_WORKER_HANDLE: dict = {}


def _worker_handle(segments: tuple, fmt: str):
    """One image handle per worker process, opened once and reused."""
    key = (segments, fmt)
    h = _WORKER_HANDLE.get(key)
    if h is None:
        from app.core.ewf_reader import EwfHandle, RawHandle
        h = (RawHandle(segments[0]) if fmt == "RAW"
             else EwfHandle(list(segments)))
        _WORKER_HANDLE[key] = h
    return h


def _scan_page_job(args):
    """Read one page and do all the CPU-bound work on it.

    Runs in a worker process, so it must not touch Qt, the case database
    or the index — it returns plain data for the parent to act on.
    """
    (segments, fmt, offset, want, body, encodings, min_run,
     scan_patterns) = args
    h = _worker_handle(segments, fmt)
    h.seek(offset)
    data = h.read(want)
    if len(data) < body:
        body = len(data)
    page = RawPage(offset=offset, length=body, data=data)
    text, n = scan_page_text(page, encodings, min_run)
    hits: list = []
    if scan_patterns and text:
        from app.core import patterns as _pat
        hits = [(p.kind, p.value, p.offset) for p in _pat.scan_text(text)]
    # The raw bytes are deliberately not returned — only the text the
    # parent needs. Shipping 16 MiB per page back would cost more than
    # the scan saves.
    return offset, body, text, n, hits


def parallel_string_sweep(segments: Sequence[str], fmt: str, total: int, *,
                          page_size: int = DEFAULT_PAGE,
                          margin: int = DEFAULT_MARGIN,
                          encodings=RAW_ENCODINGS,
                          min_run: int = MIN_RUN,
                          n_workers: int = 4,
                          scan_patterns: bool = False,
                          on_result: Optional[Callable] = None,
                          progress_cb: Optional[Callable[[int, int], None]] = None,
                          cancel_cb: Optional[Callable[[], bool]] = None
                          ) -> RawScanStats:
    """Sweep the image with `n_workers` processes.

    `on_result(page_stub, text, n_strings, hits)` is called once per page
    in ascending offset order. `page_stub` carries the offset and length
    but no bytes. `hits` is a list of (kind, value, absolute_offset).

    Returns the same RawScanStats a sequential sweep would.
    """
    import concurrent.futures

    encodings = resolve_encodings(encodings)
    stats = RawScanStats()
    stats.encodings = encodings
    if not total:
        return stats

    segments = tuple(str(s) for s in segments)
    jobs = []
    off = 0
    while off < total:
        body = min(page_size, total - off)
        want = min(page_size + margin, total - off)
        jobs.append((segments, fmt, off, want, body, encodings, min_run,
                     scan_patterns))
        off += body

    # Bounded look-ahead: enough to keep every worker busy without
    # holding the whole image's extracted text in memory at once.
    window = max(2, n_workers * 2)
    done_bytes = 0
    try:
        with concurrent.futures.ProcessPoolExecutor(
                max_workers=n_workers) as ex:
            futures: dict = {}
            next_submit = 0
            next_consume = 0
            while next_consume < len(jobs):
                while next_submit < len(jobs) and len(futures) < window:
                    futures[next_submit] = ex.submit(_scan_page_job,
                                                     jobs[next_submit])
                    next_submit += 1
                if cancel_cb and cancel_cb():
                    for f in futures.values():
                        f.cancel()
                    break
                offset, body, text, n, hits = futures.pop(next_consume).result()
                next_consume += 1
                stats.pages += 1
                stats.bytes_scanned += body
                stats.strings += n
                if on_result is not None:
                    on_result(RawPage(offset=offset, length=body, data=b""),
                              text, n, hits)
                done_bytes += body
                if progress_cb is not None:
                    progress_cb(min(done_bytes, total), total)
    except Exception:
        # Any failure to fan out (spawn blocked, pickling, worker crash)
        # must not lose the pass — the caller falls back to sequential.
        raise
    return stats


def sweep_and_carve(stream: Any, *,
                    page_size: int = DEFAULT_PAGE,
                    margin: int = DEFAULT_MARGIN,
                    carve_window_size: int = 32 * 1024 * 1024,
                    encodings=RAW_ENCODINGS,
                    min_run: int = MIN_RUN,
                    types=None,
                    max_files: int = 0,
                    on_page: Optional[Callable[[RawPage, str, int], None]] = None,
                    on_file: Optional[Callable] = None,
                    progress_cb: Optional[Callable[[int, int], None]] = None,
                    cancel_cb: Optional[Callable[[], bool]] = None):
    """Run the string sweep and the carver off a SINGLE read of the image.

    Normally each stage reads and decompresses the whole image itself.
    On a large E01 that second decompression pass is pure overhead —
    roughly 20 minutes per 100 GB at observed libewf throughput.

    Both algorithms keep their own geometry exactly: the sweep still
    sees `page_size` pages with a `margin` overlap, and the carver still
    sees `carve_window_size` windows with a `_MAX_HEADER` carry. Pages
    are read once and the carve windows are assembled from them, so the
    output of both is identical to running the passes separately — which
    the test suite asserts byte-for-byte.

    Returns (RawScanStats, CarveStats).
    """
    from app.core import carver as _carver

    encodings = resolve_encodings(encodings)
    sstats = RawScanStats()
    sstats.encodings = encodings
    cstats = _carver.CarveStats()

    try:
        total = stream.get_size()
    except Exception:  # noqa: BLE001
        total = getattr(stream, "size", 0)
    if not total:
        return sstats, cstats

    sigs = _carver.select_signatures(types)
    no_footer: dict = {}

    def read_more(abs_off: int, n: int) -> bytes:
        # Footer searches may reach past the current window. This seeks
        # away from the sequential cursor, so the main loop always seeks
        # back explicitly before its next read.
        if abs_off >= total:
            return b""
        stream.seek(abs_off)
        return stream.read(min(n, total - abs_off))

    carve_enabled = bool(sigs) and (on_file is not None or max_files >= 0)
    carry = b""
    carry_base = 0
    win = bytearray()          # accumulating carve window body bytes
    win_base = 0
    offset = 0
    stop_carving = False

    def flush_window() -> bool:
        """Carve one assembled window. False -> stop carving."""
        nonlocal carry, carry_base, win, win_base
        if not win:
            return True
        blob = carry + bytes(win) if carry else bytes(win)
        blob_base = carry_base if carry else win_base
        ok = _carver.carve_window(blob, blob_base, sigs, read_more,
                                  no_footer, cstats, on_file, max_files)
        carry = blob[-_carver._MAX_HEADER:]
        carry_base = blob_base + len(blob) - len(carry)
        win = bytearray()
        return ok

    while offset < total:
        if cancel_cb and cancel_cb():
            break
        body = min(page_size, total - offset)
        want = min(page_size + margin, total - offset)
        stream.seek(offset)                    # re-anchor after read_more
        data = stream.read(want)
        if not data:
            break
        if len(data) < body:
            body = len(data)

        # ---- string sweep on this page ------------------------------
        page = RawPage(offset=offset, length=body, data=data)
        text, n = scan_page_text(page, encodings, min_run)
        sstats.pages += 1
        sstats.bytes_scanned += body
        sstats.strings += n
        if on_page is not None:
            on_page(page, text, n)

        # ---- feed the same bytes to the carver ----------------------
        if carve_enabled and not stop_carving:
            win += data[:body]
            if len(win) >= carve_window_size:
                if not flush_window():
                    stop_carving = True

        offset += body
        if progress_cb is not None and total:
            progress_cb(min(offset, total), total)

    if carve_enabled and not stop_carving:
        flush_window()

    return sstats, cstats
