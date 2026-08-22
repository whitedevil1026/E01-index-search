"""File-signature carving.

Pure-Python recovery of files from raw image bytes by their magic
signatures — the common-format subset of what PhotoRec does, without
the external PhotoRec binary.

Carving finds files the filesystem walk cannot: deleted files whose
directory entry is gone, files embedded in other files, and data in
unallocated space.

Design choices for low false-positive rate
------------------------------------------
* Signatures are **long and specific** — e.g. JPEG is matched as the
  4-byte `FF D8 FF Ex` APP-marker form, not the 3-byte `FF D8 FF`
  which occurs constantly by chance in binary data.
* Only formats with a **reliable end marker** are carved: a footer
  signature (JPEG / PNG / GIF / PDF) or a length field in the header
  (BMP). A header whose end cannot be determined is skipped rather
  than carving a huge truncated blob.
* A minimum carved size rejects signature-byte coincidences.

The image is streamed in overlapping windows so a file straddling a
window boundary is still recovered.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any, Callable, Optional


@dataclass
class CarvedFile:
    file_type: str          # 'jpeg', 'png', ...
    offset: int             # absolute byte offset of the header
    size: int               # carved length in bytes
    data: bytes             # the carved bytes
    truncated: bool = False


@dataclass
class _Sig:
    file_type: str
    headers: tuple          # one or more header byte strings
    footer: Optional[bytes] # footer signature, or None for length-based
    max_size: int
    ext: str
    length_based: bool = False   # size encoded in the header (BMP)


# Only reliably-delimited formats. Each header is >= 4 specific bytes.
_SIGNATURES: list[_Sig] = [
    _Sig("jpeg",
         (b"\xff\xd8\xff\xe0", b"\xff\xd8\xff\xe1",
          b"\xff\xd8\xff\xe2", b"\xff\xd8\xff\xee",
          b"\xff\xd8\xff\xdb", b"\xff\xd8\xff\xc0"),
         b"\xff\xd9", 30 * 1024 * 1024, "jpg"),
    _Sig("png", (b"\x89PNG\r\n\x1a\n",),
         b"IEND\xaeB`\x82", 50 * 1024 * 1024, "png"),
    _Sig("gif", (b"GIF89a", b"GIF87a"),
         b"\x00\x3b", 20 * 1024 * 1024, "gif"),
    _Sig("pdf", (b"%PDF-1.",),
         b"%%EOF", 100 * 1024 * 1024, "pdf"),
    _Sig("bmp", (b"BM",),
         None, 50 * 1024 * 1024, "bmp", length_based=True),
]

# longest header we must keep as carry-over between windows
_MAX_HEADER = max(len(h) for s in _SIGNATURES for h in s.headers)

SUPPORTED_TYPES = tuple(sorted({s.file_type for s in _SIGNATURES}))

# A "file" smaller than this is almost certainly a signature-byte
# coincidence, not a real recoverable file.
MIN_CARVE_SIZE = 512

# Cap on the single forward read used to locate a footer that lies past
# the current window. Bounds the cost of a header candidate whose footer
# never arrives — see the note in _carve_one().
FORWARD_READ_CAP = 16 * 1024 * 1024


@dataclass
class CarveStats:
    carved: int = 0
    bytes_carved: int = 0
    per_type: dict = field(default_factory=dict)

    def add(self, file_type: str, size: int):
        self.carved += 1
        self.bytes_carved += size
        self.per_type[file_type] = self.per_type.get(file_type, 0) + 1


def _carve_one(blob: bytes, start: int, abs_start: int, sig: _Sig,
               read_more: Callable[[int, int], bytes],
               no_footer: Optional[dict] = None) -> Optional[CarvedFile]:
    """Determine the extent of one file starting at `start` in `blob`.

    NEVER slices `max_size` eagerly — that was a performance trap when
    a short signature (BMP's 2-byte `BM`) matched thousands of times.
    The size is established from a few header bytes (length-based) or
    by locating the footer with `bytes.find` (a C scan, no copy).

    `no_footer` memoises byte ranges already searched unsuccessfully for
    each signature's footer, so a cluster of false headers does not
    re-read the same region once per candidate.

    Returns None (skip) when the end cannot be reliably determined.
    """
    # ---- length-based (BMP): validate the 18-byte header -------------
    if sig.length_based:
        hdr = blob[start:start + 18]
        if len(hdr) < 18:
            hdr = hdr + read_more(abs_start + len(hdr), 18 - len(hdr))
        if len(hdr) < 18:
            return None
        try:
            size = struct.unpack_from("<I", hdr, 2)[0]
            reserved = struct.unpack_from("<I", hdr, 6)[0]
            data_offset = struct.unpack_from("<I", hdr, 10)[0]
            dib_size = struct.unpack_from("<I", hdr, 14)[0]
        except Exception:  # noqa: BLE001
            return None
        # A real BMP: reserved == 0, the DIB header size is one of the
        # standard values, and the pixel-data offset is small. These
        # checks reject the bulk of `BM`-coincidence false positives.
        if reserved != 0:
            return None
        if dib_size not in (12, 40, 52, 56, 64, 108, 124):
            return None
        if not (26 <= data_offset <= 4096):
            return None
        if not (MIN_CARVE_SIZE <= size <= sig.max_size):
            return None
        # only now fetch exactly `size` bytes
        if start + size <= len(blob):
            data = blob[start:start + size]
        else:
            data = blob[start:]
            data = data + read_more(abs_start + len(data), size - len(data))
        if len(data) < MIN_CARVE_SIZE:
            return None
        return CarvedFile(sig.file_type, abs_start, len(data), data, False)

    # ---- footer-delimited: find the footer with a C-level scan ------
    hlen = len(sig.headers[0])  # headers of a sig are similar length
    fidx = blob.find(sig.footer, start + hlen)
    if fidx >= 0:
        size = fidx + len(sig.footer) - start
        if size < MIN_CARVE_SIZE or size > sig.max_size:
            return None
        return CarvedFile(sig.file_type, abs_start, size,
                          blob[start:start + size], False)

    # Footer not in this window — the file may span past it. Do ONE
    # bounded forward read and search there.
    #
    # The read is capped at FORWARD_READ_CAP rather than sig.max_size:
    # a header whose footer never appears (a coincidental `%PDF-1.` in
    # unallocated space) costs the full read every time, and at
    # sig.max_size that is 100 MB re-read per false candidate across a
    # multi-hundred-GB image. The window already carries up to 32 MB of
    # tail, so a genuine file up to ~tail+cap is still recovered whole.
    tail = blob[start:]
    forward = min(sig.max_size - len(tail), FORWARD_READ_CAP)
    if forward <= 0:
        return None

    # Already proved there is no footer anywhere in this range?
    cached = (no_footer or {}).get(sig.file_type)
    if cached is not None:
        c_from, c_to = cached
        if c_from <= abs_start and abs_start + len(tail) + forward <= c_to:
            return None

    extra = read_more(abs_start + len(tail), forward)
    if not extra:
        return None
    region = tail + extra
    fidx = region.find(sig.footer, hlen)
    if fidx < 0:
        if no_footer is not None:
            # Remember the swept range so neighbouring false headers
            # inside it are rejected without another read.
            c_from, c_to = no_footer.get(sig.file_type, (abs_start, abs_start))
            if abs_start <= c_to:      # contiguous with / inside the known range
                no_footer[sig.file_type] = (min(c_from, abs_start),
                                            max(c_to, abs_start + len(region)))
            else:                      # a new, disjoint region
                no_footer[sig.file_type] = (abs_start, abs_start + len(region))
        return None
    size = fidx + len(sig.footer)
    if size < MIN_CARVE_SIZE:
        return None
    return CarvedFile(sig.file_type, abs_start, size, region[:size], False)


def select_signatures(types: Optional[set] = None) -> list:
    """The signature set to search, optionally restricted to `types`."""
    if types:
        return [s for s in _SIGNATURES if s.file_type in types]
    return list(_SIGNATURES)


def carve_window(blob: bytes, blob_base: int, sigs: list,
                 read_more: Callable[[int, int], bytes],
                 no_footer: dict, stats: CarveStats,
                 on_file: Optional[Callable[[CarvedFile], None]] = None,
                 max_files: int = 0) -> bool:
    """Carve every file found in one window of image bytes.

    Shared by `carve_stream` (which reads its own windows) and by the
    single-pass driver (which hands over windows already read for the
    string sweep). Keeping one implementation is what lets the two
    modes be verified byte-for-byte identical.

    Returns False when `max_files` has been reached and the caller
    should stop.
    """
    for sig in sigs:
        for header in sig.headers:
            search_from = 0
            while True:
                idx = blob.find(header, search_from)
                if idx < 0:
                    break
                search_from = idx + 1
                carved = _carve_one(blob, idx, blob_base + idx,
                                    sig, read_more, no_footer)
                if carved is None:
                    continue
                if carved.size < MIN_CARVE_SIZE:
                    continue
                if on_file is not None:
                    on_file(carved)
                stats.add(carved.file_type, carved.size)
                if max_files and stats.carved >= max_files:
                    return False
    return True


def carve_stream(stream: Any, *,
                 window: int = 32 * 1024 * 1024,
                 types: Optional[set] = None,
                 max_files: int = 0,
                 on_file: Optional[Callable[[CarvedFile], None]] = None,
                 progress_cb: Optional[Callable[[int, int], None]] = None,
                 cancel_cb: Optional[Callable[[], bool]] = None
                 ) -> CarveStats:
    """Carve files from a raw image stream.

    For every recovered file `on_file(carved)` is invoked so the caller
    can hash / index / persist it and drop the bytes — memory stays
    bounded. `types` optionally restricts the formats searched.
    """
    stats = CarveStats()
    sigs = select_signatures(types)
    if not sigs:
        return stats

    try:
        total = stream.get_size()
    except Exception:  # noqa: BLE001
        total = getattr(stream, "size", 0)
    if not total:
        return stats

    def read_more(abs_off: int, n: int) -> bytes:
        if abs_off >= total:
            return b""
        stream.seek(abs_off)
        return stream.read(min(n, total - abs_off))

    # {file_type: (from, to)} — ranges already swept without finding a
    # footer, so dense runs of false headers cost one read, not one each.
    no_footer: dict = {}

    pos = 0
    carry = b""
    carry_base = 0
    while pos < total:
        if cancel_cb and cancel_cb():
            break
        stream.seek(pos)
        chunk = stream.read(window)
        if not chunk:
            break
        blob = carry + chunk
        blob_base = carry_base if carry else pos

        if not carve_window(blob, blob_base, sigs, read_more, no_footer,
                            stats, on_file, max_files):
            return stats

        carry = blob[-_MAX_HEADER:]
        carry_base = blob_base + len(blob) - len(carry)
        pos += window
        if progress_cb and total:
            progress_cb(min(pos, total), total)

    return stats
