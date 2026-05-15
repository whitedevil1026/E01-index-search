"""EWF segment-level integrity checker + case-metadata extractor.

Pure-Python port of the user's PowerShell `E01 Integrity Checker` script,
plus a couple of fixes:
- Uses zlib.adler32 instead of a hand-rolled loop (faster, correct).
- Uses zlib.decompress(raw=False then raw=True) instead of the .NET
  DeflateStream pattern that requires manual header/trailer stripping.
- Detects EWF1/EWF2/LEWF (E01/Ex01/L01/Lx01) families via lenient
  signature check.

Reads only ~89 bytes per segment (32 from start, 76 from end + extracted
header sections) so it stays fast on network shares and multi-TB sets.

API
---
- ext_is_image(ext) -> bool
- segment_index_from_ext(ext) -> int  (1-based; returns -1 if not a segment ext)
- expected_ext_for_index(idx, prefix) -> str
- adler32(buf) -> int
- inspect_segment(path) -> SegmentInfo
- extract_metadata(first_path, last_path) -> CaseMetadata
- check_set(paths, *, callbacks) -> SetReport
- find_image_sets(folder, recurse=False) -> list[list[Path]]
"""
from __future__ import annotations

import os
import re
import struct
import uuid
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional


# ---- EWF signatures -------------------------------------------------------

SIG_EWF1 = b"\x45\x56\x46\x09\x0d\x0a\x00\x00"   # "EVF\t\r\n\0\0"
SIG_LEWF = b"\x4c\x56\x46\x09\x0d\x0a\x00\x00"   # "LVF\t\r\n\0\0"
SIG_EWF2 = b"\x45\x56\x46\x32\x0d\x0a\x81\x00"   # "EVF2\r\n\x81\0"


# ---- field-name maps ------------------------------------------------------

HEADER_FIELD_MAP = {
    "a": "ExaminerName", "c": "CaseNumber", "n": "EvidenceNumber",
    "e": "Description", "t": "Notes", "md": "Model",
    "sn": "SerialNumber", "l": "DeviceLabel",
    "av": "AcquisitionSoftware", "ov": "OperatingSystem",
    "m": "AcquiredDate", "u": "SystemDate",
    "p": "PasswordHash", "pid": "ProcessID",
    "dc": "DataClassification", "ext": "Extents",
    "r": "CompressionLevel",
}
MEDIA_TYPE_MAP = {
    0: "Removable (e.g. floppy/USB)",
    1: "Fixed disk (HDD/SSD)",
    3: "Optical (CD/DVD)",
    14: "Logical evidence file",
    16: "Memory (RAM)",
}
COMPRESSION_MAP = {0: "None", 1: "Fast", 2: "Best"}


# ---- extension helpers ----------------------------------------------------

_RE_BASIC      = re.compile(r"^[ELS]\d{2}$")
_RE_BASIC_AZ   = re.compile(r"^[ELS][A-Z]{2}$")
_RE_X_NUM      = re.compile(r"^[EL]X\d{2}$")
_RE_X_AZ       = re.compile(r"^[EL]X[A-Z]{2}$")


def ext_is_image(ext: str) -> bool:
    e = ext.lstrip(".").upper()
    return bool(
        _RE_BASIC.match(e) or _RE_BASIC_AZ.match(e)
        or _RE_X_NUM.match(e) or _RE_X_AZ.match(e)
    )


def segment_index_from_ext(ext: str) -> int:
    """Return 1-based segment index (1 = E01/EAA prefix etc). -1 if not parseable."""
    e = ext.lstrip(".").upper()
    if e.startswith("EX") or e.startswith("LX"):
        e = e[0] + e[2:]  # drop the 'x' so EX01 → E01
    if len(e) < 3:
        return -1
    tail = e[1:]
    if tail.isdigit() and len(tail) == 2:
        return int(tail)
    if len(tail) == 2 and tail.isalpha():
        a = ord(tail[0]) - ord("A")
        b = ord(tail[1]) - ord("A")
        return 100 + (a * 26) + b
    return -1


def expected_ext_for_index(index: int, prefix: str) -> str:
    if index < 100:
        return f"{prefix}{index:02d}"
    n = index - 100
    a = chr(ord("A") + (n // 26))
    b = chr(ord("A") + (n % 26))
    return f"{prefix}{a}{b}"


def ext_prefix(ext: str) -> str:
    e = ext.lstrip(".").upper()
    if e.startswith("EX"):
        return "Ex"
    if e.startswith("LX"):
        return "Lx"
    return e[0]


# ---- low-level helpers ----------------------------------------------------

def adler32(buf: bytes) -> int:
    return zlib.adler32(buf) & 0xFFFFFFFF


def _zlib_decompress(data: bytes) -> Optional[bytes]:
    """Try standard zlib stream first, then raw deflate as a fallback.
    The EWF on-disk header blocks are zlib streams; mirror the PS script's
    header/trailer stripping path as a fallback only.
    """
    if not data or len(data) < 6:
        return None
    try:
        return zlib.decompress(data)
    except zlib.error:
        pass
    try:
        return zlib.decompress(data[2:-4], -zlib.MAX_WBITS)
    except zlib.error:
        return None


def _decode_header_bytes(data: bytes, is_utf16: bool) -> Optional[str]:
    raw = _zlib_decompress(data)
    if raw is None:
        return None
    if is_utf16:
        if len(raw) >= 2 and raw[0] == 0xFF and raw[1] == 0xFE:
            raw = raw[2:]
        try:
            return raw.decode("utf-16-le", errors="replace")
        except Exception:
            return None
    try:
        return raw.decode("latin-1", errors="replace")
    except Exception:
        return None


def _parse_ewf_date(s: str) -> str:
    """Parse an EWF header date field, which can appear in three formats:

    1. "YYYY M D H M S"   — EnCase classic, space-separated calendar parts
    2. "1319391001"        — Unix epoch (seconds, 10 digits)
    3. "1319391001000"     — Unix epoch (milliseconds, 13 digits)

    Returns ISO-8601 UTC ("YYYY-MM-DD HH:MM:SS UTC") or the original
    string if unparseable.
    """
    import datetime as _dt
    if not s or not s.strip():
        return ""
    t = s.strip()
    # epoch?
    if t.isdigit():
        try:
            n = int(t)
            if len(t) == 13:
                n //= 1000          # ms → s
            if 0 < n < 4_102_444_800:   # < year 2100 sanity gate
                dt = _dt.datetime.fromtimestamp(n, tz=_dt.timezone.utc)
                return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        except (ValueError, OSError, OverflowError):
            pass
    # space-separated calendar parts
    parts = t.split()
    if len(parts) >= 6:
        try:
            y, mo, d, h, mi, se = (int(p) for p in parts[:6])
            return f"{y:04d}-{mo:02d}-{d:02d} {h:02d}:{mi:02d}:{se:02d}"
        except ValueError:
            return s
    return s


def _format_bytes(n: int) -> str:
    if n <= 0:
        return ""
    units = ("B", "KB", "MB", "GB", "TB", "PB")
    v = float(n)
    i = 0
    while v >= 1024 and i < len(units) - 1:
        v /= 1024
        i += 1
    return f"{v:.2f} {units[i]}"


# ---- section walker -------------------------------------------------------

@dataclass
class Section:
    type: str
    offset: int
    size: int
    next_offset: int
    data: Optional[bytes]


_DEFAULT_EXTRACT = ("header", "header2", "volume", "disk", "hash", "digest")


def read_sections(fh, extract_types: tuple[str, ...] = _DEFAULT_EXTRACT,
                  max_sections: int = 1024) -> list[Section]:
    """Walk the section linked list starting at offset 13 (after the 13-byte
    EWF header). Returns each section descriptor; the `data` field is only
    populated for types named in `extract_types`.
    """
    out: list[Section] = []
    fh.seek(0, os.SEEK_END)
    file_len = fh.tell()
    offset = 13
    seen: set[int] = set()
    count = 0
    while offset < file_len and count < max_sections:
        if offset in seen:
            break
        seen.add(offset)
        if offset + 76 > file_len:
            break
        fh.seek(offset)
        desc = fh.read(76)
        if len(desc) < 76:
            break
        # type[0..15] null-padded ascii; next_off=[16..23] u64; size=[24..31] u64
        null_idx = desc.find(b"\x00", 0, 16)
        if null_idx < 0:
            null_idx = 16
        try:
            stype = desc[:null_idx].decode("ascii")
        except UnicodeDecodeError:
            stype = ""
        next_off = struct.unpack_from("<Q", desc, 16)[0]
        sec_size = struct.unpack_from("<Q", desc, 24)[0]

        data: Optional[bytes] = None
        if stype in extract_types:
            data_size = int(sec_size) - 76
            if 0 < data_size < 16 * 1024 * 1024:
                buf = fh.read(data_size)
                data = buf if len(buf) == data_size else buf  # accept short reads

        out.append(Section(stype, offset, sec_size, next_off, data))
        count += 1
        if stype in ("next", "done"):
            break
        if next_off <= offset or next_off >= file_len:
            break
        offset = next_off
    return out


# ---- header / volume field parsers ---------------------------------------

def _set_header_fields(text: str, target: dict) -> None:
    if not text or not text.strip():
        return
    lines = [ln for ln in re.split(r"\r?\n", text) if ln]
    if len(lines) < 2:
        return
    for i in range(len(lines) - 1):
        cols = lines[i].split("\t")
        if len(cols) < 3:
            continue
        shortish = sum(1 for c in cols if len(c) <= 4)
        if shortish < len(cols) - 1:
            continue
        vals = lines[i + 1].split("\t")
        for k in range(min(len(cols), len(vals))):
            key = cols[k].strip().lower()
            if not key:
                continue
            friendly = HEADER_FIELD_MAP.get(key, key)
            v = vals[k]
            if friendly in ("AcquiredDate", "SystemDate"):
                target[friendly] = _parse_ewf_date(v)
            elif friendly == "CompressionLevel":
                target[friendly] = {"0": "None", "n": "None",
                                    "1": "Fast", "f": "Fast",
                                    "2": "Best", "b": "Best"}.get(
                    v.strip().lower(), v)
            else:
                target[friendly] = v
        return


def _set_volume_fields(data: bytes, target: dict) -> None:
    if not data or len(data) < 64:
        return
    mt = data[0]
    target["MediaType"] = MEDIA_TYPE_MAP.get(mt, f"Unknown ({mt})")
    target["NumberOfChunks"]  = struct.unpack_from("<I", data, 4)[0]
    target["SectorsPerChunk"] = struct.unpack_from("<I", data, 8)[0]
    target["BytesPerSector"]  = struct.unpack_from("<I", data, 12)[0]
    secs                      = struct.unpack_from("<I", data, 16)[0]
    target["NumberOfSectors"] = secs
    target["CHSCylinders"]       = struct.unpack_from("<I", data, 20)[0]
    target["CHSHeads"]           = struct.unpack_from("<I", data, 24)[0]
    target["CHSSectorsPerTrack"] = struct.unpack_from("<I", data, 28)[0]
    if len(data) > 32:
        flags = data[32]
        flag_names = []
        if flags & 0x01: flag_names.append("Image")
        if flags & 0x02: flag_names.append("Physical")
        if flags & 0x04: flag_names.append("Write-Blocker")
        target["MediaFlags"] = ", ".join(flag_names)
    if len(data) > 0x30:
        clvl = data[0x30]
        if clvl in COMPRESSION_MAP:
            target["Compression"] = COMPRESSION_MAP[clvl]
    if len(data) >= 0x38:
        target["ErrorGranularity"] = struct.unpack_from("<I", data, 0x34)[0]
    if len(data) >= 0x4C:
        try:
            g = data[0x3C:0x3C + 16]
            target["SetGUID"] = str(uuid.UUID(bytes_le=g))
        except Exception:
            pass
    bps = int(target.get("BytesPerSector") or 0)
    ns = int(secs)
    if bps > 0 and ns > 0:
        total = bps * ns
        target["TotalBytes"] = total
        target["TotalSize"] = _format_bytes(total)


# ---- public dataclasses ---------------------------------------------------

@dataclass
class SegmentInfo:
    file_name: str
    full_path: str
    size_bytes: int = 0
    header_valid: bool = False
    header_hex: str = ""
    header_ascii: str = ""
    family: str = ""
    segment_in_header: Optional[int] = None
    segment_from_name: int = -1
    segment_number_match: Optional[bool] = None
    last_section_type: str = ""
    last_section_next_offset: Optional[int] = None
    last_section_size: Optional[int] = None
    descriptor_checksum_ok: Optional[bool] = None
    read_error: str = ""
    status: str = "?"
    notes: list[str] = field(default_factory=list)


@dataclass
class CaseMetadata:
    fields: dict = field(default_factory=dict)
    metadata_error: str = ""

    def as_ordered(self) -> list[tuple[str, str]]:
        order = [
            "CaseNumber", "EvidenceNumber", "ExaminerName", "Description",
            "Notes", "Model", "SerialNumber", "DeviceLabel",
            "AcquiredDate", "SystemDate", "OperatingSystem",
            "AcquisitionSoftware", "CompressionLevel", "Compression",
            "PasswordHash", "ProcessID", "MediaType", "MediaFlags",
            "BytesPerSector", "SectorsPerChunk", "NumberOfSectors",
            "NumberOfChunks", "TotalBytes", "TotalSize",
            "CHSCylinders", "CHSHeads", "CHSSectorsPerTrack",
            "ErrorGranularity", "SetGUID", "StoredMD5", "StoredSHA1",
        ]
        return [(k, str(self.fields.get(k, ""))) for k in order]


@dataclass
class SetReport:
    image_set: str
    folder: str
    first_segment: str
    last_segment: str
    segments_present: int
    max_index: int
    missing: list[str] = field(default_factory=list)
    segments: list[SegmentInfo] = field(default_factory=list)
    metadata: CaseMetadata = field(default_factory=CaseMetadata)
    has_done_marker: bool = False
    summary: dict = field(default_factory=dict)


# ---- per-segment check ----------------------------------------------------

def inspect_segment(path: str) -> SegmentInfo:
    p = Path(path)
    info = SegmentInfo(
        file_name=p.name,
        full_path=str(p),
        segment_from_name=segment_index_from_ext(p.suffix),
    )
    try:
        sz = p.stat().st_size
        info.size_bytes = sz
        if sz < 89:
            info.read_error = "File too small (< 89 bytes) to be a valid EWF segment."
            info.status = "BAD"
            info.notes.append(info.read_error)
            return info
        with open(p, "rb") as fh:
            # ---- header (32 bytes from start) -----------------------------
            fh.seek(0)
            hdr = fh.read(32)
            if len(hdr) < 13:
                info.read_error = f"Only read {len(hdr)}/32 header bytes"
                info.status = "BAD"
                info.notes.append(info.read_error)
                return info
            info.header_hex = " ".join(f"{b:02X}" for b in hdr)
            info.header_ascii = "".join(chr(b) if 32 <= b < 127 else "." for b in hdr)
            is_evf = hdr[0:3] == b"EVF"
            is_lvf = hdr[0:3] == b"LVF"
            if is_evf:
                info.header_valid = True
                if hdr[3] == 0x32:
                    info.family = "EWF2 (Ex01)"
                elif hdr[3] == 0x09:
                    info.family = "EWF (E01)"
                else:
                    info.family = f"EWF (variant byte4=0x{hdr[3]:02X})"
            elif is_lvf:
                info.header_valid = True
                info.family = "LEWF (L01)"
            else:
                info.family = "UNKNOWN"
                info.notes.append(
                    f"Bad/missing EWF signature. First 32 bytes hex: {info.header_hex}  ascii: {info.header_ascii}"
                )
            if info.header_valid:
                info.segment_in_header = struct.unpack_from("<H", hdr, 9)[0]
                if info.segment_from_name > 0:
                    info.segment_number_match = (
                        info.segment_in_header == info.segment_from_name
                    )
                    if info.segment_number_match is False:
                        info.notes.append(
                            f"Segment# mismatch (header={info.segment_in_header}, "
                            f"name={info.segment_from_name})"
                        )

            # ---- trailing descriptor (last 76 bytes) ----------------------
            fh.seek(-76, os.SEEK_END)
            tail = fh.read(76)
            null_idx = tail.find(b"\x00", 0, 16)
            if null_idx < 0:
                null_idx = 16
            try:
                info.last_section_type = tail[:null_idx].decode("ascii")
            except UnicodeDecodeError:
                info.last_section_type = ""
            info.last_section_next_offset = struct.unpack_from("<Q", tail, 16)[0]
            info.last_section_size = struct.unpack_from("<Q", tail, 24)[0]
            stored_adler = struct.unpack_from("<I", tail, 72)[0]
            calc_adler = adler32(tail[:72])
            info.descriptor_checksum_ok = (stored_adler == calc_adler)
            if info.descriptor_checksum_ok is False:
                info.notes.append("Trailing descriptor Adler-32 invalid")
            if not info.last_section_type:
                info.notes.append("Trailing section type unreadable")
            elif info.last_section_type not in ("next", "done"):
                info.notes.append(
                    f"Trailing section is '{info.last_section_type}' "
                    "(expected 'next' or 'done')"
                )

        info.status = "OK" if not info.notes else "BAD"
        return info
    except Exception as exc:  # noqa: BLE001
        info.read_error = str(exc)
        info.status = "BAD"
        info.notes.append(f"ReadError: {exc}")
        return info


# ---- case-metadata extractor ---------------------------------------------

_META_KEYS = (
    "CaseNumber", "EvidenceNumber", "ExaminerName", "Description", "Notes",
    "Model", "SerialNumber", "DeviceLabel", "AcquiredDate", "SystemDate",
    "OperatingSystem", "AcquisitionSoftware", "CompressionLevel",
    "Compression", "PasswordHash", "ProcessID", "MediaType", "MediaFlags",
    "BytesPerSector", "SectorsPerChunk", "NumberOfSectors", "NumberOfChunks",
    "TotalBytes", "TotalSize", "CHSCylinders", "CHSHeads",
    "CHSSectorsPerTrack", "ErrorGranularity", "SetGUID",
    "StoredMD5", "StoredSHA1",
)


def extract_metadata(first_path: str, last_path: Optional[str] = None) -> CaseMetadata:
    meta = CaseMetadata({k: "" for k in _META_KEYS})
    try:
        with open(first_path, "rb") as fh:
            secs = read_sections(fh)
            # prefer header2 (UTF-16) over header (latin-1)
            for s in secs:
                if s.type == "header2" and s.data:
                    txt = _decode_header_bytes(s.data, is_utf16=True)
                    if txt:
                        _set_header_fields(txt, meta.fields)
                    break
            if not meta.fields.get("CaseNumber"):
                for s in secs:
                    if s.type == "header" and s.data:
                        txt = _decode_header_bytes(s.data, is_utf16=False)
                        if txt:
                            _set_header_fields(txt, meta.fields)
                        break
            for s in secs:
                if s.type in ("volume", "disk") and s.data:
                    _set_volume_fields(s.data, meta.fields)
                    break
    except Exception as exc:  # noqa: BLE001
        meta.metadata_error = f"First-segment parse error: {exc}"

    if last_path and Path(last_path).exists() and last_path != first_path:
        try:
            with open(last_path, "rb") as fh:
                secs = read_sections(fh, extract_types=("hash", "digest"))
                for s in secs:
                    if s.type == "hash" and s.data and len(s.data) >= 16:
                        md5 = s.data[:16].hex()
                        if md5 != "00" * 16:
                            meta.fields["StoredMD5"] = md5
                    if s.type == "digest" and s.data:
                        if len(s.data) >= 16 and not meta.fields.get("StoredMD5"):
                            md5 = s.data[:16].hex()
                            if md5 != "00" * 16:
                                meta.fields["StoredMD5"] = md5
                        if len(s.data) >= 36:
                            sha1 = s.data[16:36].hex()
                            if sha1 != "00" * 20:
                                meta.fields["StoredSHA1"] = sha1
        except Exception as exc:  # noqa: BLE001
            extra = f"Last-segment parse error: {exc}"
            meta.metadata_error = (meta.metadata_error + "; " + extra) if meta.metadata_error else extra

    return meta


# ---- set discovery + full check ------------------------------------------

def find_image_sets(folder: str, recurse: bool = False) -> list[list[Path]]:
    """Group files in `folder` by basename → ordered list of segment paths."""
    root = Path(folder)
    if not root.exists():
        return []
    it = root.rglob("*") if recurse else root.iterdir()
    groups: dict[str, list[Path]] = {}
    for p in it:
        if not p.is_file():
            continue
        if not ext_is_image(p.suffix):
            continue
        key = str(p.parent / p.stem)
        groups.setdefault(key, []).append(p)
    out: list[list[Path]] = []
    for key, files in sorted(groups.items()):
        files.sort(key=lambda f: segment_index_from_ext(f.suffix))
        out.append(files)
    return out


def check_set(
    paths: list[Path],
    *,
    extract_meta: bool = True,
    on_segment: Optional[Callable[[SegmentInfo, int, int], None]] = None,
    on_log: Optional[Callable[[str], None]] = None,
) -> SetReport:
    """Run integrity check on a sorted list of segment paths."""
    if not paths:
        raise ValueError("no segments provided")
    paths_sorted = sorted(paths, key=lambda p: segment_index_from_ext(p.suffix))
    base = paths_sorted[0].stem
    folder = str(paths_sorted[0].parent)

    present: dict[int, Path] = {}
    for p in paths_sorted:
        idx = segment_index_from_ext(p.suffix)
        if idx > 0:
            present[idx] = p
    max_idx = max(present)
    prefix = ext_prefix(paths_sorted[0].suffix)

    report = SetReport(
        image_set=base, folder=folder,
        first_segment=paths_sorted[0].name,
        last_segment=paths_sorted[-1].name,
        segments_present=len(present),
        max_index=max_idx,
    )

    # missing pass
    for i in range(1, max_idx + 1):
        if i not in present:
            miss_name = f"{base}.{expected_ext_for_index(i, prefix)}"
            report.missing.append(miss_name)
            if on_log:
                on_log(f"  MISSING : {miss_name}")
            seg = SegmentInfo(
                file_name=miss_name,
                full_path=str(Path(folder) / miss_name),
                segment_from_name=i,
                status="MISSING",
                notes=["Chunk not present in folder"],
            )
            report.segments.append(seg)

    has_done = False
    total = max_idx
    done_count = 0
    # per-segment check pass
    for i in range(1, max_idx + 1):
        if i not in present:
            continue
        seg = inspect_segment(str(present[i]))
        is_last_present = (i == max_idx)
        if seg.last_section_type == "done":
            if not is_last_present:
                seg.notes.append("'done' on non-final chunk (later segments may be orphans)")
                seg.status = "BAD"
            has_done = True
        elif seg.last_section_type == "next":
            if is_last_present:
                seg.notes.append(
                    "Final present chunk ends with 'next' — more chunks expected but missing"
                )
                seg.status = "BAD"
        if seg.notes and seg.status == "OK":
            seg.status = "BAD"
        report.segments.append(seg)
        done_count += 1
        if on_segment:
            on_segment(seg, done_count, total)
        if on_log:
            on_log(
                f"  {seg.file_name:<30s} size={seg.size_bytes:>14,d} "
                f"hdr={'OK' if seg.header_valid else 'BAD'} "
                f"trail={seg.last_section_type:<5s} -> {seg.status}"
            )
            for nt in seg.notes:
                on_log(f"      ! {nt}")

    report.has_done_marker = has_done
    if not has_done:
        if on_log:
            on_log(f"  WARNING: set '{base}' has no 'done' marker -- INCOMPLETE.")

    # metadata
    if extract_meta:
        if on_log:
            on_log(f"  Extracting case metadata…")
        report.metadata = extract_metadata(
            str(paths_sorted[0]),
            str(paths_sorted[-1]) if len(paths_sorted) > 1 else None,
        )
        if on_log:
            for k, v in report.metadata.as_ordered():
                if v:
                    on_log(f"    {k:<22s}: {v}")

    # summary counts
    ok = sum(1 for s in report.segments if s.status == "OK")
    bad = sum(1 for s in report.segments if s.status == "BAD")
    miss = sum(1 for s in report.segments if s.status == "MISSING")
    report.summary = {"ok": ok, "bad": bad, "missing": miss,
                      "has_done": has_done,
                      "complete": (miss == 0 and bad == 0 and has_done)}
    if on_log:
        on_log(f"  Summary: OK={ok}  BAD={bad}  MISSING={miss}  "
               f"done_marker={'yes' if has_done else 'NO'}")
    return report


# ---- FTK-style human-readable text report ---------------------------------

def _fmt_kv(k: str, v) -> str:
    if v in (None, "", b""):
        return f"  {k:<28s}: (not present)"
    return f"  {k:<28s}: {v}"


def format_report_txt(
    reports: list["SetReport"],
    *,
    case_name: str = "",
    examiner: str = "",
    case_id: str = "",
    investigator_notes: str = "",
    extras: Optional[dict] = None,
) -> str:
    """Produce an FTK-Imager-style text report covering one or more image sets.

    The output is plain ASCII, suitable for case archives, courtroom
    discovery packages, and chain-of-custody binders. It is deterministic
    given the same inputs (no embedded random IDs).
    """
    import datetime as _dt
    extras = extras or {}
    now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    out: list[str] = []
    bar = "=" * 78
    sub = "-" * 78

    out.append(bar)
    out.append("E01 / EWF Image Verification & Case Report")
    out.append(bar)
    out.append("")
    out.append("Case Information")
    out.append(sub)
    out.append(_fmt_kv("Case Name", case_name))
    out.append(_fmt_kv("Case Identifier", case_id))
    out.append(_fmt_kv("Examiner", examiner))
    out.append(_fmt_kv("Report Generated", now))
    out.append(_fmt_kv("Tool", "e01-indexing try1 (Python)"))
    if investigator_notes:
        out.append("")
        out.append("Investigator Notes:")
        for line in investigator_notes.splitlines():
            out.append("  " + line)
    out.append("")

    for r in reports:
        out.append(bar)
        out.append(f"Evidence Item: {r.image_set}")
        out.append(bar)
        out.append("")
        out.append("Image Set")
        out.append(sub)
        out.append(_fmt_kv("Source folder", r.folder))
        out.append(_fmt_kv("First segment", r.first_segment))
        out.append(_fmt_kv("Last segment",  r.last_segment))
        out.append(_fmt_kv("Segments present", r.segments_present))
        out.append(_fmt_kv("Highest segment index", r.max_index))
        out.append(_fmt_kv("Missing segments", len(r.missing) or "(none)"))
        if r.missing:
            for m in r.missing:
                out.append(f"      MISSING: {m}")
        out.append(_fmt_kv("'done' marker present",
                           "yes" if r.has_done_marker else "NO -- incomplete"))
        s = r.summary
        verdict = "COMPLETE" if s.get("complete") else "INCOMPLETE / DAMAGED"
        out.append(_fmt_kv("Verdict", verdict))
        out.append(_fmt_kv("Counts", f"OK={s['ok']}  BAD={s['bad']}  MISSING={s['missing']}"))
        out.append("")

        # Case metadata block (FTK-style)
        out.append("Acquisition Metadata (from EWF header)")
        out.append(sub)
        for k, v in r.metadata.as_ordered():
            if v:
                pretty_key = {
                    "AcquiredDate": "Acquired Date (UTC)",
                    "SystemDate":   "System Date (UTC)",
                    "StoredMD5":    "Stored MD5 hash (acquisition)",
                    "StoredSHA1":   "Stored SHA-1 hash (acquisition)",
                    "SetGUID":      "EWF Set GUID",
                    "TotalSize":    "Total Size (human)",
                    "TotalBytes":   "Total Size (bytes)",
                    "MediaType":    "Media Type",
                    "MediaFlags":   "Media Flags",
                    "BytesPerSector":   "Bytes / Sector",
                    "SectorsPerChunk":  "Sectors / Chunk",
                    "NumberOfSectors":  "Number of Sectors",
                    "NumberOfChunks":   "Number of Chunks",
                    "CHSCylinders":     "CHS Cylinders",
                    "CHSHeads":         "CHS Heads",
                    "CHSSectorsPerTrack": "CHS Sectors / Track",
                    "ErrorGranularity": "Error Granularity",
                    "PasswordHash":     "Password Hash (if any)",
                    "ProcessID":        "Acquisition Process ID",
                    "OperatingSystem":  "Acquisition OS",
                    "AcquisitionSoftware": "Acquisition Software Version",
                    "CompressionLevel": "Compression Level (raw)",
                    "Compression":      "Compression Level",
                    "EvidenceNumber":   "Evidence Number",
                    "CaseNumber":       "Case Number",
                    "ExaminerName":     "Examiner (recorded in image)",
                    "Description":      "Description",
                    "Notes":            "Notes",
                    "DeviceLabel":      "Device Label",
                    "Model":             "Device Model",
                    "SerialNumber":     "Device Serial Number",
                }.get(k, k)
                out.append(_fmt_kv(pretty_key, v))
        if r.metadata.metadata_error:
            out.append(_fmt_kv("Metadata parse errors", r.metadata.metadata_error))
        out.append("")

        # Per-segment table
        out.append("Per-Segment Verification")
        out.append(sub)
        out.append(f"  {'Status':<8} {'Segment':<32} {'Size (bytes)':>14}  "
                   f"{'Family':<14} {'Trailer':<7} Adler-32")
        for seg in r.segments:
            adler = "OK" if seg.descriptor_checksum_ok else (
                "BAD" if seg.descriptor_checksum_ok is False else "n/a"
            )
            out.append(
                f"  {seg.status:<8} {seg.file_name:<32} {seg.size_bytes:>14,d}  "
                f"{(seg.family or '-'):<14} {(seg.last_section_type or '-'):<7} {adler}"
            )
            for nt in seg.notes:
                out.append(f"      ! {nt}")
        out.append("")

        # Extras (per-evidence): file-level hashes, additional digests, etc.
        if extras.get(r.image_set):
            out.append("Computed Hashes Over Full E01 Segment Files")
            out.append(sub)
            for seg_name, hashes in extras[r.image_set].items():
                out.append(f"  {seg_name}:")
                for algo, dig in hashes.items():
                    out.append(f"      {algo:<10s}= {dig}")
            out.append("")

    out.append(bar)
    out.append("End of Report")
    out.append(bar)
    return "\n".join(out) + "\n"

