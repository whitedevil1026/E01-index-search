"""Trace a search hit back to its origin in the image, and pull the
original bytes back out.

Two questions an examiner asks of every hit:

    "Where did this come from?"   -> describe()
    "Give me that file."          -> export()

Both are answered from the case database plus the evidence image; no
state is kept between the ingest and the export, so an export performed
months later resolves the same way.

Every indexed document falls into one of four origins, distinguished by
the path the indexer stored:

  file      /Windows/System32/x.dll      a live filesystem file. Re-opened
                                         through its recorded volume and
                                         read by inode (or by path).
  carved    /(carved)/jpeg/0x1a2b3c      a signature-carved file. Read back
                                         as a byte range of the image.
  raw       /(raw)/0x1a2b3c              a 16 MiB raw sweep page. The page
                                         bytes are what is exported.
  artifact  /path/to/store.pst#msg/42    an item parsed out of a container.
                                         The container file is exported.

The exported bytes are hashed on the way out and the digest is returned,
so the examiner can show the export matches what was indexed.
"""
from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from app.core.ewf_reader import inspect, open_handle
from app.core.streams import OffsetStream, pytsk_img_from_stream

try:
    import pytsk3
    HAS_PYTSK3 = True
except Exception:  # noqa: BLE001
    HAS_PYTSK3 = False


CARVED_RE = re.compile(r"^/\(carved\)/(?P<kind>[^/]+)/0x(?P<off>[0-9a-fA-F]+)$")
RAW_RE = re.compile(r"^/\(raw\)/0x(?P<off>[0-9a-fA-F]+)$")

# What one raw sweep page covers. Kept in sync with raw_scan.DEFAULT_PAGE.
RAW_PAGE_BYTES = 16 * 1024 * 1024


class ExportError(RuntimeError):
    """Raised when the bytes behind a hit cannot be produced."""


@dataclass
class Provenance:
    """Where an indexed document came from, in examiner-facing terms."""
    kind: str                       # file | carved | raw | artifact
    indexed_path: str               # exactly what the index stored
    display_path: str               # the human answer to "where is it?"
    evidence_id: Optional[int] = None
    evidence_path: str = ""         # the .E01 / raw image on disk
    file_path: str = ""             # path inside the filesystem
    container_path: str = ""        # artifacts: the containing file
    sub_item: str = ""              # artifacts: item within the container
    image_offset: Optional[int] = None    # absolute offset in the image
    size_bytes: Optional[int] = None
    inode: Optional[int] = None
    volume_offset: Optional[int] = None
    volume_label: str = ""
    vss_snapshot_id: Optional[str] = None
    fs_backend: str = ""
    sha256: str = ""
    md5: str = ""
    is_allocated: Optional[bool] = None
    exportable: bool = False
    note: str = ""                  # why not exportable, when it isn't
    suggested_name: str = "export.bin"

    def summary_lines(self) -> list[tuple[str, str]]:
        """(label, value) pairs for a details panel."""
        out: list[tuple[str, str]] = [("Origin", self.kind)]
        if self.file_path:
            out.append(("File path", self.file_path))
        if self.container_path:
            out.append(("Container", self.container_path))
        if self.sub_item:
            out.append(("Item in container", self.sub_item))
        if self.volume_label:
            out.append(("Volume", self.volume_label))
        if self.vss_snapshot_id:
            out.append(("Shadow copy", self.vss_snapshot_id))
        if self.image_offset is not None:
            out.append(("Image offset", f"{self.image_offset:#x} "
                                        f"({self.image_offset:,})"))
        if self.size_bytes is not None:
            out.append(("Size", f"{self.size_bytes:,} bytes"))
        if self.inode is not None:
            out.append(("Inode / MFT", str(self.inode)))
        if self.is_allocated is not None:
            out.append(("Allocated", "yes" if self.is_allocated else
                        "no (deleted / unallocated)"))
        if self.sha256:
            out.append(("SHA-256", self.sha256))
        if self.md5:
            out.append(("MD5", self.md5))
        if self.evidence_path:
            out.append(("Evidence image", self.evidence_path))
        if self.note:
            out.append(("Note", self.note))
        return out


def _safe_name(s: str, default: str = "export.bin") -> str:
    base = s.replace("\\", "/").rstrip("/").split("/")[-1]
    base = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", base).strip(". ")
    return base or default


def origin_of(indexed_path: str) -> str:
    """Classify an indexed path without touching the database — cheap
    enough to label every row of a result table."""
    if CARVED_RE.match(indexed_path):
        return "carved"
    if RAW_RE.match(indexed_path):
        return "raw/unalloc"
    if "#" in indexed_path:
        return "in container"
    return "file"


def describe(case, indexed_path: str,
             evidence_id: int | None = None,
             evidence_uuid: str = "") -> Provenance:
    """Resolve an indexed path to its origin. Never raises — an
    unresolvable hit comes back with exportable=False and a reason.

    A case can hold several images and the same path can exist in more
    than one (`/Boot`, `/$RECYCLE.BIN`, `/System Volume Information`).
    Pass `evidence_uuid` (carried on every search hit) or `evidence_id`
    so the hit is attributed to the image it actually came from —
    without one, a shared path resolves to whichever row is found first,
    which would report the wrong image and export the wrong bytes.
    """
    if evidence_id is None and evidence_uuid:
        ev_row = case.evidence_by_uuid(evidence_uuid)
        if ev_row:
            evidence_id = ev_row["id"]

    row = case.file_by_path(indexed_path, evidence_id)
    ev_id = (row or {}).get("evidence_id") or evidence_id
    ev = case.evidence_by_id(ev_id) if ev_id is not None else None
    if ev is None:
        # Raw sweep pages are never rows in `files`, so there is nothing
        # to join against. With a single image the case is unambiguous;
        # with several, the caller must say which one (the UUID above).
        all_ev = case.list_evidence()
        if len(all_ev) == 1:
            ev = all_ev[0]
            ev_id = ev["id"]
    ev_path = (ev or {}).get("path", "")

    # ---- carved ------------------------------------------------------
    m = CARVED_RE.match(indexed_path)
    if m:
        off = int(m.group("off"), 16)
        size = (row or {}).get("size_bytes")
        p = Provenance(
            kind="carved", indexed_path=indexed_path,
            display_path=f"unallocated space @ {off:#x}",
            evidence_id=ev_id, evidence_path=ev_path,
            image_offset=off, size_bytes=size,
            sha256=(row or {}).get("sha256") or "",
            md5=(row or {}).get("md5") or "",
            is_allocated=False,
            suggested_name=_safe_name((row or {}).get("name")
                                      or f"{m.group('kind')}_{off:x}.{m.group('kind')}"),
        )
        p.exportable = bool(ev_path and size)
        if not p.exportable:
            p.note = ("carved size not recorded — re-ingest this evidence "
                      "to enable export")
        return p

    # ---- raw sweep page ----------------------------------------------
    m = RAW_RE.match(indexed_path)
    if m:
        off = int(m.group("off"), 16)
        p = Provenance(
            kind="raw", indexed_path=indexed_path,
            display_path=f"raw image bytes @ {off:#x} "
                         f"(not a filesystem file)",
            evidence_id=ev_id, evidence_path=ev_path,
            image_offset=off, size_bytes=RAW_PAGE_BYTES,
            is_allocated=False,
            note="Loose text in unallocated space or slack, not a file. "
                 "Exporting saves the 16 MiB image page it was found in.",
            suggested_name=f"raw_{off:x}.bin",
        )
        p.exportable = bool(ev_path)
        if not p.exportable:
            n_ev = len(case.list_evidence())
            p.note = (
                f"This case holds {n_ev} evidence images and a raw page is "
                f"not a filesystem entry, so the image it came from cannot "
                f"be identified from the path alone. Re-select the hit in "
                f"the Search tab, which carries that information."
                if n_ev > 1 else
                "Evidence image path is not recorded for this case."
            )
        return p

    # ---- artifact sub-item -------------------------------------------
    if "#" in indexed_path:
        container, sub = indexed_path.split("#", 1)
        crow = case.file_by_path(container, ev_id)
        p = describe(case, container, ev_id) if crow else Provenance(
            kind="artifact", indexed_path=indexed_path,
            display_path=container, evidence_path=ev_path)
        p.kind = "artifact"
        p.indexed_path = indexed_path
        p.container_path = container
        p.sub_item = sub
        p.display_path = f"{sub}  in  {container}"
        p.note = ("This is an item inside a container (mailbox, registry "
                  "hive, database). Exporting saves the whole container "
                  "file.")
        p.suggested_name = _safe_name(container)
        return p

    # ---- ordinary filesystem file ------------------------------------
    if not row:
        return Provenance(
            kind="file", indexed_path=indexed_path,
            display_path=indexed_path, evidence_id=ev_id,
            evidence_path=ev_path, file_path=indexed_path,
            exportable=False,
            note="No record of this path in the case database.",
            suggested_name=_safe_name(indexed_path),
        )

    p = Provenance(
        kind="file", indexed_path=indexed_path, display_path=indexed_path,
        evidence_id=ev_id, evidence_path=ev_path, file_path=row["path"],
        size_bytes=row.get("size_bytes"), inode=row.get("inode"),
        volume_offset=row.get("volume_offset"),
        volume_label=row.get("volume_label") or "",
        vss_snapshot_id=row.get("vss_snapshot_id"),
        fs_backend=row.get("fs_backend") or "",
        sha256=row.get("sha256") or "", md5=row.get("md5") or "",
        is_allocated=bool(row.get("is_allocated", 1)),
        suggested_name=_safe_name(row.get("name") or indexed_path),
    )
    if not ev_path:
        p.note = "Evidence image path not recorded for this file."
    elif row.get("volume_offset") is None:
        p.note = ("Volume provenance missing — this file was indexed by "
                  "an older build. Re-ingest the evidence to enable export.")
    elif p.vss_snapshot_id:
        p.note = ("File came from a Volume Shadow Copy; export re-opens "
                  "the snapshot.")
        p.exportable = True
    else:
        p.exportable = True
    return p


# ---- byte retrieval -------------------------------------------------------

def _read_range(handle, offset: int, length: int, out) -> int:
    """Copy `length` bytes from `offset` to a writable file object."""
    handle.seek(offset)
    remaining = length
    written = 0
    while remaining > 0:
        chunk = handle.read(min(remaining, 8 << 20))
        if not chunk:
            break
        out.write(chunk)
        written += len(chunk)
        remaining -= len(chunk)
    return written


def _open_volume_stream(handle, prov: Provenance):
    """The volume this file lives in, as a seekable stream."""
    if prov.volume_offset is None:
        raise ExportError("volume offset not recorded for this file")
    try:
        size = handle.get_size()
    except Exception:  # noqa: BLE001
        size = getattr(handle, "size", 0)
    length = max(0, size - prov.volume_offset)
    return OffsetStream(handle, prov.volume_offset, length)


def _export_fs_file(handle, prov: Provenance, out) -> int:
    """Read a live filesystem file back out through TSK."""
    if not HAS_PYTSK3:
        raise ExportError("pytsk3 is not installed — cannot read the "
                          "filesystem to extract this file")
    vstream = _open_volume_stream(handle, prov)
    img = pytsk_img_from_stream(vstream)
    try:
        fs = pytsk3.FS_Info(img, offset=0)
    except Exception as exc:  # noqa: BLE001
        raise ExportError(f"could not open the filesystem at volume "
                          f"offset {prov.volume_offset:#x}: {exc}") from exc

    entry = None
    # Prefer the inode: it survives a rename and is what the walk recorded.
    if prov.inode is not None:
        try:
            entry = fs.open_meta(inode=int(prov.inode))
        except Exception:  # noqa: BLE001
            entry = None
    if entry is None:
        try:
            entry = fs.open(prov.file_path)
        except Exception as exc:  # noqa: BLE001
            raise ExportError(
                f"file not found in the image by inode "
                f"{prov.inode} or path {prov.file_path!r}: {exc}") from exc

    meta = getattr(entry, "info", None)
    size = None
    if meta is not None and getattr(meta, "meta", None) is not None:
        size = getattr(meta.meta, "size", None)
    if not size:
        size = prov.size_bytes or 0
    if not size:
        return 0

    written = 0
    offset = 0
    while offset < size:
        n = min(8 << 20, size - offset)
        try:
            buf = entry.read_random(offset, n)
        except Exception as exc:  # noqa: BLE001
            raise ExportError(f"read failed at offset {offset}: {exc}") from exc
        if not buf:
            break
        out.write(buf)
        written += len(buf)
        offset += len(buf)
    return written


def _receipt_text(case, prov: Provenance, dest: Path, digests: dict,
                  written: int, verified: Optional[bool],
                  ingest_hashes: dict) -> str:
    """A plain-text record proving where an exported file came from and
    what it hashes to. Written next to the export so the file and its
    provenance travel together."""
    try:
        meta = case.meta()
        case_line = f"{meta.name}   (id {meta.id})"
        examiner = meta.examiner
    except Exception:  # noqa: BLE001
        case_line, examiner = "(unknown)", "(unknown)"

    if verified is True:
        verdict = ("MATCH - the exported bytes hash to the value recorded "
                   "when this item was indexed.")
    elif verified is False:
        verdict = ("*** MISMATCH *** - the exported bytes DO NOT match the "
                   "value recorded at ingest. Do not rely on this export.")
    else:
        verdict = ("NOT COMPARED - no hash was recorded for this item at "
                   "ingest, so there is nothing to compare against.")

    lines = [
        "E01 Index & Search - exported file verification receipt",
        "=" * 66,
        "",
        f"Generated          : {time.strftime('%Y-%m-%d %H:%M:%S %Z')}",
        f"Case               : {case_line}",
        f"Examiner           : {examiner}",
        "",
        "EXPORTED FILE",
        "-" * 66,
        f"Saved as           : {dest.name}",
        f"Full path          : {dest}",
        f"Size on disk       : {written:,} bytes",
        "",
        "ORIGIN IN EVIDENCE",
        "-" * 66,
    ]
    for k, v in prov.summary_lines():
        lines.append(f"{k:<19}: {v}")
    lines += [
        "",
        "HASHES OF THE EXPORTED FILE",
        "-" * 66,
    ]
    for algo in sorted(digests):
        lines.append(f"{algo.upper():<19}: {digests[algo]}")
    if ingest_hashes:
        lines += ["", "RECORDED AT INGEST", "-" * 66]
        for algo in sorted(ingest_hashes):
            lines.append(f"{algo.upper():<19}: {ingest_hashes[algo]}")
    lines += [
        "",
        "VERIFICATION",
        "-" * 66,
        verdict,
        "",
        "This export was appended to the case audit log as "
        "'evidence.export'.",
        "The evidence image itself was opened read-only and is unmodified.",
        "",
    ]
    return "\n".join(lines)


def export(case, prov: Provenance, dest: str | Path,
           algos: Optional[list] = None,
           write_receipt: bool = False) -> dict[str, Any]:
    """Write the bytes behind `prov` to `dest`.

    algos          — digests to compute. Defaults to the case's hash
                     policy, so an export is hashed under exactly the
                     algorithms the case was set up to use.
    write_receipt  — also write `<dest>.verify.txt`, a plain-text record
                     of the origin, the digests and whether they match
                     what was recorded at ingest.

    Returns {path, bytes, digests, sha256, md5, verified, receipt}.
    `verified` is True when the exported bytes hash to the digest
    recorded at ingest, False on mismatch, None when none was stored.
    """
    if not prov.exportable:
        raise ExportError(prov.note or "this hit cannot be exported")
    if not prov.evidence_path:
        raise ExportError("evidence image path is not recorded")

    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)

    info = inspect(prov.evidence_path)
    written = 0
    with open_handle(info) as handle, open(dest, "wb") as out:
        if prov.kind == "file":
            written = _export_fs_file(handle, prov, out)
        elif prov.kind == "artifact":
            # Export the container; the sub-item lives inside it.
            container = describe(case, prov.container_path, prov.evidence_id)
            if not container.exportable:
                raise ExportError(container.note or
                                  "container file cannot be exported")
            written = _export_fs_file(handle, container, out)
        elif prov.kind in ("carved", "raw"):
            size = prov.size_bytes or 0
            try:
                total = handle.get_size()
            except Exception:  # noqa: BLE001
                total = getattr(handle, "size", 0)
            if total:
                size = min(size, max(0, total - (prov.image_offset or 0)))
            written = _read_range(handle, prov.image_offset or 0, size, out)
        else:
            raise ExportError(f"unknown origin kind {prov.kind!r}")

    # Hash what actually landed on disk, not the buffer that was written
    # — that is what the examiner will hand over and what a third party
    # will re-hash. SHA-256 and MD5 are always included so the result can
    # be compared against the ingest-time values regardless of policy.
    if algos:
        wanted = [str(a).lower() for a in algos]
    else:
        try:
            wanted = list(case.hash_policy().all_algos())
        except Exception:  # noqa: BLE001
            wanted = ["sha256", "md5"]
    for required in ("sha256", "md5"):
        if required not in wanted:
            wanted.append(required)

    hashers: dict = {}
    for a in wanted:
        try:
            hashers[a] = (hashlib.blake2b() if a == "blake2b"
                          else hashlib.new(a))
        except Exception:  # noqa: BLE001
            continue
    with open(dest, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            for h in hashers.values():
                h.update(chunk)
    digests = {a: h.hexdigest() for a, h in hashers.items()}
    sha = digests.get("sha256", "")

    ingest_hashes = {}
    if prov.sha256:
        ingest_hashes["sha256"] = prov.sha256
    if prov.md5:
        ingest_hashes["md5"] = prov.md5

    # Compare against whichever digest was recorded at ingest.
    verified: Optional[bool] = None
    for algo, recorded in ingest_hashes.items():
        got = digests.get(algo)
        if got and recorded:
            verified = (got == recorded)
            if verified is False:
                break        # any mismatch is decisive

    receipt_path = ""
    if write_receipt:
        receipt_path = str(dest) + ".verify.txt"
        try:
            Path(receipt_path).write_text(
                _receipt_text(case, prov, dest, digests, written,
                              verified, ingest_hashes),
                encoding="utf-8")
        except Exception as exc:  # noqa: BLE001
            raise ExportError(
                f"file exported to {dest}, but the verification receipt "
                f"could not be written: {exc}") from exc

    result = {"path": str(dest), "bytes": written, "digests": digests,
              "sha256": sha, "md5": digests.get("md5", ""),
              "verified": verified, "receipt": receipt_path}
    try:
        case.log("evidence.export", {
            "indexed_path": prov.indexed_path, "kind": prov.kind,
            "evidence_id": prov.evidence_id, "dest": str(dest),
            "bytes": written, "digests": digests, "verified": verified,
            "receipt": receipt_path,
        })
    except Exception:  # noqa: BLE001
        pass
    return result
