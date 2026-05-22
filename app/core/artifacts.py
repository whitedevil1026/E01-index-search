"""Phase 4 — specialized artifact parsing.

Container formats a forensic examiner must look *inside*, because the
filesystem walk only sees the container file, never its contents:

    PST / OST      Outlook mail stores      -> libpff
    Registry hive  NTUSER.DAT, SOFTWARE …   -> libregf
    ESE database   Edge/IE history, SRUM …  -> libesedb
    SQLite DB      browser / app / chat DB  -> stdlib sqlite3
    Defender .dat  quarantined files        -> RC4 decode (static key)

Detection-only (no parsing, just flag and route):

    encrypted chat DBs   WhatsApp .crypt14/15, Signal SQLCipher
    memory images        .mem / .raw / .vmem / .dmp
    packet captures      .pcap / .pcapng

Each parser yields `ArtifactItem`s — one per message / table / hive
subtree — so the ingest layer can index each as its own searchable
document instead of cramming a whole mail store into one blob.
"""
from __future__ import annotations

import io
import os
import shutil
import sqlite3
import struct
import tempfile
from dataclasses import dataclass, field
from typing import Any, Iterator, Optional

try:
    import pypff
    HAS_PYPFF = True
except Exception:  # noqa: BLE001
    HAS_PYPFF = False

try:
    import pyregf
    HAS_PYREGF = True
except Exception:  # noqa: BLE001
    HAS_PYREGF = False

try:
    import pyesedb
    HAS_PYESEDB = True
except Exception:  # noqa: BLE001
    HAS_PYESEDB = False


# ---- artifact kinds -------------------------------------------------------

NONE = ""
PST = "pst"
REGISTRY = "registry"
ESEDB = "esedb"
SQLITE = "sqlite"
DEFENDER_QUARANTINE = "defender_quarantine"
WHATSAPP_ENC = "whatsapp_encrypted"
SQLCIPHER = "sqlcipher"
MEMORY = "memory"
PCAP = "pcap"

# kinds that this module fully parses
PARSEABLE = {PST, REGISTRY, ESEDB, SQLITE, DEFENDER_QUARANTINE}
# kinds that are only identified + flagged
FLAG_ONLY = {WHATSAPP_ENC, SQLCIPHER, MEMORY, PCAP}


HUMAN = {
    PST: "Outlook mail store (PST/OST)",
    REGISTRY: "Windows Registry hive",
    ESEDB: "ESE database",
    SQLITE: "SQLite database",
    DEFENDER_QUARANTINE: "Microsoft Defender quarantine",
    WHATSAPP_ENC: "WhatsApp encrypted database",
    SQLCIPHER: "SQLCipher-encrypted database (e.g. Signal)",
    MEMORY: "memory image",
    PCAP: "packet capture",
}


# ---- result shapes --------------------------------------------------------

@dataclass
class ArtifactItem:
    """One indexable unit extracted from a container."""
    subpath: str            # e.g. 'Inbox/msg_42' or 'table:WebHistory'
    name: str               # short label
    text: str               # searchable text
    meta: dict = field(default_factory=dict)


@dataclass
class ArtifactSummary:
    kind: str
    items: int = 0
    error: str = ""
    note: str = ""


class _MemFile(io.BytesIO):
    """BytesIO that also exposes get_size() — libyal open_file_object()
    requires it.
    """
    def get_size(self) -> int:
        return len(self.getbuffer())


# ---- detection ------------------------------------------------------------

_REG_HIVE_NAMES = {
    "ntuser.dat", "usrclass.dat", "system", "software", "sam",
    "security", "default", "components", "drivers", "bcd",
}


def detect_artifact(name: str, head: bytes) -> str:
    """Identify a specialized artifact from its name + first bytes."""
    low = name.lower()
    ext = low.rsplit(".", 1)[-1] if "." in low else ""

    # --- detection-only kinds first --------------------------------
    if ext in ("crypt14", "crypt15", "crypt12"):
        return WHATSAPP_ENC
    if ext in ("mem", "vmem", "raw", "lime", "dmp", "core"):
        # .dmp is also Windows minidump; treat large ones as memory
        return MEMORY
    if ext in ("pcap", "pcapng", "cap"):
        return PCAP
    if head[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4") \
            or head[:4] == b"\x0a\x0d\x0d\x0a":
        return PCAP

    # --- magic-byte parseable kinds --------------------------------
    if head[:4] == b"!BDN":                       # PST/OST
        return PST
    if head[:4] == b"regf":                       # registry hive
        return REGISTRY
    if len(head) >= 8 and head[4:8] == b"\xef\xcd\xab\x89":  # ESE
        return ESEDB
    if head[:16] == b"SQLite format 3\x00":
        return SQLITE

    # --- name-based hints ------------------------------------------
    if low in _REG_HIVE_NAMES:
        return REGISTRY
    if ext in ("pst", "ost", "pab"):
        return PST
    if ext in ("edb", "ese"):
        return ESEDB
    if ext in ("db", "sqlite", "sqlite3", "db3"):
        # could be plain SQLite or SQLCipher — header check above
        # already caught plain SQLite; a .db without the header is
        # likely SQLCipher-encrypted
        return SQLCIPHER
    if "quarantine" in low and ext in ("", "dat"):
        return DEFENDER_QUARANTINE
    return NONE


# ---- PST / OST ------------------------------------------------------------

def _pff_message_text(msg) -> str:
    parts: list[str] = []
    for getter in ("get_subject", "get_sender_name",
                   "get_conversation_topic"):
        try:
            v = getattr(msg, getter)()
            if v:
                parts.append(str(v))
        except Exception:  # noqa: BLE001
            pass
    try:
        hdrs = msg.get_transport_headers()
        if hdrs:
            parts.append(str(hdrs))
    except Exception:  # noqa: BLE001
        pass
    try:
        body = msg.get_plain_text_body()
        if body:
            parts.append(body.decode("utf-8", errors="replace")
                         if isinstance(body, bytes) else str(body))
    except Exception:  # noqa: BLE001
        pass
    if len(parts) <= 1:
        # fall back to HTML body
        try:
            hb = msg.get_html_body()
            if hb:
                from app.core.text_extract import _strip_html
                raw = hb.decode("utf-8", errors="replace") \
                    if isinstance(hb, bytes) else str(hb)
                parts.append(_strip_html(raw))
        except Exception:  # noqa: BLE001
            pass
    return "\n".join(parts)


def _pff_walk_folder(folder, path: str, counter: dict,
                     max_messages: int) -> Iterator[ArtifactItem]:
    try:
        fname = folder.get_name() or "(folder)"
    except Exception:  # noqa: BLE001
        fname = "(folder)"
    here = f"{path}/{fname}" if path else fname
    # messages in this folder
    try:
        n_msg = folder.get_number_of_sub_messages()
    except Exception:  # noqa: BLE001
        n_msg = 0
    for i in range(n_msg):
        if counter["n"] >= max_messages:
            return
        try:
            msg = folder.get_sub_message(i)
        except Exception:  # noqa: BLE001
            continue
        text = _pff_message_text(msg)
        if not text:
            continue
        subj = ""
        try:
            subj = msg.get_subject() or ""
        except Exception:  # noqa: BLE001
            pass
        counter["n"] += 1
        yield ArtifactItem(
            subpath=f"{here}/msg_{i}",
            name=subj or f"message {i}",
            text=text,
            meta={"folder": here},
        )
    # recurse sub-folders
    try:
        n_sub = folder.get_number_of_sub_folders()
    except Exception:  # noqa: BLE001
        n_sub = 0
    for j in range(n_sub):
        if counter["n"] >= max_messages:
            return
        try:
            sub = folder.get_sub_folder(j)
        except Exception:  # noqa: BLE001
            continue
        yield from _pff_walk_folder(sub, here, counter, max_messages)


def parse_pst(content: bytes, source: str = "",
              max_messages: int = 100_000) -> Iterator[ArtifactItem]:
    if not HAS_PYPFF:
        return
    fo = _MemFile(content)
    try:
        pff = pypff.file()
        pff.open_file_object(fo)
    except Exception:  # noqa: BLE001
        return
    try:
        root = pff.get_root_folder()
    except Exception:  # noqa: BLE001
        return
    counter = {"n": 0}
    if root is not None:
        yield from _pff_walk_folder(root, "", counter, max_messages)


# ---- Registry hive --------------------------------------------------------

def _regf_value_text(value) -> str:
    try:
        s = value.get_data_as_string()
        if s:
            return str(s)
    except Exception:  # noqa: BLE001
        pass
    try:
        ms = value.get_data_as_multi_string()
        if ms:
            return " ".join(str(x) for x in ms)
    except Exception:  # noqa: BLE001
        pass
    try:
        iv = value.get_data_as_integer()
        if iv is not None:
            return str(iv)
    except Exception:  # noqa: BLE001
        pass
    try:
        d = value.get_data()
        if d:
            # show a hex preview for binary values
            return d[:64].hex()
    except Exception:  # noqa: BLE001
        pass
    return ""


def _regf_walk_key(key, path: str, counter: dict,
                   max_keys: int, lines: list) -> None:
    if counter["n"] >= max_keys:
        return
    try:
        kname = key.get_name() or ""
    except Exception:  # noqa: BLE001
        kname = ""
    here = f"{path}\\{kname}" if path else kname
    counter["n"] += 1
    # values
    try:
        n_val = key.get_number_of_values()
    except Exception:  # noqa: BLE001
        n_val = 0
    for i in range(n_val):
        try:
            val = key.get_value(i)
            vname = val.get_name() or "(default)"
            vtext = _regf_value_text(val)
            lines.append(f"{here}\\{vname} = {vtext}")
        except Exception:  # noqa: BLE001
            continue
    # sub-keys
    try:
        n_sub = key.get_number_of_sub_keys()
    except Exception:  # noqa: BLE001
        n_sub = 0
    for j in range(n_sub):
        if counter["n"] >= max_keys:
            return
        try:
            sub = key.get_sub_key(j)
        except Exception:  # noqa: BLE001
            continue
        _regf_walk_key(sub, here, counter, max_keys, lines)


def parse_registry(content: bytes, source: str = "",
                   max_keys: int = 400_000) -> Iterator[ArtifactItem]:
    if not HAS_PYREGF:
        return
    fo = _MemFile(content)
    try:
        regf = pyregf.file()
        regf.open_file_object(fo)
        root = regf.get_root_key()
    except Exception:  # noqa: BLE001
        return
    if root is None:
        return
    counter = {"n": 0}
    lines: list[str] = []
    _regf_walk_key(root, "", counter, max_keys, lines)
    # batch the flat key/value listing into ~500 KB chunks so a huge
    # hive becomes several index docs
    chunk: list[str] = []
    size = 0
    part = 0
    for ln in lines:
        chunk.append(ln)
        size += len(ln) + 1
        if size >= 500_000:
            yield ArtifactItem(f"hive/part_{part}",
                               f"registry keys (part {part})",
                               "\n".join(chunk),
                               {"keys": counter["n"]})
            part += 1
            chunk = []
            size = 0
    if chunk:
        yield ArtifactItem(f"hive/part_{part}",
                           f"registry keys (part {part})",
                           "\n".join(chunk), {"keys": counter["n"]})


# ---- ESE database ---------------------------------------------------------

def _esedb_record_text(record) -> str:
    parts: list[str] = []
    try:
        n = record.get_number_of_values()
    except Exception:  # noqa: BLE001
        return ""
    for i in range(n):
        try:
            v = record.get_value_data_as_string(i)
        except Exception:  # noqa: BLE001
            v = None
        if v is None:
            try:
                iv = record.get_value_data_as_integer(i)
                v = str(iv) if iv is not None else None
            except Exception:  # noqa: BLE001
                v = None
        if v:
            parts.append(str(v))
    return " | ".join(parts)


def parse_esedb(content: bytes, source: str = "",
                max_rows_per_table: int = 200_000) -> Iterator[ArtifactItem]:
    if not HAS_PYESEDB:
        return
    fo = _MemFile(content)
    try:
        esedb = pyesedb.file()
        esedb.open_file_object(fo)
        n_tables = esedb.get_number_of_tables()
    except Exception:  # noqa: BLE001
        return
    for t in range(n_tables):
        try:
            table = esedb.get_table(t)
            tname = table.get_name() or f"table_{t}"
            n_rec = table.get_number_of_records()
        except Exception:  # noqa: BLE001
            continue
        rows: list[str] = []
        size = 0
        part = 0
        for r in range(min(n_rec, max_rows_per_table)):
            try:
                rec = table.get_record(r)
            except Exception:  # noqa: BLE001
                continue
            txt = _esedb_record_text(rec)
            if not txt:
                continue
            rows.append(txt)
            size += len(txt) + 1
            if size >= 500_000:
                yield ArtifactItem(f"table:{tname}/part_{part}",
                                   f"{tname} (part {part})",
                                   "\n".join(rows),
                                   {"table": tname})
                part += 1
                rows = []
                size = 0
        if rows:
            yield ArtifactItem(f"table:{tname}/part_{part}",
                               f"{tname}" + (f" (part {part})" if part else ""),
                               "\n".join(rows), {"table": tname})


# ---- SQLite database ------------------------------------------------------

def parse_sqlite(content: bytes, source: str = "",
                 max_rows_per_table: int = 200_000,
                 wal_content: Optional[bytes] = None) -> Iterator[ArtifactItem]:
    """Parse a SQLite DB.

    stdlib sqlite3 needs a path, so the DB bytes are written to a temp
    file. If `wal_content` (the `-wal` write-ahead-log side file) is
    supplied it is written alongside as `<temp>-wal` and SQLite replays
    its uncommitted transactions on open — recovering the most recent
    chat messages / history rows that had not yet been checkpointed.

    Forensic note: the ORIGINAL evidence is never touched. Only a
    throwaway temp COPY is opened, and only that copy is read.
    """
    tmp_dir = None
    try:
        tmp_dir = tempfile.mkdtemp(prefix="e01sqlite_")
        tmp_path = os.path.join(tmp_dir, "db.sqlite")
        with open(tmp_path, "wb") as fh:
            fh.write(content)
        if wal_content:
            with open(tmp_path + "-wal", "wb") as fh:
                fh.write(wal_content)
            # WAL replay requires a normal (non-immutable) open on the
            # temp copy so SQLite can checkpoint the log into the DB.
            uri = f"file:{tmp_path}"
        else:
            # no WAL — open the copy strictly read-only
            uri = f"file:{tmp_path}?immutable=1&mode=ro"
        conn = sqlite3.connect(uri, uri=True)
        conn.text_factory = lambda b: b.decode("utf-8", errors="replace")
        if wal_content:
            try:
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except Exception:  # noqa: BLE001
                pass
    except Exception:  # noqa: BLE001
        if tmp_dir and os.path.isdir(tmp_dir):
            shutil.rmtree(tmp_dir, ignore_errors=True)
        return
    try:
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [r[0] for r in cur.fetchall()]
        for tname in tables:
            rows: list[str] = []
            size = 0
            part = 0
            try:
                tcur = conn.cursor()
                tcur.execute(f'SELECT * FROM "{tname}" LIMIT {max_rows_per_table}')
            except Exception:  # noqa: BLE001
                continue
            for row in tcur:
                cells = [str(c) for c in row if c not in (None, "")]
                if not cells:
                    continue
                line = " | ".join(cells)
                rows.append(line)
                size += len(line) + 1
                if size >= 500_000:
                    yield ArtifactItem(f"table:{tname}/part_{part}",
                                       f"{tname} (part {part})",
                                       "\n".join(rows), {"table": tname})
                    part += 1
                    rows = []
                    size = 0
            if rows:
                yield ArtifactItem(
                    f"table:{tname}" + (f"/part_{part}" if part else ""),
                    f"{tname}" + (f" (part {part})" if part else ""),
                    "\n".join(rows), {"table": tname})
    finally:
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass
        if tmp_dir and os.path.isdir(tmp_dir):
            shutil.rmtree(tmp_dir, ignore_errors=True)


# ---- Microsoft Defender quarantine ---------------------------------------

# The static RC4 key Windows Defender uses to obfuscate quarantined
# files. Publicly documented and used by every Defender-quarantine
# forensic tool.
_DEFENDER_RC4_KEY = bytes([
    0x1E, 0x87, 0x78, 0x1B, 0x8D, 0xBA, 0xA8, 0x44, 0xCE, 0x69,
    0x70, 0x2C, 0x0C, 0x78, 0xB7, 0x86, 0xA3, 0xF6, 0x23, 0xB7,
    0x38, 0xF5, 0xED, 0xF9, 0xAF, 0x83, 0x53, 0x0F, 0xB3, 0xFC,
    0x54, 0xFA, 0xA2, 0x1E, 0xB9, 0xCF, 0x13, 0x31, 0xFD, 0x0F,
    0x0D, 0xA9, 0x54, 0xF6, 0x87, 0xCB, 0x9E, 0x18, 0x27, 0x96,
    0x97, 0x90, 0x0E, 0x53, 0xFB, 0x31, 0x7C, 0x9C, 0xBC, 0xE4,
    0x8E, 0x23, 0xD0, 0x53, 0x71, 0xEC, 0xC1, 0x59, 0x51, 0xB8,
    0xF3, 0x64, 0x9D, 0x7C, 0xA3, 0x3E, 0xD6, 0x8D, 0xC9, 0x04,
    0x7E, 0x82, 0xC9, 0xBA, 0xAD, 0x97, 0x99, 0xD0, 0xD4, 0x58,
    0xCB, 0x84, 0x7C, 0xA9, 0xFF, 0xBE, 0x3C, 0x8A, 0x77, 0x52,
    0x33, 0x55, 0x7D, 0xDE, 0x13, 0xA8, 0xB1, 0x40, 0x87, 0xCC,
    0x1B, 0xC8, 0xF1, 0x0F, 0x6E, 0xCD, 0xD0, 0x83, 0xA9, 0x59,
    0xCF, 0xF8, 0x4A, 0x9D, 0x1D, 0x50, 0x75, 0x5E, 0x3E, 0x19,
    0x18, 0x18, 0xAF, 0x23, 0xE2, 0x29, 0x35, 0x58, 0x76, 0x6D,
    0x2C, 0x07, 0xE2, 0x57, 0x12, 0xB2, 0xCA, 0x0B, 0x53, 0x5E,
    0xD8, 0xF6, 0xC5, 0x6C, 0xE7, 0x3D, 0x24, 0xBD, 0xD0, 0x29,
    0x17, 0x71, 0x86, 0x1A, 0x54, 0xB4, 0xC2, 0x85, 0xA9, 0xA3,
    0xDB, 0x7A, 0xCA, 0x6D, 0x22, 0x4A, 0xEA, 0xCD, 0x62, 0x1D,
    0xB9, 0xF2, 0xA2, 0x2E, 0xD1, 0xE9, 0xE1, 0x1D, 0x75, 0xBE,
    0xD7, 0xDC, 0x0E, 0xCB, 0x0A, 0x8E, 0x68, 0xA2, 0xFF, 0x12,
    0x63, 0x40, 0x8D, 0xC8, 0x08, 0xDF, 0xFD, 0x16, 0x4B, 0x11,
    0x67, 0x74, 0xCD, 0x0B, 0x9B, 0x8D, 0x05, 0x41, 0x1E, 0xD6,
    0x26, 0x2E, 0x42, 0x9B, 0xA4, 0x95, 0x67, 0x6B, 0x83, 0x98,
    0xDB, 0x2F, 0x35, 0xD3, 0xC1, 0xB9, 0xCE, 0xD0, 0x06, 0x36,
    0x6E, 0x6B, 0x42, 0xD8, 0x8E, 0x0C, 0x83, 0x4F, 0xD1, 0x84,
    0xCF, 0xC1, 0x1E, 0x84, 0x9F, 0x5A,
])


def _rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256))
    j = 0
    klen = len(key)
    for i in range(256):
        j = (j + S[i] + key[i % klen]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out = bytearray(len(data))
    i = j = 0
    for n in range(len(data)):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out[n] = data[n] ^ S[(S[i] + S[j]) & 0xFF]
    return bytes(out)


def decode_defender_quarantine(content: bytes) -> Optional[bytes]:
    """RC4-decrypt a Microsoft Defender quarantine file with the static
    key. Returns the decrypted bytes, or None on failure.
    """
    if not content:
        return None
    try:
        return _rc4(_DEFENDER_RC4_KEY, content)
    except Exception:  # noqa: BLE001
        return None


def parse_defender_quarantine(content: bytes, source: str = "",
                              ) -> Iterator[ArtifactItem]:
    decrypted = decode_defender_quarantine(content)
    if not decrypted:
        return
    # the decrypted blob holds the original quarantined file + metadata.
    # Recover searchable text from it via the standard extractor.
    try:
        from app.core.text_extract import extract_text
        res = extract_text("quarantined", decrypted)
        text = res.text if res.ok() else ""
    except Exception:  # noqa: BLE001
        text = ""
    if not text:
        # fall back to printable strings
        import re
        runs = re.findall(rb"[\x20-\x7e]{6,}", decrypted)
        text = "\n".join(r.decode("ascii", "replace") for r in runs[:5000])
    yield ArtifactItem("quarantine/decrypted",
                       "Defender quarantine (decrypted)",
                       text,
                       {"decrypted_bytes": len(decrypted)})


# ---- dispatcher -----------------------------------------------------------

def parse_artifact(kind: str, content: bytes, source: str = "",
                   wal_content: Optional[bytes] = None
                   ) -> tuple[list[ArtifactItem], ArtifactSummary]:
    """Parse a detected artifact. Returns (items, summary).

    `wal_content` is the SQLite `-wal` side file, when one was found —
    it is passed through to the SQLite parser for write-ahead-log
    replay. For FLAG_ONLY kinds no parsing happens.
    """
    summary = ArtifactSummary(kind=kind)
    if kind in FLAG_ONLY:
        summary.note = HUMAN.get(kind, kind)
        return [], summary

    items: list[ArtifactItem] = []
    try:
        if kind == SQLITE:
            gen = parse_sqlite(content, source, wal_content=wal_content)
        elif kind == PST:
            gen = parse_pst(content, source)
        elif kind == REGISTRY:
            gen = parse_registry(content, source)
        elif kind == ESEDB:
            gen = parse_esedb(content, source)
        elif kind == DEFENDER_QUARANTINE:
            gen = parse_defender_quarantine(content, source)
        else:
            summary.error = f"no parser for kind {kind!r}"
            return [], summary
        for item in gen:
            items.append(item)
    except Exception as exc:  # noqa: BLE001
        summary.error = f"{type(exc).__name__}: {exc}"
    summary.items = len(items)
    return items, summary


def availability() -> dict[str, bool]:
    return {
        PST: HAS_PYPFF,
        REGISTRY: HAS_PYREGF,
        ESEDB: HAS_PYESEDB,
        SQLITE: True,                 # stdlib
        DEFENDER_QUARANTINE: True,    # pure python
    }
