"""SQLite case database with hash-chained, append-only audit log.

Schema:
  case_meta         singleton row with case id, name, examiner, created_at
  evidence          one row per ingested image
  files             one row per file enumerated in any evidence item
  indexed_docs      one row per Tantivy doc id (cross-reference)
  audit_log         append-only, hash-chained log of every examiner action

Audit-log chaining: each row stores prev_hash = SHA-256(prev_row_canonical).
Tampering with any historical row breaks the chain.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


SCHEMA = """
CREATE TABLE IF NOT EXISTS case_meta (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    examiner TEXT NOT NULL,
    created_at REAL NOT NULL,
    schema_version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_uuid TEXT UNIQUE NOT NULL,
    path TEXT NOT NULL,
    format TEXT NOT NULL,
    size_bytes INTEGER,
    acquired_md5 TEXT,
    acquired_sha256 TEXT,
    notes TEXT,
    added_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id INTEGER NOT NULL REFERENCES evidence(id),
    inode INTEGER,
    path TEXT NOT NULL,
    name TEXT NOT NULL,
    size_bytes INTEGER,
    mtime REAL,
    atime REAL,
    ctime REAL,
    crtime REAL,
    md5 TEXT,
    sha256 TEXT,
    tlsh TEXT,
    is_allocated INTEGER NOT NULL DEFAULT 1,
    ads_name TEXT,
    vss_snapshot_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_files_evidence ON files(evidence_id);
CREATE INDEX IF NOT EXISTS idx_files_sha256 ON files(sha256);
CREATE INDEX IF NOT EXISTS idx_files_tlsh ON files(tlsh);

CREATE TABLE IF NOT EXISTS indexed_docs (
    file_id INTEGER NOT NULL REFERENCES files(id),
    tantivy_doc_id INTEGER NOT NULL,
    field TEXT NOT NULL,
    PRIMARY KEY (file_id, field)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    row_hash TEXT NOT NULL
);

-- Per-case key/value config (hash policy, examiner-set toggles, etc.)
CREATE TABLE IF NOT EXISTS case_config (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL
);

-- Raw-scan findings: distinct IoC indicators and YARA matches.
-- IoC rows are deduplicated per (kind, subtype, value) with an
-- occurrence count; YARA rows are per (rule, source).
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id INTEGER NOT NULL REFERENCES evidence(id),
    kind TEXT NOT NULL,          -- 'ioc' | 'yara'
    subtype TEXT NOT NULL,       -- ioc: email/url/...  yara: rule name
    value TEXT NOT NULL,         -- the indicator value / matched source
    count INTEGER NOT NULL DEFAULT 1,
    first_offset INTEGER,
    added_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_ev ON findings(evidence_id);
CREATE INDEX IF NOT EXISTS idx_findings_kind ON findings(kind, subtype);
"""

SCHEMA_VERSION = 1


@dataclass
class CaseMeta:
    id: str
    name: str
    examiner: str
    created_at: float


class Case:
    """Open or create a forensic case directory.

    Layout on disk:
      <case_dir>/
        case.db                  this SQLite
        manifest.json            current state manifest (regenerated on close)
        manifest.sig             Ed25519 signature
        index/                   Tantivy index root
        keys/                    Ed25519 keypair for this case
        evidence/                symlinks/copies of source E01 sets (optional)
    """

    def __init__(self, root: Path):
        self.root = Path(root)
        self.db_path = self.root / "case.db"
        self.index_dir = self.root / "index"
        self.keys_dir = self.root / "keys"
        self.evidence_dir = self.root / "evidence"
        self._conn: sqlite3.Connection | None = None

    # ---- lifecycle -------------------------------------------------------

    @classmethod
    def create(cls, root: Path, name: str, examiner: str,
               hash_policy_json: str | None = None) -> "Case":
        root = Path(root)
        root.mkdir(parents=True, exist_ok=False)
        c = cls(root)
        c.index_dir.mkdir(exist_ok=True)
        c.keys_dir.mkdir(exist_ok=True)
        c.evidence_dir.mkdir(exist_ok=True)
        with c.connect() as conn:
            conn.executescript(SCHEMA)
            conn.execute(
                "INSERT INTO case_meta(id, name, examiner, created_at, schema_version) VALUES (?,?,?,?,?)",
                (str(uuid.uuid4()), name, examiner, time.time(), SCHEMA_VERSION),
            )
            if hash_policy_json:
                conn.execute(
                    "INSERT OR REPLACE INTO case_config(key, value_json) VALUES (?,?)",
                    ("hash_policy", hash_policy_json),
                )
        c.log("case.create", {"name": name, "examiner": examiner,
                              "hash_policy": hash_policy_json or "(default)"})
        return c

    @classmethod
    def open(cls, root: Path) -> "Case":
        c = cls(root)
        if not c.db_path.exists():
            raise FileNotFoundError(f"No case.db at {c.db_path}")
        with c.connect() as conn:
            conn.executescript(SCHEMA)  # idempotent — migrate-friendly
        c.log("case.open", {})
        return c

    # ---- connection ------------------------------------------------------

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(self.db_path, isolation_level=None)  # autocommit-ish
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
        finally:
            conn.close()

    # ---- config (hash policy etc.) --------------------------------------

    def get_config(self, key: str, default: str | None = None) -> str | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT value_json FROM case_config WHERE key=?", (key,)
            ).fetchone()
        return row[0] if row else default

    def set_config(self, key: str, value_json: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO case_config(key, value_json) VALUES (?,?)",
                (key, value_json),
            )
        self.log("case.config", {"key": key, "value": value_json[:200]})

    def hash_policy(self):
        """Returns the case's HashPolicy (parsed). Always returns a policy."""
        from app.core.hash_policy import HashPolicy
        return HashPolicy.from_json(self.get_config("hash_policy"))

    def meta(self) -> CaseMeta:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT id, name, examiner, created_at FROM case_meta LIMIT 1"
            ).fetchone()
        if not row:
            raise RuntimeError("case_meta missing")
        return CaseMeta(*row)

    # ---- evidence --------------------------------------------------------

    def add_evidence(self, path: str, fmt: str, size: int | None,
                     md5: str | None, sha256: str | None, notes: str = "") -> int:
        eu = str(uuid.uuid4())
        with self.connect() as conn:
            cur = conn.execute(
                "INSERT INTO evidence(evidence_uuid, path, format, size_bytes, "
                "acquired_md5, acquired_sha256, notes, added_at) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (eu, path, fmt, size, md5, sha256, notes, time.time()),
            )
            ev_id = cur.lastrowid
        self.log("evidence.add", {"evidence_uuid": eu, "path": path, "format": fmt})
        return int(ev_id)

    def list_evidence(self) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT id, evidence_uuid, path, format, size_bytes, acquired_md5, "
                "acquired_sha256, added_at FROM evidence ORDER BY id"
            ).fetchall()
        cols = ["id", "evidence_uuid", "path", "format", "size_bytes",
                "acquired_md5", "acquired_sha256", "added_at"]
        return [dict(zip(cols, r)) for r in rows]

    # ---- files -----------------------------------------------------------

    def add_files(self, evidence_id: int, rows: Iterable[dict]) -> int:
        n = 0
        with self.connect() as conn:
            conn.execute("BEGIN")
            for r in rows:
                conn.execute(
                    "INSERT INTO files(evidence_id, inode, path, name, size_bytes, "
                    "mtime, atime, ctime, crtime, md5, sha256, tlsh, "
                    "is_allocated, ads_name, vss_snapshot_id) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (evidence_id, r.get("inode"), r["path"], r["name"], r.get("size_bytes"),
                     r.get("mtime"), r.get("atime"), r.get("ctime"), r.get("crtime"),
                     r.get("md5"), r.get("sha256"), r.get("tlsh"),
                     1 if r.get("is_allocated", True) else 0,
                     r.get("ads_name"), r.get("vss_snapshot_id")),
                )
                n += 1
            conn.execute("COMMIT")
        return n

    # ---- findings (raw-scan IoC / YARA) ----------------------------------

    def add_findings(self, evidence_id: int, rows: Iterable[dict]) -> int:
        """Bulk-insert raw-scan findings. Each row dict needs:
        kind, subtype, value, and optionally count / first_offset.
        """
        n = 0
        now = time.time()
        with self.connect() as conn:
            conn.execute("BEGIN")
            for r in rows:
                conn.execute(
                    "INSERT INTO findings(evidence_id, kind, subtype, value, "
                    "count, first_offset, added_at) VALUES (?,?,?,?,?,?,?)",
                    (evidence_id, r["kind"], r["subtype"], r["value"],
                     int(r.get("count", 1)), r.get("first_offset"), now),
                )
                n += 1
            conn.execute("COMMIT")
        return n

    def list_findings(self, kind: str | None = None,
                      subtype: str | None = None,
                      search: str | None = None,
                      limit: int = 2000) -> list[dict]:
        q = ("SELECT id, evidence_id, kind, subtype, value, count, "
             "first_offset, added_at FROM findings")
        clauses: list[str] = []
        params: list[Any] = []
        if kind:
            clauses.append("kind = ?")
            params.append(kind)
        if subtype:
            clauses.append("subtype = ?")
            params.append(subtype)
        if search:
            clauses.append("value LIKE ?")
            params.append(f"%{search}%")
        if clauses:
            q += " WHERE " + " AND ".join(clauses)
        q += " ORDER BY count DESC, id ASC LIMIT ?"
        params.append(limit)
        with self.connect() as conn:
            rows = conn.execute(q, params).fetchall()
        cols = ["id", "evidence_id", "kind", "subtype", "value", "count",
                "first_offset", "added_at"]
        return [dict(zip(cols, r)) for r in rows]

    def findings_summary(self) -> dict[str, dict[str, int]]:
        """Return {kind: {subtype: total_count}} across the case."""
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT kind, subtype, SUM(count) FROM findings "
                "GROUP BY kind, subtype"
            ).fetchall()
        out: dict[str, dict[str, int]] = {}
        for kind, subtype, total in rows:
            out.setdefault(kind, {})[subtype] = int(total or 0)
        return out

    def carved_files(self, search: str | None = None,
                     limit: int = 2000) -> list[dict]:
        """Carved files are recorded in the files table with a
        /(carved)/ path prefix — surface them for the Findings view.
        """
        q = ("SELECT id, evidence_id, path, name, size_bytes, md5, sha256, "
             "tlsh FROM files WHERE path LIKE '/(carved)/%'")
        params: list[Any] = []
        if search:
            q += " AND (name LIKE ? OR sha256 LIKE ?)"
            params += [f"%{search}%", f"%{search}%"]
        q += " ORDER BY size_bytes DESC LIMIT ?"
        params.append(limit)
        with self.connect() as conn:
            rows = conn.execute(q, params).fetchall()
        cols = ["id", "evidence_id", "path", "name", "size_bytes",
                "md5", "sha256", "tlsh"]
        return [dict(zip(cols, r)) for r in rows]

    # ---- audit log -------------------------------------------------------

    def log(self, action: str, payload: dict[str, Any], actor: str = "examiner") -> None:
        with self.connect() as conn:
            prev = conn.execute(
                "SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1"
            ).fetchone()
            prev_hash = prev[0] if prev else ("0" * 64)
            ts = time.time()
            payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            canon = f"{ts}|{actor}|{action}|{payload_json}|{prev_hash}".encode("utf-8")
            row_hash = hashlib.sha256(canon).hexdigest()
            conn.execute(
                "INSERT INTO audit_log(ts, actor, action, payload_json, prev_hash, row_hash) "
                "VALUES (?,?,?,?,?,?)",
                (ts, actor, action, payload_json, prev_hash, row_hash),
            )

    def audit_rows(self, limit: int = 500) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT id, ts, actor, action, payload_json, prev_hash, row_hash "
                "FROM audit_log ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        cols = ["id", "ts", "actor", "action", "payload_json", "prev_hash", "row_hash"]
        return [dict(zip(cols, r)) for r in rows]

    def verify_audit_chain(self) -> tuple[bool, str]:
        """Return (ok, message). Walks the chain forward and re-derives each row_hash."""
        prev_hash = "0" * 64
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT id, ts, actor, action, payload_json, prev_hash, row_hash "
                "FROM audit_log ORDER BY id ASC"
            ).fetchall()
        for r in rows:
            rid, ts, actor, action, payload_json, stored_prev, stored_hash = r
            if stored_prev != prev_hash:
                return False, f"prev_hash mismatch at row {rid}"
            canon = f"{ts}|{actor}|{action}|{payload_json}|{stored_prev}".encode("utf-8")
            recomputed = hashlib.sha256(canon).hexdigest()
            if recomputed != stored_hash:
                return False, f"row_hash mismatch at row {rid}"
            prev_hash = stored_hash
        return True, f"chain verified across {len(rows)} rows"
