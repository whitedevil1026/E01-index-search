"""Known-file hash sets (NSRL RDS and friends).

The implementation plan called this the single biggest hit-rate reducer
in indexed forensic search and put it in Phase 0. It was never built, so
every ingest treated a stock `kernel32.dll` exactly like a document the
suspect wrote.

What this does
--------------
A hash set is a list of hashes of files already known to the world —
operating-system and application files shipped by vendors. Matching the
evidence against it separates "came with the machine" from "was put
there", which is usually the first question worth asking.

The store lives OUTSIDE any single case (`known_sets.db`, next to the
application by default) because a hash set is reference data, not
evidence: importing NSRL once serves every case afterwards. That also
satisfies the plan's cross-case hash deduplication item.

The forensic rule this module enforces
--------------------------------------
**A known-file match annotates; it never deletes.** Hiding "known" files
from results is a view option, off by default, and whenever it is on the
UI states how many rows it is hiding. The reasons matter:

* A hash set is not a statement of innocence. Attackers ship legitimate
  signed binaries (`certutil.exe`, `psexec.exe`) and use them as the
  attack. NSRL contains them.
* A hash set can be wrong or stale, and a file altered by one byte no
  longer matches at all.
* Silently removing rows from an examiner's view is the same failure as
  a capped result list that does not say it is capped.

So nothing is ever dropped from the index or the database — only
labelled, and the label is recorded per file with the set it came from.

Probabilistic filters are deliberately NOT supported for exclusion.
CIRCL publishes a ~700 MB Bloom filter of the NSRL SHA-1 space, which is
attractive for size, but a Bloom filter has false positives by
construction: it can claim a file is known when it is not. Marking a
suspect's file "known" on a false positive is exactly the error that
loses evidence, so a Bloom filter may only ever drive a soft hint, never
the `known` flag. Only exact hash sets are accepted here.

Import sources
--------------
``nsrl``   An RDSv3 SQLite publication (full or minimal). The schema is
           fixed by NIST::

               CREATE TABLE FILE (
                   sha256 VARCHAR NOT NULL, sha1 VARCHAR NOT NULL,
                   md5 VARCHAR NOT NULL, crc32 VARCHAR NOT NULL,
                   file_name VARCHAR NOT NULL, file_size INTEGER NOT NULL,
                   package_id INTEGER NOT NULL, ...)

           NIST retired the old RDS 2.xx text format; RDSv3 SQLite is
           what is published now. A full Modern set is hundreds of GB
           unzipped, so the minimal publication (same FILE view, far
           smaller) is the practical choice.

``hashes`` A plain text file, one hash per line, MD5 / SHA-1 / SHA-256
           in any mix, `#` comments allowed. This is the universal path:
           every hash-set vendor and every `hashdeep`/`md5sum` run can
           produce it, and it needs no network.

``csv``    A delimited file with a header naming at least one hash
           column (md5 / sha1 / sha256, case-insensitive).
"""
from __future__ import annotations

import csv as _csv
import os
import re
import sqlite3
import time
import urllib.parse
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Optional

# Lengths used to tell one hash algorithm from another by sight.
_HASH_LEN = {32: "md5", 40: "sha1", 64: "sha256"}
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

SCHEMA = """
CREATE TABLE IF NOT EXISTS hash_set (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    source_path TEXT,
    kind TEXT NOT NULL,          -- nsrl | hashes | csv
    imported_at REAL NOT NULL,
    n_hashes INTEGER NOT NULL DEFAULT 0,
    -- 0 when the import was cancelled or limited, so a partial set
    -- can never be mistaken for full coverage.
    complete INTEGER NOT NULL DEFAULT 1,
    source_rows INTEGER,
    notes TEXT
);

-- One row per (set, algorithm, hash). Kept narrow on purpose: this
-- table reaches hundreds of millions of rows on a full NSRL import, so
-- it carries no file names or vendor metadata.
CREATE TABLE IF NOT EXISTS known_hash (
    set_id INTEGER NOT NULL REFERENCES hash_set(id) ON DELETE CASCADE,
    algo TEXT NOT NULL,          -- md5 | sha1 | sha256
    hash TEXT NOT NULL,          -- lowercase hex
    PRIMARY KEY (algo, hash, set_id)
) WITHOUT ROWID;
"""


@dataclass
class HashSetInfo:
    id: int
    name: str
    kind: str
    n_hashes: int
    imported_at: float
    source_path: str = ""
    complete: bool = True
    notes: str = ""

    def describe(self) -> str:
        when = time.strftime("%Y-%m-%d %H:%M",
                             time.localtime(self.imported_at))
        flag = "" if self.complete else "  [PARTIAL]"
        return (f"{self.name}  ({self.kind}, {self.n_hashes:,} hashes, "
                f"imported {when}){flag}")


def _ro_uri(path: str | Path) -> str:
    """A read-only SQLite URI for `path`, correctly escaped.

    Raw concatenation was wrong: a `#` in the path starts a URI
    fragment, so `?mode=ro` was swallowed and never applied — SQLite
    then opened a DIFFERENT, truncated path read-WRITE and created a
    file there. A `%` was misread as a percent-escape. Reference data
    filed under e.g. `NSRL#2024Q3\rds.db` hit both faults.
    """
    posix = Path(path).resolve().as_posix()
    return "file:/" + urllib.parse.quote(posix.lstrip("/"), safe="/:") + "?mode=ro"


def normalise_hash(value: str) -> tuple[str, str] | None:
    """('sha256', '<lowercase hex>') for a recognisable hash, else None."""
    if not value:
        return None
    v = value.strip().strip('"').strip("'").lower()
    algo = _HASH_LEN.get(len(v))
    if algo is None or not _HEX_RE.match(v):
        return None
    return algo, v


class KnownSetStore:
    """SQLite store of known-file hash sets, shared across cases."""

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.executescript(SCHEMA)
            self._migrate(conn)

    # Columns added to hash_set after the first release. CREATE TABLE IF
    # NOT EXISTS will not add a column to a table that already exists,
    # so a store written by an earlier build needs them backfilled —
    # otherwise list_sets() fails with "no such column: complete".
    _ADDED_COLUMNS = (
        ("complete", "INTEGER NOT NULL DEFAULT 1"),
        ("source_rows", "INTEGER"),
        ("notes", "TEXT"),
    )

    @classmethod
    def _migrate(cls, conn) -> None:
        have = {r[1] for r in conn.execute(
            "PRAGMA table_info(hash_set)").fetchall()}
        for name, decl in cls._ADDED_COLUMNS:
            if name not in have:
                conn.execute(
                    f"ALTER TABLE hash_set ADD COLUMN {name} {decl}")

    @contextmanager
    def connect(self):
        """A closing context manager, mirroring Case.connect().

        The earlier version returned a bare connection, so `with` only
        wrapped a transaction and the handle was reclaimed by
        refcounting. foreign_keys is on so that deleting a hash_set row
        actually cascades to its hashes.
        """
        conn = sqlite3.connect(self.db_path, isolation_level=None,
                               timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
        finally:
            conn.close()

    def sweep_orphans(self) -> int:
        """Delete hashes whose set row is gone. Repairs stores written
        by the earlier INSERT OR REPLACE import path."""
        with self.connect() as conn:
            cur = conn.execute(
                "DELETE FROM known_hash WHERE set_id NOT IN "
                "(SELECT id FROM hash_set)")
            return cur.rowcount or 0

    # ---- set management ------------------------------------------------

    def list_sets(self) -> list[HashSetInfo]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT id, name, kind, n_hashes, imported_at, "
                "COALESCE(source_path,''), complete, COALESCE(notes,'') "
                "FROM hash_set WHERE name NOT LIKE '~staging~%' "
                "ORDER BY name"
            ).fetchall()
        return [HashSetInfo(r[0], r[1], r[2], r[3], r[4], r[5],
                            bool(r[6]), r[7]) for r in rows]

    def total_hashes(self) -> int:
        with self.connect() as conn:
            return int(conn.execute(
                "SELECT COALESCE(SUM(n_hashes),0) FROM hash_set "
                "WHERE name NOT LIKE '~staging~%'"
            ).fetchone()[0] or 0)

    def delete_set(self, name: str) -> bool:
        with self.connect() as conn:
            conn.execute("PRAGMA foreign_keys=ON")
            cur = conn.execute("SELECT id FROM hash_set WHERE name=?", (name,))
            row = cur.fetchone()
            if not row:
                return False
            conn.execute("DELETE FROM known_hash WHERE set_id=?", (row[0],))
            conn.execute("DELETE FROM hash_set WHERE id=?", (row[0],))
        return True

    # ---- lookup --------------------------------------------------------

    def lookup(self, *, md5: str = "", sha1: str = "",
               sha256: str = "") -> Optional[str]:
        """Name of the first set containing any of these hashes, else None.

        SHA-256 is tried first: it is the strongest of the three and the
        one an RDSv3 import indexes most usefully.
        """
        # Queried strongest-first in separate statements. A single OR
        # with LIMIT 1 left the choice to SQLite's evaluation order, so
        # which set name got recorded against the evidence could change
        # with the query planner.
        with self.connect() as conn:
            return self._lookup_on(conn, md5=md5, sha1=sha1, sha256=sha256)

    @staticmethod
    def _lookup_on(conn, *, md5: str = "", sha1: str = "",
                   sha256: str = "") -> Optional[str]:
        """lookup() against a caller-supplied connection.

        Opening a connection per file cost 0.77 ms each — about 25
        minutes of pure setup on a two-million-file image — so the
        ingest reuses one connection on its own thread.
        """
        for algo, val in (("sha256", sha256), ("sha1", sha1), ("md5", md5)):
            n = normalise_hash(val or "")
            if not n:
                continue
            row = conn.execute(
                "SELECT s.name FROM known_hash h JOIN hash_set s "
                "ON s.id = h.set_id WHERE h.algo=? AND h.hash=? LIMIT 1",
                (n[0], n[1])).fetchone()
            if row:
                return row[0]
        return None

    def lookup_many(self, hashes: Iterable[str]) -> dict[str, str]:
        """{hash: set_name} for those present. One query per 500 hashes."""
        buckets: dict[str, list[str]] = {}
        for h in hashes:
            n = normalise_hash(h or "")
            if n:
                buckets.setdefault(n[0], []).append(n[1])
        out: dict[str, str] = {}
        with self.connect() as conn:
            for algo, vals in buckets.items():
                for i in range(0, len(vals), 500):
                    chunk = vals[i:i + 500]
                    marks = ",".join("?" * len(chunk))
                    rows = conn.execute(
                        f"SELECT h.hash, s.name FROM known_hash h "
                        f"JOIN hash_set s ON s.id=h.set_id "
                        f"WHERE h.algo=? AND h.hash IN ({marks})",
                        [algo, *chunk]).fetchall()
                    for hsh, name in rows:
                        out[hsh] = name
        return out

    # ---- import --------------------------------------------------------

    @staticmethod
    def _flush(conn, batch: list) -> int:
        """Insert a batch and return how many rows were actually STORED.

        INSERT OR IGNORE drops duplicates, so len(batch) overstates
        coverage — badly on an NSRL import, where one file appears under
        many packages. total_changes is the truth.
        """
        if not batch:
            return 0
        before = conn.total_changes
        conn.executemany(
            "INSERT OR IGNORE INTO known_hash(set_id, algo, hash) "
            "VALUES (?,?,?)", batch)
        stored = conn.total_changes - before
        batch.clear()
        return stored

    def _begin_set(self, conn, name: str, kind: str, source: str) -> int:
        """Create a STAGING set row and return its id.

        The previous version used INSERT OR REPLACE on the real name,
        which deleted the existing set before the import had produced
        anything. A failed or killed import therefore destroyed working
        reference data — an examiner re-importing a new NSRL quarter
        under the same name lost the old one and was left with a row
        reading "0 hashes" plus unreachable rows bloating the store.
        The real name is only taken in _finish_set, after the data is in.
        """
        staging = f"~staging~{time.time()}~{name}"
        conn.execute(
            "INSERT INTO hash_set(name, source_path, kind, imported_at, "
            "n_hashes) VALUES (?,?,?,?,0)",
            (staging, source, kind, time.time()))
        return int(conn.execute("SELECT id FROM hash_set WHERE name=?",
                                (staging,)).fetchone()[0])

    @staticmethod
    def _finish_set(conn, set_id: int, name: str, n_stored: int,
                    complete: bool = True, note: str = "") -> None:
        """Atomically retire any previous set of this name and promote
        the staging set into its place."""
        conn.execute("BEGIN IMMEDIATE")
        try:
            old = conn.execute(
                "SELECT id FROM hash_set WHERE name=? AND id!=?",
                (name, set_id)).fetchall()
            for (oid,) in old:
                conn.execute("DELETE FROM known_hash WHERE set_id=?", (oid,))
                conn.execute("DELETE FROM hash_set WHERE id=?", (oid,))
            conn.execute(
                "UPDATE hash_set SET name=?, n_hashes=?, complete=?, notes=? "
                "WHERE id=?",
                (name, n_stored, 1 if complete else 0, note or None, set_id))
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except Exception:  # noqa: BLE001
                pass
            raise
        conn.execute("COMMIT")

    @staticmethod
    def _discard_set(conn, set_id: int) -> None:
        """Drop a staging set after a failed import, leaving whatever
        was already there untouched."""
        try:
            conn.execute("DELETE FROM known_hash WHERE set_id=?", (set_id,))
            conn.execute("DELETE FROM hash_set WHERE id=?", (set_id,))
        except Exception:  # noqa: BLE001
            pass

    def import_hash_list(self, path: str | Path, name: str,
                         progress_cb: Optional[Callable[[int], None]] = None
                         ) -> int:
        """Import a plain one-hash-per-line file.

        Returns the number of hashes actually STORED (duplicates in the
        source are not counted twice).
        """
        path = Path(path)
        stored = 0
        skipped = 0
        with self.connect() as conn:
            set_id = self._begin_set(conn, name, "hashes", str(path))
            try:
                conn.execute("BEGIN")
                batch: list[tuple] = []
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        # Tolerate `hash  filename`, as md5sum writes.
                        n = normalise_hash(line.split()[0])
                        if not n:
                            skipped += 1
                            continue
                        batch.append((set_id, n[0], n[1]))
                        if len(batch) >= 20000:
                            stored += self._flush(conn, batch)
                            if progress_cb:
                                progress_cb(stored)
                stored += self._flush(conn, batch)
                conn.execute("COMMIT")
            except Exception:
                try:
                    conn.execute("ROLLBACK")
                except Exception:  # noqa: BLE001
                    pass
                self._discard_set(conn, set_id)
                raise
            self._finish_set(conn, set_id, name, stored, True,
                             self._skip_note(skipped))
        if progress_cb:
            progress_cb(stored)
        return stored

    @staticmethod
    def _skip_note(skipped: int) -> str:
        """Unusable source rows are reported, not silently dropped."""
        return (f"{skipped:,} source rows had no usable MD5/SHA-1/SHA-256"
                if skipped else "")

    def import_csv(self, path: str | Path, name: str,
                   progress_cb: Optional[Callable[[int], None]] = None) -> int:
        """Import a delimited file whose header names a hash column."""
        path = Path(path)
        stored = 0
        skipped = 0
        with open(path, "r", encoding="utf-8", errors="replace",
                  newline="") as fh:
            sample = fh.read(8192)
            fh.seek(0)
            try:
                dialect = _csv.Sniffer().sniff(sample, delimiters=",;	|")
            except Exception:  # noqa: BLE001
                dialect = _csv.excel
            reader = _csv.DictReader(fh, dialect=dialect)
            cols = [c for c in (reader.fieldnames or [])
                    if c and c.strip().lower().replace("-", "") in
                    ("md5", "sha1", "sha256")]
            if not cols:
                raise ValueError(
                    "no md5 / sha1 / sha256 column found in the header; "
                    "use the plain hash-list import instead")
            with self.connect() as conn:
                set_id = self._begin_set(conn, name, "csv", str(path))
                try:
                    conn.execute("BEGIN")
                    batch: list[tuple] = []
                    for row in reader:
                        for c in cols:
                            n = normalise_hash(row.get(c) or "")
                            if n:
                                batch.append((set_id, n[0], n[1]))
                            else:
                                skipped += 1
                        if len(batch) >= 20000:
                            stored += self._flush(conn, batch)
                            if progress_cb:
                                progress_cb(stored)
                    stored += self._flush(conn, batch)
                    conn.execute("COMMIT")
                except Exception:
                    try:
                        conn.execute("ROLLBACK")
                    except Exception:  # noqa: BLE001
                        pass
                    self._discard_set(conn, set_id)
                    raise
                self._finish_set(conn, set_id, name, stored, True,
                                 self._skip_note(skipped))
        if progress_cb:
            progress_cb(stored)
        return stored

    # ---- NSRL RDSv3 ----------------------------------------------------

    @staticmethod
    def inspect_nsrl(path: str | Path) -> dict:
        """Report what an RDSv3 publication contains, without importing.

        Checked before an import because the full Modern set is hundreds
        of GB and the examiner should see the row count first.
        """
        path = Path(path)
        out = {"path": str(path), "ok": False, "n_files": 0,
               "columns": [], "note": ""}
        if not path.exists():
            out["note"] = "file not found"
            return out
        try:
            conn = sqlite3.connect(_ro_uri(path), uri=True, timeout=30.0)
        except Exception as exc:  # noqa: BLE001
            out["note"] = f"cannot open as SQLite: {exc}"
            return out
        try:
            tabs = {r[0].upper() for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type IN "
                "('table','view')")}
            if "FILE" not in tabs:
                out["note"] = ("no FILE table/view — this does not look "
                               "like an RDSv3 publication")
                return out
            cols = [r[1].lower() for r in conn.execute(
                "PRAGMA table_info(FILE)")]
            if not cols:                     # FILE is a view
                cur = conn.execute("SELECT * FROM FILE LIMIT 1")
                cols = [d[0].lower() for d in (cur.description or [])]
            out["columns"] = cols
            have = [c for c in ("sha256", "sha1", "md5") if c in cols]
            if not have:
                out["note"] = "FILE has no md5/sha1/sha256 column"
                return out
            out["n_files"] = int(conn.execute(
                "SELECT COUNT(*) FROM FILE").fetchone()[0] or 0)
            out["hash_columns"] = have
            out["ok"] = True
            out["note"] = f"RDSv3 FILE with {', '.join(have)}"
        except Exception as exc:  # noqa: BLE001
            out["note"] = f"error reading publication: {exc}"
        finally:
            conn.close()
        return out

    def import_nsrl(self, path: str | Path, name: str,
                    algos: Iterable[str] = ("sha256", "md5"),
                    limit: int = 0,
                    progress_cb: Optional[Callable[[int], None]] = None,
                    cancel_cb: Optional[Callable[[], bool]] = None) -> int:
        """Import hashes from an RDSv3 SQLite publication.

        Only the requested hash columns are copied. Importing just the
        algorithms the case policy actually computes keeps the store a
        fraction of the size of the publication; the default matches the
        tool's default policy (SHA-256 + MD5).

        The publication is opened READ-ONLY — it is reference data and is
        never modified.
        """
        info = self.inspect_nsrl(path)
        if not info["ok"]:
            raise ValueError(info["note"])
        cols = [a for a in algos if a in info.get("hash_columns", [])]
        if not cols:
            raise ValueError(
                f"none of {list(algos)} are present; this publication has "
                f"{info.get('hash_columns')}")

        src = sqlite3.connect(_ro_uri(path), uri=True, timeout=30.0)
        stored = 0
        skipped = 0
        cancelled = False
        total_rows = info.get("n_files", 0)
        try:
            q = f"SELECT {', '.join(cols)} FROM FILE"
            if limit:
                q += f" LIMIT {int(limit)}"
            seen_rows = 0
            with self.connect() as conn:
                set_id = self._begin_set(conn, name, "nsrl", str(path))
                try:
                    conn.execute("BEGIN")
                    batch: list[tuple] = []
                    for row in src.execute(q):
                        if cancel_cb and cancel_cb():
                            cancelled = True
                            break
                        seen_rows += 1
                        for algo, val in zip(cols, row):
                            n = normalise_hash(val or "")
                            if n:
                                batch.append((set_id, n[0], n[1]))
                            else:
                                skipped += 1
                        if len(batch) >= 20000:
                            stored += self._flush(conn, batch)
                            if progress_cb:
                                progress_cb(stored)
                    stored += self._flush(conn, batch)
                    conn.execute("COMMIT")
                except Exception:
                    try:
                        conn.execute("ROLLBACK")
                    except Exception:  # noqa: BLE001
                        pass
                    self._discard_set(conn, set_id)
                    raise
                # A cancelled or limited import must never look complete:
                # half of NSRL is indistinguishable from all of it unless
                # the set says so.
                notes = []
                if cancelled:
                    notes.append(f"CANCELLED after {seen_rows:,} of "
                                 f"{total_rows:,} FILE rows")
                if limit:
                    notes.append(f"limited to {int(limit):,} FILE rows")
                sk = self._skip_note(skipped)
                if sk:
                    notes.append(sk)
                conn.execute("UPDATE hash_set SET source_rows=? WHERE id=?",
                             (total_rows, set_id))
                self._finish_set(conn, set_id, name, stored,
                                 complete=not (cancelled or bool(limit)),
                                 note="; ".join(notes))
        finally:
            src.close()
        if progress_cb:
            progress_cb(stored)
        return stored


def default_store_path() -> Path:
    """Where the shared hash-set store lives.

    Beside the application, not inside a case: a hash set is reference
    data reused by every case. Override with E01_KNOWN_SETS_DB.
    """
    env = os.environ.get("E01_KNOWN_SETS_DB")
    if env:
        return Path(env)
    return Path(__file__).resolve().parent.parent.parent / "known_sets.db"
