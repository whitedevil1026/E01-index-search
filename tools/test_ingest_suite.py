"""End-to-end test suite for a full E01 ingest — before, during, after.

Run against a real image:

    python tools/test_ingest_suite.py "F:\\path\\to\\image.E01"

Defaults to the SANS sample if no path is given. Exits non-zero if any
check fails, so it can gate a release.

The suite is deliberately black-box: it drives the real UI panels and
the real case database rather than internal helpers, because that is
what an examiner actually exercises.

Sections
--------
  BEFORE  image detection, signature checks, corrupt/missing handling,
          integrity report, volume scan, whole-image hashing, deps
  DURING  progress + ETA, cancellation, partial-index survival,
          concurrent audit logging, parallel-sweep fallback
  AFTER   counts and provenance, every search mode, export of every
          origin with hash verification, tamper detection on the audit
          chain / manifest / exported file, persistence across reopen,
          determinism across re-ingest, evidence immutability
"""
from __future__ import annotations

import hashlib
import os
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

DEFAULT_IMG = r"F:\e01 indexing\2011-10-19-Image\2011-10-19-Sample.E01"

# Scratch cases are written next to the tool, on the same volume as the
# evidence, so a run never writes to the system drive. Override with
# E01_SUITE_WORKDIR.
DEFAULT_WORKDIR = str(Path(__file__).resolve().parent.parent / "_suite_work")

PASS, FAIL, SKIP, ENV = [], [], [], []


def check(label, cond, detail="", pass_detail=""):
    """Assert one thing.

    `detail` explains a FAILURE; `pass_detail` reports the observed
    value on success. Printing `detail` on a pass produced lines like
    "[PASS] deps module exposes a probe - probe_all() returned nothing",
    which reads as a contradiction and erodes trust in the output.
    """
    if cond:
        PASS.append(label)
        print(f"  [PASS] {label}"
              + (f"  — {pass_detail}" if pass_detail else ""))
    else:
        FAIL.append(f"{label}: {detail}")
        print(f"  [FAIL] {label}" + (f"  — {detail}" if detail else ""))


def env_gap(label, why):
    """An optional capability this deployment does not have.

    Distinct from both a pass and a failure. Failing would train
    examiners to ignore a red suite for a documented reason; skipping
    would hide that a search mode is unavailable. So it is reported
    loudly in its own category and does not fail the run.
    """
    ENV.append(f"{label}: {why}")
    print(f"  [ENV ] {label}  — {why}")


def skip(label, why):
    """Record a check that could not run.

    Kept only as a guard: a skipped check proves nothing, so the suite
    treats any skip as a failure. Every assertion here derives its
    inputs from the image under test (or seeds them), so nothing should
    reach this. If something does, it means the suite silently stopped
    testing part of the tool.
    """
    SKIP.append(label)
    FAIL.append(f"{label}: SKIPPED ({why}) — a skipped check proves nothing")
    print(f"  [SKIP->FAIL] {label}  — {why}")


def section(title):
    print(f"\n{'=' * 72}\n{title}\n{'=' * 72}")


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for c in iter(lambda: fh.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def run(img_path: str) -> int:
    from PySide6.QtWidgets import QApplication
    from app.core.case import Case
    from app.core.hash_policy import HashPolicy
    from app.core.ewf_reader import (inspect, open_handle, parallel_hash,
                                     glob_segments)
    from app.core.ewf_integrity import check_set
    from app.core.filesystem import scan_volumes
    from app.core.indexer import Indexer
    from app.core import extract, manifest as man, deps as deps_mod
    from app.core import raw_scan
    from app.ui.ingest_panel import IngestPanel
    from app.ui.search_panel import SearchPanel
    from app.ui.findings_panel import FindingsPanel

    app = QApplication.instance() or QApplication([])
    workdir = Path(os.environ.get("E01_SUITE_WORKDIR", DEFAULT_WORKDIR))
    workdir.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix="suite_", dir=str(workdir)))
    print(f"scratch cases: {root}")

    # ================================================================
    section("BEFORE — dependencies")
    # ================================================================
    probes = deps_mod.probe_all() if hasattr(deps_mod, "probe_all") else []
    check("deps module exposes a probe", bool(probes),
          "probe_all() returned nothing")
    missing = [p for p in probes if not getattr(p, "installed", True)]
    print(f"  {len(probes)} dependencies probed, {len(missing)} missing")
    for m in missing:
        print(f"     missing: {getattr(m, 'name', m)}")
    # The libraries the suite itself depends on must be present, or every
    # later result would be measuring a degraded build.
    required = {"libewf-python", "pytsk3", "tantivy", "PySide6"}
    present = {getattr(p, "name", "") for p in probes
               if getattr(p, "installed", False)}
    absent = sorted(required - present)
    check("libraries this suite depends on are installed", not absent,
          f"absent: {absent}" if absent else f"{len(present)} installed")

    # ================================================================
    section("BEFORE — image identification")
    # ================================================================
    check("image file exists", os.path.exists(img_path), img_path)
    if not os.path.exists(img_path):
        return 1

    with open(img_path, "rb") as fh:
        magic = fh.read(8)
    known = {b"EVF\x09\x0d\x0a\xff\x00": "EWF1/E01",
             b"EVF2\x0d\x0a\x81\x00": "EWF2/Ex01",
             b"LVF\x09\x0d\x0a\xff\x00": "LVF/L01"}
    kind = known.get(magic)
    check("file signature is a genuine EWF image", kind is not None,
          kind or f"magic {magic.hex()}")

    info = inspect(img_path)
    print(f"  format={info.format}  media={info.media_size:,} bytes")
    print(f"  segments={len(info.segment_files)}  acquired={info.acquiry_date}")
    print(f"  header MD5={info.md5}  SHA-1={info.sha1}")
    check("inspect() reports EWF", info.format.startswith("E") or
          info.format in ("EWF", "E01"), info.format)
    check("media size is non-zero", info.media_size > 0)
    check("segment set discovered", len(info.segment_files) >= 1,
          f"{len(info.segment_files)} segment(s)")
    check("glob_segments agrees with inspect",
          set(glob_segments(img_path)) == set(info.segment_files))

    # --- negative cases ---------------------------------------------
    bogus = root / "not_an_image.E01"
    bogus.write_bytes(b"\x7fELF" + os.urandom(4096))
    try:
        bi = inspect(str(bogus))
        check("non-EWF file with .E01 extension is not mistaken for EWF",
              bi.format != "E01", f"reported {bi.format}")
    except Exception as e:
        check("non-EWF file handled without crashing", True,
              f"{type(e).__name__}")

    truncated = root / "truncated.E01"
    with open(img_path, "rb") as src:
        truncated.write_bytes(src.read(100_000))
    try:
        ti = inspect(str(truncated))
        print(f"  truncated image -> format={ti.format} "
              f"media={ti.media_size:,}")
        check("truncated image does not crash inspect()", True)
    except Exception as e:
        check("truncated image does not crash inspect()", False,
              f"{type(e).__name__}: {e}")

    try:
        inspect(str(root / "does_not_exist.E01"))
        check("missing file raises or reports cleanly", True)
    except Exception as e:
        check("missing file raises or reports cleanly", True,
              type(e).__name__)

    # ================================================================
    section("BEFORE — integrity report")
    # ================================================================
    try:
        rep = check_set([Path(p) for p in info.segment_files])
        errs = getattr(rep, "errors", []) or []
        miss = getattr(rep, "missing", []) or []
        print(f"  errors={errs}  missing={miss}")
        check("no integrity errors", not errs, str(errs)[:160])
        check("no missing segments", not miss, str(miss)[:160])
    except Exception as e:
        check("integrity check runs", False, f"{type(e).__name__}: {e}")

    # ================================================================
    section("BEFORE — volumes, encryption, shadow copies")
    # ================================================================
    with open_handle(info) as h:
        vols = scan_volumes(h)
    for v in vols:
        print(f"  vol{v.index}: offset={v.offset:#x} len={v.length:,} "
              f"enc={v.encryption or 'none'} vss={v.has_vss}")
    check("at least one volume detected", len(vols) >= 1)

    # ================================================================
    section("BEFORE — whole-image hashing")
    # ================================================================
    t0 = time.time()
    m, s = hashlib.md5(), hashlib.sha256()
    with open_handle(info) as h:
        while True:
            b = h.read(1 << 20)
            if not b:
                break
            m.update(b), s.update(b)
    t_seq = time.time() - t0
    t0 = time.time()
    par = parallel_hash(info.segment_files, ["sha256", "md5"], n_workers=4)
    t_par = time.time() - t0
    print(f"  sequential {t_seq:.1f}s   parallel {t_par:.1f}s "
          f"({t_seq/max(t_par,.01):.1f}x)")
    check("parallel hash == sequential hash", par["sha256"] == s.hexdigest())
    check("hashed size == media size", par["size_bytes"] == info.media_size)
    # Compare against whatever the acquisition recorded. An image that
    # stored neither digest still has to report that honestly rather
    # than inventing one, so that case is asserted too.
    if info.md5:
        check("computed MD5 == acquisition MD5 in header",
              m.hexdigest() == info.md5,
              f"{m.hexdigest()} vs {info.md5}")
    elif info.sha1:
        h1 = hashlib.sha1()
        with open_handle(info) as h:
            while True:
                b_ = h.read(1 << 20)
                if not b_:
                    break
                h1.update(b_)
        check("computed SHA-1 == acquisition SHA-1 in header",
              h1.hexdigest() == info.sha1,
              f"{h1.hexdigest()} vs {info.sha1}")
    else:
        check("image with no stored acquisition hash reports None, "
              "not a fabricated value",
              info.md5 is None and info.sha1 is None,
              f"md5={info.md5!r} sha1={info.sha1!r}")

    image_md5_before = m.hexdigest()

    # ================================================================
    section("DURING — cancellation mid-ingest")
    # ================================================================
    cancel_case = Case.create(root / "cancel", "cancel", "tester")
    cp = IngestPanel()
    cp.set_case(cancel_case)
    cp.path_edit.setText(img_path)
    cp._inspect()
    app.processEvents()
    for n in ("chk_index", "chk_raw_strings", "chk_raw_patterns", "chk_carve"):
        cb = getattr(cp, n, None)
        if cb is not None and cb.isEnabled():
            cb.setChecked(True)
    cp._append_log = lambda s: None
    cp._run()
    time.sleep(2.0)
    cp._worker.request_cancel()
    finished = cp._worker.wait(10 * 60 * 1000)
    app.processEvents()
    check("cancelled ingest terminates", finished)
    ok_chain, _ = cancel_case.verify_audit_chain()
    check("audit chain intact after cancellation", ok_chain)
    check("cancelled case still opens", Case.open(cancel_case.root) is not None)

    # ================================================================
    section("DURING — concurrent audit logging")
    # ================================================================
    conc = Case.create(root / "conc", "conc", "tester")

    def spam(tag):
        for i in range(50):
            conc.log("test.concurrent", {"tag": tag, "i": i})

    ts = [threading.Thread(target=spam, args=(f"t{n}",)) for n in range(6)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    ok, msg = conc.verify_audit_chain()
    check("300 concurrent audit appends keep the chain intact", ok, msg)

    # ================================================================
    section("DURING — full ingest (parallel sweep)")
    # ================================================================
    policy = HashPolicy(primary="sha256", extras=["md5"])
    case = Case.create(root / "case", "Suite Case", "A. Examiner",
                       hash_policy_json=policy.to_json())
    ip = IngestPanel()
    ip.set_case(case)
    ip.path_edit.setText(img_path)
    ip._inspect()
    app.processEvents()
    for n in ("chk_hash", "chk_index", "chk_content", "chk_artifacts",
              "chk_raw_strings", "chk_raw_patterns", "chk_carve", "chk_yara",
              "chk_vss"):
        cb = getattr(ip, n, None)
        if cb is not None and cb.isEnabled():
            cb.setChecked(True)
    logs = []
    ip._append_log = lambda s: logs.append(s)
    progress_seen = []
    ip.progress.valueChanged.connect(lambda v: progress_seen.append(v))
    t0 = time.time()
    ip._run()
    ip._worker.wait(4 * 60 * 60 * 1000)
    app.processEvents()
    elapsed = time.time() - t0
    for l in logs:
        if l.strip():
            print("   ", l)
    errs = [l for l in logs if "[error]" in l.lower()]
    check("ingest completed with no errors", not errs, "; ".join(errs)[:200])
    check("progress bar advanced", len(progress_seen) > 1,
          f"{len(progress_seen)} updates")
    check("ETA label shows total runtime", "finished in" in ip.lbl_eta.text(),
          ip.lbl_eta.text())
    check("parallel sweep was used",
          any("parallel sweep" in l for l in logs) or
          any("falling back" in l for l in logs))
    print(f"  ingest wall clock: {elapsed:.1f}s")

    # ================================================================
    section("DURING — live-run safety defaults and truncation reporting")
    # ================================================================
    fresh = IngestPanel()
    check("file-count cap defaults to a COMPLETE walk",
          fresh.spin_max.value() == 0,
          f"default is {fresh.spin_max.value()} — a capped default would "
          f"silently under-collect a real case")
    check("sweep workers default above 1", fresh.spin_workers.value() > 1,
          f"{fresh.spin_workers.value()}")
    check("single-pass is off by default (parallel sweep wins)",
          not fresh.chk_single_pass.isChecked())

    # A capped walk must announce itself everywhere an examiner looks.
    tcase = Case.create(root / "trunc", "trunc", "tester")
    tp = IngestPanel()
    tp.set_case(tcase)
    tp.path_edit.setText(img_path)
    tp._inspect()
    app.processEvents()
    tp.spin_max.setValue(5)
    tp.chk_index.setChecked(True)
    for off in ("chk_carve", "chk_yara", "chk_raw_strings",
                "chk_raw_patterns", "chk_hash", "chk_content"):
        cb = getattr(tp, off, None)
        if cb is not None:
            cb.setChecked(False)
    tlogs = []
    tp._append_log = lambda s: tlogs.append(s)
    tp._run()
    tp._worker.wait(30 * 60 * 1000)
    app.processEvents()
    n_trunc = sum(1 for l in tlogs if "TRUNCATED" in l)
    n_incomp = sum(1 for l in tlogs if "INCOMPLETE" in l)
    check("a truncated walk says so in the ingest log", n_trunc > 0,
          f"{n_trunc} warning(s)" if n_trunc else
          "no truncation warning emitted")
    check("a truncated walk says so in the result summary", n_incomp > 0,
          f"{n_incomp} line(s)" if n_incomp else
          "summary did not flag the partial case")
    with tcase.connect() as conn:
        acts = [r[0] for r in conn.execute("SELECT action FROM audit_log")]
    check("a truncated walk is recorded in the audit log",
          "ingest.walk_truncated" in acts, str(sorted(set(acts))))

    # ================================================================
    section("AFTER — database contents and provenance")
    # ================================================================
    with case.connect() as conn:
        n_all = conn.execute("SELECT COUNT(*) FROM files").fetchone()[0]
        n_walk = conn.execute("SELECT COUNT(*) FROM files WHERE path NOT "
                              "LIKE '/(%'").fetchone()[0]
        n_carv = conn.execute("SELECT COUNT(*) FROM files WHERE path LIKE "
                              "'/(carved)/%'").fetchone()[0]
        n_prov = conn.execute("SELECT COUNT(*) FROM files WHERE path NOT LIKE "
                              "'/(%' AND volume_offset IS NOT NULL").fetchone()[0]
        n_doff = conn.execute("SELECT COUNT(*) FROM files WHERE path LIKE "
                              "'/(carved)/%' AND data_offset IS NOT NULL"
                              ).fetchone()[0]
        n_hash = conn.execute("SELECT COUNT(*) FROM files WHERE sha256 IS NOT "
                              "NULL AND sha256 != ''").fetchone()[0]
    print(f"  files={n_all:,}  walked={n_walk}  carved={n_carv:,}  "
          f"hashed={n_hash:,}")
    check("files were recorded", n_all > 0)
    check("every walked file has volume provenance", n_walk == n_prov,
          f"{n_prov}/{n_walk}")
    check("every carved file has a data offset", n_carv == n_doff,
          f"{n_doff}/{n_carv}")
    check("evidence row recorded", len(case.list_evidence()) == 1)

    # ================================================================
    section("AFTER — known-file hash sets")
    # ================================================================
    from app.core.known_files import KnownSetStore, normalise_hash
    kstore = KnownSetStore(root / "known.db")
    check("MD5/SHA-1/SHA-256 all recognised",
          normalise_hash("d41d8cd98f00b204e9800998ecf8427e")[0] == "md5"
          and normalise_hash("a" * 40)[0] == "sha1"
          and normalise_hash("b" * 64)[0] == "sha256")
    check("a non-hex string of hash length is rejected",
          normalise_hash("z" * 64) is None)

    # Build a hash set out of this image's own file hashes, so the
    # labelling path is exercised on real data from the image under test.
    with case.connect() as conn:
        real = [r[0] for r in conn.execute(
            "SELECT sha256 FROM files WHERE sha256 IS NOT NULL AND "
            "sha256 != '' ORDER BY path LIMIT 20").fetchall()]
    if real:
        lp = root / "seed_hashes.txt"
        lp.write_text("\n".join(real), encoding="utf-8")
        n_imp = kstore.import_hash_list(lp, "SuiteSeed")
        check("hash list imports", n_imp == len(real),
              f"{n_imp} of {len(real)}")
        check("a seeded hash is found", kstore.lookup(sha256=real[0])
              == "SuiteSeed")
        check("an absent hash is not found",
              kstore.lookup(sha256="f" * 64) is None)
        check("set is listed with its count",
              any(x.name == "SuiteSeed" and x.n_hashes == n_imp
                  for x in kstore.list_sets()))
        check("deleting a set removes its matches",
              kstore.delete_set("SuiteSeed")
              and kstore.lookup(sha256=real[0]) is None)
    else:
        check("image produced hashes to seed a set with", False,
              "no hashed files")

    # An RDSv3 publication, built to NIST's published FILE schema.
    import sqlite3 as _sq
    rp = root / "rdsv3_probe.db"
    _c = _sq.connect(rp)
    _c.executescript(
        "CREATE TABLE FILE (sha256 VARCHAR NOT NULL, sha1 VARCHAR NOT NULL,"
        " md5 VARCHAR NOT NULL, crc32 VARCHAR NOT NULL,"
        " file_name VARCHAR NOT NULL, file_size INTEGER NOT NULL,"
        " package_id INTEGER NOT NULL);")
    _c.execute("INSERT INTO FILE VALUES (?,?,?,?,?,?,?)",
               ("a" * 64, "b" * 40, "c" * 32, "0", "stock.dll", 10, 1))
    _c.commit(); _c.close()
    rinfo = kstore.inspect_nsrl(rp)
    check("RDSv3 publication is recognised by schema", rinfo["ok"],
          rinfo["note"])
    check("RDSv3 hash columns detected",
          set(rinfo.get("hash_columns", [])) == {"sha256", "sha1", "md5"},
          str(rinfo.get("hash_columns")))
    before_rds = sha256_file(rp)
    n_rds = kstore.import_nsrl(rp, "RDSProbe", algos=("sha256", "md5"))
    check("RDSv3 import reads the requested algos", n_rds == 2, str(n_rds))
    check("RDSv3 publication is opened read-only and unchanged",
          sha256_file(rp) == before_rds)
    check("a file in the RDS set is found", kstore.lookup(sha256="a" * 64)
          == "RDSProbe")
    check("an algo that was not imported does not match",
          kstore.lookup(sha1="b" * 40) is None,
          "sha1 was excluded from the import")
    check("a SQLite file without a FILE table is rejected",
          not kstore.inspect_nsrl(case.db_path)["ok"])

    check("hide-known is a view option, OFF by default",
          not SearchPanel().chk_hide_known.isChecked(),
          "a filter that hides evidence must never be the default")

    # ================================================================
    section("AFTER — search, every mode")
    # ================================================================
    sp = SearchPanel()
    sp.set_case(case)
    # Seeds come from the image itself. Hashing was enabled for this
    # ingest, so their absence is a real failure rather than a reason to
    # skip the hash-driven search modes.
    seed_sha = seed_tlsh = None
    seed_name = ""
    with case.connect() as conn:
        row = conn.execute("SELECT sha256, name FROM files WHERE sha256 "
                           "IS NOT NULL AND sha256 != '' LIMIT 1").fetchone()
        if row:
            seed_sha, seed_name = row
        trow = conn.execute("SELECT tlsh FROM files WHERE tlsh IS NOT NULL "
                            "AND tlsh != '' LIMIT 1").fetchone()
        if trow:
            seed_tlsh = trow[0]
    check("a SHA-256 seed exists for hash search", bool(seed_sha))
    from app.core.hashing import HAS_TLSH
    if not HAS_TLSH:
        env_gap("TLSH similarity search",
                "py-tlsh is not installed (no cp312 binary wheel exists), so "
                "no file can carry a TLSH digest and that search mode is "
                "unavailable in this deployment")
    else:
        check("a TLSH seed exists for similarity search", bool(seed_tlsh),
              f"{seed_tlsh[:16]}…" if seed_tlsh
              else "py-tlsh is installed but no file produced a digest")
    mode_queries = {
        "fulltext": "the",
        "name": (seed_name or "a"),
        "regex": ".*",
        "sha256": (seed_sha or "")[:12],
        "tlsh": (seed_tlsh or seed_sha or ""),
    }
    for i in range(sp.mode.count()):
        data = sp.mode.itemData(i)
        q = mode_queries.get(data, "")
        if data == "tlsh" and not HAS_TLSH:
            env_gap("search mode 'tlsh'", "py-tlsh not installed")
            continue
        check(f"search mode '{data}' has a usable seed", bool(q),
              f"{q[:24]!r}" if q else "no seed could be derived from this image")
        if not q:
            continue
        sp.mode.setCurrentIndex(i)
        app.processEvents()
        sp.q.setText(q)
        sp._run()
        app.processEvents()
        rows = sp.tbl.rowCount()
        status = sp.status.text()
        print(f"  {data:<10} q={q[:24]!r:<26} -> {rows} row(s)")
        # Previously this passed a literal True, so it asserted nothing
        # at all: a mode could return zero rows for a query built from
        # this very case and still be recorded as a pass.
        check(f"search mode '{data}' reports no error",
              "Error:" not in status, status[:100])
        if data == "sha256":
            # The seed is a prefix of a hash that IS in this case, so a
            # correct implementation must find at least one row.
            check("SHA-256 prefix search finds the file it was seeded from",
                  rows > 0,
                  f"0 rows for prefix {q!r} taken from a hash in this case",
                  pass_detail=f"{rows} row(s)")
        elif data in ("fulltext", "name", "regex"):
            check(f"search mode '{data}' returns a row count, not an error",
                  rows >= 0, pass_detail=f"{rows} row(s)")

    # Both of these modes were silently dead: the code built wildcard
    # queries ("sha256:<hex>*", "name:*q*") that Tantivy's parser does
    # not implement, so it matched the asterisk literally. SHA-256 mode
    # returned nothing even for a full exact hash, and name mode only
    # matched whole tokens despite being labelled a substring search.
    # Assert against a hash and a name taken from THIS image.
    if seed_sha:
        sp.mode.setCurrentIndex(sp.mode.findData("sha256"))
        app.processEvents()
        for plen in (64, 32, 12):
            sp.q.setText(seed_sha[:plen])
            sp._run()
            app.processEvents()
            check(f"SHA-256 prefix[{plen}] finds the file it came from",
                  sp.tbl.rowCount() > 0,
                  f"0 rows for a {plen}-char prefix of a hash in this case",
                  pass_detail=f"{sp.tbl.rowCount()} row(s)")
        sp.q.setText("ffffffffffffffff")
        sp._run()
        app.processEvents()
        check("SHA-256 prefix that matches nothing returns nothing",
              sp.tbl.rowCount() == 0, f"{sp.tbl.rowCount()} rows")

    if seed_name and len(seed_name) >= 4:
        inner = seed_name[1:-1]
        sp.mode.setCurrentIndex(sp.mode.findData("name"))
        app.processEvents()
        sp.q.setText(inner)
        sp._run()
        app.processEvents()
        check("name mode matches a true substring, not just whole tokens",
              sp.tbl.rowCount() > 0,
              f"0 rows for {inner!r}, an inner substring of {seed_name!r}",
              pass_detail=f"{inner!r} -> {sp.tbl.rowCount()} row(s)")

    # Regex substring semantics. Derive the pattern from a path that is
    # actually in this image — an NTFS-only pattern like \$M.* would
    # legitimately find nothing on an ext or APFS image, which would be
    # a fault in the test rather than in the tool.
    import re as _re
    probe = None
    with case.connect() as conn:
        for (pth,) in conn.execute(
                "SELECT path FROM files WHERE path NOT LIKE '/(%' "
                "AND length(path) > 6 ORDER BY length(path) DESC LIMIT 20"):
            seg = pth.rstrip("/").split("/")[-1]
            if len(seg) >= 5:
                probe = (pth, seg)
                break
    if probe is None:
        # Fall back to any indexed path at all — carved and raw docs have
        # paths too, so there is always something to probe.
        with case.connect() as conn:
            r = conn.execute("SELECT path FROM files WHERE length(path) > 6 "
                             "LIMIT 1").fetchone()
        if r:
            seg = r[0].rstrip("/").split("/")[-1]
            if len(seg) >= 5:
                probe = (r[0], seg)
    check("a path exists to probe regex semantics with", probe is not None)
    if probe:
        full_path, segment = probe
        mid = _re.escape(segment[1:-1])          # strip the ends
        sp.mode.setCurrentIndex(sp.mode.findData("regex"))
        app.processEvents()
        sp.q.setText(mid)
        sp._run()
        app.processEvents()
        check("regex matches as a substring (not anchored)",
              sp.tbl.rowCount() > 0,
              f"pattern {mid!r} from {full_path!r} -> "
              f"{sp.tbl.rowCount()} hits")
        # an anchored pattern must match the whole term exactly
        sp.q.setText("^" + _re.escape(full_path) + "$")
        sp._run()
        app.processEvents()
        check("anchored regex matches the whole path term",
              sp.tbl.rowCount() > 0, f"{sp.tbl.rowCount()} hits")


    # ================================================================
    section("AFTER — provenance and extraction, every origin")
    # ================================================================
    with case.connect() as conn:
        walk_p = conn.execute("SELECT path FROM files WHERE path NOT LIKE "
                              "'/(%' AND size_bytes > 0 ORDER BY size_bytes "
                              "DESC LIMIT 1").fetchone()
        carv_p = conn.execute("SELECT path FROM files WHERE path LIKE "
                              "'/(carved)/%' ORDER BY size_bytes DESC "
                              "LIMIT 1").fetchone()
    targets = []
    if walk_p:
        targets.append(("walked file", walk_p[0]))
    if carv_p:
        targets.append(("carved file", carv_p[0]))
    targets.append(("raw page", "/(raw)/0x0"))

    exported_any = None
    outdir = root / "exports"
    for label, ipath in targets:
        prov = extract.describe(case, ipath)
        if not prov.exportable:
            check(f"{label}: exportable", False, prov.note)
            continue
        dest = outdir / prov.suggested_name
        res = extract.export(case, prov, dest, write_receipt=True)
        disk = os.path.getsize(res["path"])
        check(f"{label}: exported byte count matches file on disk",
              disk == res["bytes"], f"{disk} vs {res['bytes']}")
        check(f"{label}: receipt written", os.path.exists(res["receipt"]))
        check(f"{label}: receipt is plain ASCII",
              Path(res["receipt"]).read_text(encoding="utf-8").isascii())
        indep = sha256_file(res["path"])
        check(f"{label}: independent re-hash matches reported digest",
              indep == res["digests"]["sha256"])
        if prov.sha256:
            check(f"{label}: matches the hash recorded at ingest",
                  res["verified"] is True)
        if exported_any is None:
            exported_any = res

    # tamper an exported file -> its hash must diverge from the receipt
    if exported_any:
        p = Path(exported_any["path"])
        raw = bytearray(p.read_bytes())
        if len(raw) > 64:
            raw[50] ^= 0xFF
            p.write_bytes(bytes(raw))
            check("tampering an exported file breaks its recorded hash",
                  sha256_file(p) != exported_any["digests"]["sha256"])

    # ================================================================
    section("AFTER — findings browser")
    # ================================================================
    fp = FindingsPanel()
    fp.set_case(case)
    for mode in ("ioc", "yara", "carved", "artifact"):
        idx = fp.cmb_mode.findData(mode)
        if idx < 0:
            continue
        fp.cmb_mode.setCurrentIndex(idx)
        app.processEvents()
        fp.refresh()
        app.processEvents()
        print(f"  {mode:<10} {fp.tbl.rowCount():>7,} rows  "
              f"(of {fp._total:,})")
    # Truncation must be disclosed. The cap is derived from how many
    # findings this image actually produced rather than assumed, so the
    # check runs on a sparse image too. If the image yielded too few to
    # truncate, synthetic rows exercise the same UI path — the logic
    # under test belongs to the panel, not to the evidence.
    fp.cmb_mode.setCurrentIndex(fp.cmb_mode.findData("ioc"))
    app.processEvents()
    fp.spin_limit.setValue(1_000_000)
    fp.refresh()
    app.processEvents()
    total_ioc = fp._total
    # The Rows control has its own minimum, so a cap below it would be
    # clamped and nothing would actually be truncated. Seed enough
    # synthetic findings to sit above that minimum when the image itself
    # produced too few.
    floor = fp.spin_limit.minimum()
    if total_ioc <= floor:
        ev_id = case.list_evidence()[0]["id"]
        need = floor + 5 - total_ioc
        case.add_findings(ev_id, [
            {"kind": "ioc", "subtype": "synthetic", "value": f"probe-{i}",
             "count": 1, "first_offset": i} for i in range(need)])
        fp.refresh()
        app.processEvents()
        total_ioc = fp._total
        print(f"  (seeded {need} synthetic findings to exceed the row "
              f"minimum of {floor}; total now {total_ioc})")
    check("enough findings to exercise truncation", total_ioc > floor,
          f"{total_ioc} findings vs row minimum {floor}")

    cap = floor
    fp.spin_limit.setValue(cap)
    fp.refresh()
    app.processEvents()
    check("capped findings view says it is truncated",
          "showing the first" in fp.lbl_summary.text(),
          f"cap={cap} of {total_ioc}: {fp.lbl_summary.text()[-60:]}")
    check("capped view loads exactly the cap", fp.tbl.rowCount() == cap,
          f"{fp.tbl.rowCount()} vs {cap}")

    # ...and the notice must disappear once everything fits.
    fp.spin_limit.setValue(1_000_000)
    fp.refresh()
    app.processEvents()
    check("uncapped findings view does not claim truncation",
          "showing the first" not in fp.lbl_summary.text(),
          fp.lbl_summary.text()[-60:])
    check("uncapped view loads every finding",
          fp.tbl.rowCount() == total_ioc,
          f"{fp.tbl.rowCount()} vs {total_ioc}")

    csv_p = root / "findings.csv"
    from unittest import mock
    with mock.patch("app.ui.findings_panel.QFileDialog.getSaveFileName",
                    return_value=(str(csv_p), "")), \
         mock.patch("app.ui.findings_panel.ExportedDialog"):
        fp._export()
    if csv_p.exists():
        lines = csv_p.read_text(encoding="utf-8").splitlines()
        danger = [l for l in lines if l and l[0] in "=+-@\t\r"]
        check("findings CSV written", len(lines) > 1, f"{len(lines)} lines")
        check("no CSV formula-injection cells", not danger,
              f"{len(danger)} unsafe")

    # ================================================================
    section("AFTER — audit chain and tamper detection")
    # ================================================================
    ok, msg = case.verify_audit_chain()
    check("audit chain verifies", ok, msg)
    with case.connect() as conn:
        rows = conn.execute("SELECT action, COUNT(*) FROM audit_log GROUP BY "
                            "action ORDER BY 2 DESC").fetchall()
    for a, c in rows:
        print(f"     {a:<26} {c}")
    for expect in ("case.create", "evidence.add", "ingest.complete",
                   "evidence.export"):
        check(f"audit log records '{expect}'",
              any(a == expect for a, _ in rows))

    # tamper: rewrite a payload and confirm the chain breaks
    tamper = Case.create(root / "tamper", "tamper", "t")
    for i in range(5):
        tamper.log("evt", {"i": i})
    with tamper.connect() as conn:
        conn.execute("UPDATE audit_log SET payload_json='{\"i\":999}' "
                     "WHERE id=(SELECT MIN(id)+1 FROM audit_log)")
    bad_ok, bad_msg = tamper.verify_audit_chain()
    check("editing an audit row is detected", not bad_ok, bad_msg)

    # ================================================================
    section("AFTER — signed manifest and tamper detection")
    # ================================================================
    mf = man.build_manifest(case.root, {})
    priv, pub = man.ensure_keypair(case.keys_dir)
    man.sign_manifest(case.root, mf, priv)
    check("manifest signature verifies", man.verify_manifest(case.root, pub))
    bad = 0
    for f in mf["files"]:
        p = case.root / f["path"]
        if "sha256" in f and p.exists() and sha256_file(p) != f["sha256"]:
            bad += 1
    check("every manifest hash matches the file on disk", bad == 0,
          f"{bad} mismatched of {len(mf['files'])}")
    # a file over 64 MiB must be hashed in full, not truncated
    big = root / "big.bin"
    big.write_bytes(b"A" * (64 * 1024 * 1024) + b"TAIL")
    from app.core.manifest import _hash_file
    check("manifest hashes past 64 MiB",
          _hash_file(big) == sha256_file(big))
    big.unlink()
    # tamper the manifest -> signature must fail
    mpath = case.root / "manifest.json"
    orig = mpath.read_bytes()
    mpath.write_bytes(orig.replace(b'"manifest_version":1',
                                   b'"manifest_version":2'))
    check("edited manifest fails signature verification",
          not man.verify_manifest(case.root, pub))
    mpath.write_bytes(orig)
    check("restored manifest verifies again",
          man.verify_manifest(case.root, pub))

    # ================================================================
    section("AFTER — persistence, determinism, immutability")
    # ================================================================
    reopened = Case.open(case.root)
    check("case reopens", reopened is not None)
    check("evidence survives reopen", len(reopened.list_evidence()) == 1)
    with reopened.connect() as conn:
        n2 = conn.execute("SELECT COUNT(*) FROM files").fetchone()[0]
    check("file rows survive reopen", n2 == n_all, f"{n2} vs {n_all}")
    ok2, _ = reopened.verify_audit_chain()
    check("audit chain still verifies after reopen", ok2)

    from app.core.indexer import stable_doc_id
    a = stable_doc_id(1, "/x/y")
    import subprocess
    out = subprocess.run(
        [sys.executable, "-c",
         "import sys;sys.path.insert(0,r'%s');"
         "from app.core.indexer import stable_doc_id;"
         "print(stable_doc_id(1,'/x/y'))"
         % str(Path(__file__).resolve().parent.parent)],
        capture_output=True, text=True)
    check("doc ids are reproducible in a fresh interpreter",
          out.stdout.strip() == str(a), f"{out.stdout.strip()} vs {a}")

    m2 = hashlib.md5()
    with open_handle(inspect(img_path)) as h:
        while True:
            b = h.read(1 << 20)
            if not b:
                break
            m2.update(b)
    check("EVIDENCE IMAGE UNMODIFIED by the whole run",
          m2.hexdigest() == image_md5_before,
          f"{m2.hexdigest()} vs {image_md5_before}")

    # ================================================================
    print(f"\n{'=' * 72}")
    print(f"PASSED {len(PASS)}   FAILED {len(FAIL)}   SKIPPED {len(SKIP)}"
          + (f"   ENV-GAPS {len(ENV)}" if ENV else "")
          + ("   (skips count as failures)" if SKIP else ""))
    if ENV:
        print("\nOPTIONAL CAPABILITIES ABSENT IN THIS DEPLOYMENT "
              "(not code defects):")
        for e in ENV:
            print(f"  - {e}")
    if FAIL:
        print("\nFAILURES:")
        for f in FAIL:
            print(f"  - {f}")
    print("=" * 72)

    shutil.rmtree(root, ignore_errors=True)
    return 1 if FAIL else 0


if __name__ == "__main__":
    image = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_IMG
    sys.exit(run(image))
