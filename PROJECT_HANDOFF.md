# PROJECT HANDOFF — E01 Index & Search

> Read this file first to resume the project cold in a new chat.
> Last updated: after Phase 4 completion (commit `2337aec`).

---

## 1. What this project is

**E01 Index & Search** — a self-contained **desktop forensic tool** (PySide6
GUI) that indexes and searches **EWF / EnCase `.E01` disk images**. It walks
filesystems inside an image, hashes files, extracts and indexes text,
carves deleted files, scans for IoCs, parses specialized artefacts
(Outlook PST, registry, ESE, SQLite), verifies image integrity, and keeps
a court-defensible audit trail.

Built from a planning/review document: **`F:\e01 indexing\e01 md file.md`**
(a "Critical Review of the E01 Indexed-Search Tool Implementation Plan,
May 2026"). That file defines the 7-phase plan this project follows.

### Key facts

| | |
|---|---|
| **Project folder** | `F:\e01 indexing\try1\` (everything lives here) |
| **GitHub repo** | https://github.com/whitedevil1026/E01-index-search (branch `main`) |
| **Git identity** | `whitedevil1026` (already configured — do not change git config) |
| **License** | Apache 2.0 (`LICENSE` + `NOTICE`) |
| **Python** | 3.10 (all bundled wheels are cp310) |
| **Run** | `cd "F:\e01 indexing\try1" && python main.py` |
| **Test image** | `F:\e01 indexing\2011-10-19-Image\2011-10-19-Sample.E01` |

### Test-image caveat

The SANS `2011-10-19-Sample.E01` is a **minimal 150 MB NTFS image** — its
live filesystem has only **23 files** (all `$`-prefixed NTFS metadata).
Real documents/registry/PST appear only in **carved unallocated space**.
So registry/PST parsing **cannot be fully tested on this image** — the
user will validate Phase 4 on a real **100 GB image** they have.

---

## 2. Current status — 6 of 7 phases done

```
Phase 0 — Foundation .............. DONE      100%
Phase 1 — Image access ............ DONE      ~95%
Phase 2 — Indexing core ........... DONE      100%
Phase 3 — Raw scan / carving ...... DONE      100%
Phase 4 — Specialized artifacts ... DONE      ~95%
Phase 5 — Search / UI / export .... DONE      ~95%
Phase 6 — Multi-case / scale-out .. NOT STARTED 0%  (optional)
```

The tool is **functionally complete** for single-examiner, per-case E01
forensics. Phase 6 was flagged "only if needed" by the plan itself.

---

## 3. What each phase delivered

### Phase 0 — Foundation
- PySide6 desktop GUI shell, SQLite per-case database
- **Hash-chained audit log** — each row stores SHA-256 of
  `(ts|actor|action|payload|prev_hash)`; tampering breaks the chain
- **Ed25519-signed manifest** of the case folder (reproducibility contract)
- Per-case **hash policy** (MD5/SHA-1/SHA-256/SHA-512/BLAKE2b)

### Phase 1 — Image access
- `libewf-python` E01 reader; `EwfHandle` file-like wrapper
- Partition enumeration; **encryption** (BitLocker/FileVault/LUKS via
  pybde/pyfvde/pyluksde) with a key-escrow dialog
- **VSS** (Volume Shadow Copies) via pyvshadow + cross-snapshot dedup
- Filesystem walk: pytsk3 primary, **direct libfsntfs/libfsapfs fallback**
- **Multi-handle parallel hashing** (`parallel_hash`) — bit-identical to
  sequential, verified
- EWF integrity checker + FTK-style report (originally a user PowerShell
  script, ported to Python)

### Phase 2 — Indexing core
- `tantivy-py` index, one per evidence item; `default` analyzer + app-level
  NFC normalisation
- **File-content extraction** (pure-Python, NO Apache Tika/JVM):
  PDF (PyMuPDF), DOCX/XLSX/PPTX (stdlib zip+XML), MSG (extract-msg),
  EML (stdlib), HTML, RTF, plain text
- **Paged multi-encoding raw string sweep** (ASCII/UTF-8/UTF-16/CJK),
  regex-based (18× faster than the char-loop first attempt)
- Incremental Tantivy commits (every 2000–5000 docs)

### Phase 3 — Raw scan / carving
- **IoC pattern extraction** (`patterns.py`): email, URL, IPv4/6, domain,
  credit-card (Luhn-validated), Bitcoin, phone, MAC, .onion
- **File-signature carving** (`carver.py`): JPEG/PNG/GIF/PDF/BMP,
  footer- or length-delimited (pure Python, replaces PhotoRec)
- **YARA-X scanning** (`yara_scan.py`) with a built-in rule pack +
  custom `.yar` loading
- **Findings table + Findings tab** — browse IoC indicators, YARA
  matches, carved files; CSV export

### Phase 4 — Specialized artifacts
- `artifacts.py` — looks INSIDE container files:
  - PST/OST → libpff (every message)
  - Registry hives → libregf (every key/value)
  - ESE databases → libesedb (every table row)
  - SQLite DBs → stdlib (every table row, read-only/immutable)
  - Defender quarantine → RC4 decode (static key)
  - Encrypted chat DBs / memory / pcap → detect & flag
- Each container yields per-item Tantivy docs (`mailbox.pst#Inbox/msg_42`)
- "Flagged artifacts" view in the Findings tab

### Phase 5 — Search / UI / export
- Search modes: keyword full-text, exact-name substring, **regex (RE2)**,
  SHA-256 prefix, **TLSH distance similarity**
- Smart fallback (`system 32` → `system32`); live status feedback
- **Per-file hashing** during ingest (the "Hash file contents" checkbox
  now actually works — MD5+SHA-256+TLSH)
- **Search results export** to CSV

---

## 4. Source layout

```
try1/
  main.py                    entry point
  requirements.txt           (user-maintained — yara-x/libpff commented under Optional)
  LICENSE  NOTICE  README.md
  PROJECT_HANDOFF.md         <- this file
  wheels/                    11 pre-built cp310 wheels (offline install)
  tools/build_wheels.py      rebuild wheels for other Python versions
  app/
    core/
      case.py            SQLite case DB, audit log, findings, hash policy, tlsh_similar
      deps.py            probes 19 dependencies
      manifest.py        Ed25519 signed manifest
      worker.py          QThread base — signal is 'done' (NEVER name it 'finished')
      hashing.py         md5/sha256/tlsh helpers
      hash_policy.py     HashPolicy + single-pass multi-hash engine
      streams.py         OffsetStream (partition slice) + pytsk_img_from_stream
      ewf_reader.py      libewf wrapper, EwfHandle, parallel_hash
      ewf_integrity.py   EWF segment integrity + metadata + FTK-style txt report
      encryption.py      BitLocker/FileVault/LUKS unlock (pybde/pyfvde/pyluksde)
      vss.py             Volume Shadow Copy (pyvshadow) + SnapshotDedup
      filesystem.py      walk_image: pytsk3 + direct libfsntfs/libfsapfs,
                         encryption + VSS integration, scan_volumes()
      indexer.py         tantivy wrapper: search() + regex_search()
      encodings.py       regex-based multi-encoding string extraction
      text_extract.py    PDF/Office/email/html/rtf/text extraction
      raw_scan.py        paged 16 MiB sbuf string sweep
      patterns.py        IoC regex extraction
      carver.py          file-signature carving
      yara_scan.py       YARA-X wrapper + BUILTIN_RULES
      artifacts.py       PST/registry/ESE/SQLite/quarantine parsing
    ui/
      main_window.py     7 tabs, toolbar, drag-and-drop E01
      case_panel.py      case metadata + hash-policy editor
      integrity_panel.py EWF integrity checker UI
      ingest_panel.py    THE BIG ONE — inspect/scan/compute/ingest + raw scan
      search_panel.py    multi-mode search + export
      findings_panel.py  browse IoC / YARA / carved / flagged artifacts
      audit_panel.py     hash-chained audit log viewer
      deps_panel.py      dependency status + in-app installer
      new_case_dialog.py case-creation wizard (name/examiner/hash policy)
      encryption_dialog.py  key-escrow dialog for encrypted volumes
      install_dialog.py  in-app pip installer (uses ./wheels)
      exported_dialog.py copyable-path "files exported" dialog
      help_dialog.py     Audit/Manifest/TLSH/Hash-Policy/About help
      centered_msg.py    popup helpers (center on parent screen)
```

The app has **7 tabs**: Case · Integrity Check · Ingest · Search ·
Findings · Audit Log · Deps Status.

---

## 5. Dependencies (19, all install — cp310)

PySide6, cryptography, tantivy, charset-normalizer, tlsh, libewf-python,
pytsk3, libvshadow-python, libbde-python, libfvde-python, libluksde-python,
libfsntfs-python, libfsapfs-python, PyMuPDF, extract-msg, yara-x,
libpff-python, libregf-python, libesedb-python.

`wheels/` bundles the 11 C-extension wheels that lack reliable PyPI
Windows wheels OR are needed for offline install. **The whole point: a
fresh Windows + Python 3.10 machine installs with NO Microsoft C++ Build
Tools** — `pip install -r requirements.txt` then in-app "Install
Missing" (Deps Status tab) uses `--find-links ./wheels`.

`tools/build_wheels.py` rebuilds wheels for Python 3.11/3.12/3.13.

---

## 6. Critical gotchas / decisions (DON'T re-break these)

1. **QThread signals**: never name a custom signal `finished` — it shadows
   `QThread.finished` and crashes on emit. We use `done`. (worker.py)
2. **pyewf.handle.seek() returns None**, not the new offset. `EwfHandle`
   tracks position itself — see the big comment in `ewf_reader.py`.
3. **PySide6 6.x enums**: `QDialog.Accepted` works as a *class* attribute,
   NOT as `dlg.Accepted` (instance) — that raises AttributeError.
4. **String extraction is regex-based**, not a Python char loop (was 2 MB/s,
   now 36 MB/s). `encodings.py`.
5. **Carver `_carve_one` never slices `max_size` eagerly** — a 2-byte BMP
   signature once triggered ~78 GB of buffer copies. BMP is validated via
   its 18-byte header (reserved==0, DIB size known value).
6. **Patterns scan extracted text, not raw bytes** — 10× less data, no
   regex backtracking on binary noise. cc/phone regexes are linear.
7. **libyal file-like objects need `get_size()`** — see `_MemFile` in
   artifacts.py and `OffsetStream` in streams.py.
8. **Tantivy uses the built-in `default` analyzer** — a custom
   `TextAnalyzerBuilder` analyzer was tried and is fragile across
   tantivy-py builds (caused "Error getting tokenizer" at commit).
9. **Incremental Tantivy commits** every N docs — a multi-hour ingest
   crash then loses only the last batch, not the whole index.
10. **End every chat response with a ✅** (user preference).

---

## 7. How to run / test

```
cd "F:\e01 indexing\try1"
python main.py
```

Offscreen smoke test pattern used throughout:
```
QT_QPA_PLATFORM=offscreen python -c "...build MainWindow, processEvents..."
```

Full-pipeline test against the SANS image: create a case, point Ingest at
`F:\e01 indexing\2011-10-19-Image\2011-10-19-Sample.E01`, tick every
checkbox. Expect ~23 walked files + ~3,300 carved + ~11k IoC indicators.

---

## 8. What's still TODO

### Phase 6 — Multi-case / scale-out (optional, not started)
- Multi-image case stitching (one case spanning many evidence sets)
- Quickwit-backed mode for >5 TB corpora / multi-examiner
- Cross-case hash deduplication

### Smaller leftover items (low priority, plan-deferred)
- **AFF4** image format support (`pyaff4` is on PyPI, 0.34)
- **NSRL RDS** known-file hash filter (was a Phase 0 wish, never built)
- VSS dedup currently keys on `path|size|mtime`, not SHA-256 (pragmatic)
- Tantivy `en_stem` field variant for stemmed search
- BGE-M3 embeddings / vector search (plan said off-by-default)
- Custom YARA rules: loadable, but no persistent per-case rule store
- PST/registry/ESE parsing tested only on synthetic data + graceful-
  failure — needs validation on the user's real 100 GB image

---

## 9. Commit history (recent first)

```
2337aec  Phase 4 — specialized artifact parsing (PST/registry/ESE/SQLite)
f08af84  Phase 5 — per-file hashing, regex & TLSH search, results export
7bc9397  Phase 3 complete — findings persistence + Findings browser
a7b088e  Phase 2 complete + Phase 3 raw scan / carving / IoC / YARA
2bf6639  Phase 2 — file-content indexing (search inside documents)
e49227c  incremental commits + drag-drop + About dialog
4d77e4b  polish: centered popups + tooltips + Ctrl+F + empty states
378e67d  polish: rewrite README + remove "try1" from user-facing text
5d5697a  chore: switch license MIT -> Apache 2.0 + add NOTICE
628e272  Initial commit
```

---

## 10. How to continue in a new chat

1. Read this file and `F:\e01 indexing\e01 md file.md` (the plan).
2. The working folder is `F:\e01 indexing\try1\` — everything is there.
3. `git log --oneline` to see state; `git status` should be clean.
4. Pick up from §8 (Phase 6 or the leftover items), OR address whatever
   the user reports after testing on their 100 GB image.
5. Workflow used in this project: make focused edits, smoke-test with an
   offscreen Qt run against the SANS image, then `git commit` + `git push`
   to the repo above. Commit messages are detailed and end with the
   `Co-Authored-By: Claude` trailer.
6. Respect the gotchas in §6 and end responses with ✅.
