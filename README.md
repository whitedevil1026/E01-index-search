# E01 Index & Search

**A self-contained desktop forensic indexer for EWF / EnCase `.E01`
disk images.**

E01 Index & Search opens a forensic disk image, verifies its
integrity, walks every filesystem inside it, recovers deleted and
hidden data, extracts and indexes searchable text from files and
unallocated space, parses specialized artefacts (mailboxes, registry,
databases), and presents everything through a single offline desktop
application — while keeping a tamper-evident, court-defensible record
of every action the examiner takes.

Licensed under the **[Apache License 2.0](LICENSE)** — the license used
across the forensic open-source ecosystem (Autopsy, Plaso, Volatility,
The Sleuth Kit bindings, TLSH, Apache Lucene). Third-party attribution
is in [`NOTICE`](NOTICE).

---

## Purpose

Digital forensic examiners routinely receive a single artefact — an
`.E01` evidence image — that may contain hundreds of gigabytes across
millions of files, deleted data, shadow copies, encrypted volumes and
opaque container formats. Commercial suites that make this tractable
(EnCase, FTK, AXIOM) are expensive, heavyweight and closed.

This project's intent is a **focused, free, fully-offline,
court-defensible tool** that does one job well: **turn an E01 image
into something an examiner can search and reason about** — and do so
without trusting a network, without a multi-gigabyte runtime, and
without ever modifying the evidence.

It is built directly from a documented implementation review (see
`e01 md file.md`) that critically assessed the 2026 forensic-tooling
landscape and specified a seven-phase plan; this codebase implements
that plan.

## Design principles

1. **Evidence is read-only, always.** E01 images are opened through
   `libewf` read paths only; SQLite databases are opened
   `immutable=1&mode=ro`; no code path writes back to source evidence.
2. **Court-defensibility is built in, not bolted on.** Every examiner
   action is recorded in a SHA-256 hash-chained audit log; the case
   state can be sealed with an Ed25519-signed manifest.
3. **Offline and self-contained.** No cloud, no telephone-home, no JVM,
   no Apache Tika. Pure-Python extraction wherever feasible; the few
   C-extension dependencies ship as pre-built wheels so a clean
   Windows + Python 3.10 machine installs in under two minutes with no
   compiler.
4. **Honest about uncertainty.** Where a result is approximate
   (manifest-level rather than bit-identical reproducibility; noisy IoC
   matches; partial filesystem support) the tool says so rather than
   overpromising.
5. **Examiner-first UX.** Every long operation is cancellable and
   reports live progress; every panel explains itself; every defect
   surfaces as a clear message, never a silent failure.

---

## Capabilities

**Image access**
- Read EWF / EnCase `.E01` images (and `.Ex01 / .L01` variants)
- Partition enumeration; whole-disk and single-volume images
- Multi-handle **parallel media hashing** — bit-identical to a
  single-threaded read, verified
- **EWF integrity verification** — missing segments, bad signatures,
  segment-number mismatches, broken Adler-32 trailers, `next`/`done`
  markers; full acquisition-metadata extraction; FTK-style reports

**Encrypted and shadowed volumes**
- **BitLocker, FileVault 2, LUKS** detection and key-escrow unlock
  (recovery key / password / startup key / raw FVEK)
- **Volume Shadow Copies (VSS)** — enumerate and walk every snapshot,
  with cross-snapshot file deduplication

**Filesystem walk**
- The Sleuth Kit (`pytsk3`) as the primary walker
- Direct **libfsntfs / libfsapfs** fallback when TSK degrades on a
  volume
- Per-file MD5 + SHA-256 + TLSH hashing

**Content & raw indexing**
- Full-text extraction from **PDF, DOCX/XLSX/PPTX, MSG, EML, HTML,
  RTF** and plain-text/source files — pure-Python, no Apache Tika
- **Raw-stream string sweep** of unallocated space and slack in
  parallel encodings (ASCII / UTF-8 / UTF-16 / CJK code pages)
- **IoC pattern extraction** — emails, URLs, IPv4/6, domains,
  credit-card numbers (Luhn-validated), Bitcoin addresses, phone
  numbers, MAC addresses, `.onion` addresses

**Carving & malware triage**
- **File-signature carving** of deleted/embedded files (JPEG, PNG,
  GIF, PDF, BMP) — a pure-Python PhotoRec subset
- **YARA-X scanning** with a built-in IoC rule pack and support for
  loading the examiner's own `.yar` rules

**Specialized artefacts**
- **Outlook PST / OST** mail stores — every message indexed
- **Windows Registry hives** — every key/value indexed
- **ESE databases** (Edge/IE history, Windows Search, SRUM, Defender)
- **SQLite databases** (browser, application and chat-app data)
- **Microsoft Defender quarantine** — RC4-decoded and recovered
- Encrypted chat databases (WhatsApp `crypt14/15`, Signal SQLCipher),
  memory images and packet captures are **detected and flagged** for
  routing to dedicated tooling

**Search**
- Keyword full-text, exact-name substring, **RE2 regex**, SHA-256
  prefix, and **TLSH fuzzy-similarity** search
- Live status feedback; smart query fallback; CSV export of results

**Findings & reporting**
- A **Findings** browser for IoC indicators, YARA matches, carved
  files and flagged artefacts, with CSV export
- FTK-Imager-style integrity / case reports

## The application

Seven tabs:

| Tab | Purpose |
|---|---|
| **Case** | Create / open a case; set the per-case hash policy. |
| **Integrity Check** | Verify EWF segment sets; extract acquisition metadata; export reports. |
| **Ingest** | Inspect an image, scan volumes for encryption/VSS, compute hashes, walk filesystems, extract content, run the raw scan / carving / YARA pass. |
| **Search** | Multi-mode search across every evidence index in the case; export results. |
| **Findings** | Browse IoC indicators, YARA matches, carved files and flagged artefacts. |
| **Audit Log** | The append-only, SHA-256 hash-chained record of every action; one-click chain verification. |
| **Deps Status** | Dependency inventory with an in-app offline installer. |

---

## Quick start (Windows · Python 3.10)

```
git clone https://github.com/whitedevil1026/E01-index-search.git
cd E01-index-search
pip install -r requirements.txt
python main.py
```

In the app, open the **Deps Status** tab and click **Install Missing…**.
The 11 C-extension dependencies ship as pre-built `cp310` wheels in
[`wheels/`](wheels/); the installer passes `--find-links=./wheels` to
pip, so they install **offline, in seconds, with no Microsoft C++
Build Tools**.

For Python 3.11 / 3.12 / 3.13, rebuild the wheels once on a machine
with the MSVC toolchain:

```
py -3.12 tools/build_wheels.py
```

---

## Forensic methodology

**Hash policy.** On case creation the examiner selects a Primary
algorithm (MD5 / SHA-1 / SHA-256 / SHA-512 / BLAKE2b) and any Extras.
The policy is stored in the case database and applied consistently to
every file and image hashed for the lifetime of the case. TLSH is
computed alongside as a *fuzzy* similarity hash (for "find similar"
workflows) and is tracked separately.

**Acquisition hashes vs. computed hashes.** The Ingest tab clearly
separates the hashes the *original acquisition tool* wrote into the
E01 header (always MD5/SHA-1, recorded at imaging time) from the
hashes *this tool* computes per the case policy — so the examiner can
independently verify the image content against the acquisition record.

**Hash-chained audit log.** Every action writes a row storing
`SHA-256(timestamp | actor | action | payload | previous_row_hash)`.
Editing, deleting or inserting any historical row breaks the chain;
**Verify Audit Chain** re-derives every hash and reports the first
mismatch.

**Ed25519-signed manifest.** Sealing a case writes a JSON manifest of
every file in the case folder with its SHA-256, the tool's dependency
versions and the host environment, then signs it with a per-case
Ed25519 key. The tool promises **manifest-level reproducibility** —
given the named inputs and tool versions, all output hashes can be
re-verified — and is explicit that bit-identical index output is not
guaranteed (Tantivy segment IDs are non-deterministic).

---

## Architecture & technology

| Layer | Technology |
|---|---|
| Language / runtime | Python 3.10 |
| GUI | PySide6 (Qt 6) |
| Search index | tantivy-py (Rust, Lucene-class) |
| E01 reader | libewf (`libewf-python`) |
| Filesystem | The Sleuth Kit (`pytsk3`) + libfsntfs / libfsapfs |
| Encryption | libbde · libfvde · libluksde |
| Shadow copies | libvshadow |
| Artefact parsers | libpff · libregf · libesedb + stdlib `sqlite3` |
| Content extraction | PyMuPDF · extract-msg · Python stdlib |
| Hashing | hashlib (MD5/SHA family/BLAKE2b) · TLSH |
| Pattern / malware scan | pure-Python regex IoC engine · YARA-X |
| Crypto / signing | `cryptography` (Ed25519) |
| Case state | SQLite (WAL) |

The forensic engine (`app/core/`) is fully decoupled from the GUI
(`app/ui/`) — every core module is independently testable and the
heavy work runs on cancellable `QThread` workers so the UI never
freezes.

### Project layout

```
main.py                  application entry point
requirements.txt
LICENSE  NOTICE  README.md  PROJECT_HANDOFF.md
wheels/                  11 pre-built cp310 wheels (offline install)
tools/build_wheels.py    rebuild wheels for other Python versions
app/core/
  case.py                SQLite case DB, hash-chained audit log, findings
  deps.py                dependency probing
  manifest.py            Ed25519 signed manifest
  worker.py              cancellable QThread base
  hashing.py  hash_policy.py     hashing engines
  streams.py             stream adapters (partition slicing, pytsk bridge)
  ewf_reader.py          libewf wrapper, parallel hashing
  ewf_integrity.py       EWF segment integrity + FTK-style reports
  encryption.py          BitLocker / FileVault / LUKS unlock
  vss.py                 Volume Shadow Copy enumeration + dedup
  filesystem.py          filesystem walk (TSK + direct fallbacks)
  encodings.py           multi-encoding string extraction
  text_extract.py        PDF / Office / email / HTML / RTF extraction
  raw_scan.py            paged raw-stream string sweep
  patterns.py            IoC regex extraction
  carver.py              file-signature carving
  yara_scan.py           YARA-X wrapper + built-in rules
  artifacts.py           PST / registry / ESE / SQLite / quarantine
  indexer.py             tantivy-py search index
app/ui/
  main_window.py         7-tab main window
  case_panel.py  integrity_panel.py  ingest_panel.py
  search_panel.py  findings_panel.py  audit_panel.py  deps_panel.py
  new_case_dialog.py  encryption_dialog.py  install_dialog.py
  exported_dialog.py  help_dialog.py  centered_msg.py
```

---

## Status

Six of the seven planned phases are complete: Foundation, Image
Access, Indexing Core, Raw Scan / Carving, Specialized Artefacts, and
Search / UI / Export. The tool is functionally complete for
single-examiner, per-case E01 forensics.

**Not yet implemented** (deliberately deferred, low priority): AFF4
image format support, NSRL RDS known-file filtering, multi-image case
stitching and distributed (Quickwit) scale-out for multi-terabyte
corpora, and optional embedding/vector search.

`PROJECT_HANDOFF.md` documents the full status, architecture and
remaining work in detail.

---

## Development notes

- Custom `QThread` signals are named `done`, never `finished`
  (`finished` shadows the Qt built-in and crashes on emit).
- The audit-log row hash uses `|` as a literal field separator and is
  verified forward from a genesis `prev_hash` of 64 zeros.
- Bundled wheels are committed to the repository so the install path
  is deterministic and offline.
- All UI panels are wrapped in scroll areas with capped minimum sizes
  so the window fits a 1366 × 768 laptop screen.

## Disclaimer

This software is provided under the Apache 2.0 license "as is", without
warranty. It is an independent open-source project and is not
affiliated with or endorsed by any commercial forensic vendor.
Examiners remain responsible for validating tool output against their
own accreditation and evidence-handling requirements.
