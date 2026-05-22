# E01 Index & Search

A self-contained desktop forensic indexer for **EWF / EnCase E01** images.
Verify integrity, walk filesystems, hash with a court-defensible policy,
and search by file name across cases — all through a single PySide6
desktop app with a hash-chained audit log and Ed25519-signed manifest.

Licensed under the **[Apache License 2.0](LICENSE)** — the same license
used by Autopsy, Plaso, Volatility, pytsk3, TLSH, Apache Tika and
Lucene. See [`NOTICE`](NOTICE) for third-party attribution.

---

## Quick start (Windows · Python 3.10)

```
git clone https://github.com/whitedevil1026/E01-index-search.git
cd E01-index-search
pip install -r requirements.txt
python main.py
```

Then in the app: open the **Deps Status** tab → click **Install Missing…**
→ confirm. Done in about a minute.

**No Microsoft C++ Build Tools required.** Pre-built `.whl` files for
the two C-extension dependencies (`pytsk3`, `python-tlsh`) live in
[`wheels/`](wheels/) — the installer dialog passes `--find-links=./wheels`
to pip so they install offline, in seconds.

---

## What it does

| Tab | Purpose |
|---|---|
| **Case** | Create / open a forensic case. View case ID, examiner, root path, and the active hash policy. Change the policy at any time and apply across the case. |
| **Integrity Check** | Pre-flight any EWF segment set. Detects missing chunks (E01–E99, EAA–EZZ, Ex / L / Lx variants), bad EWF signatures, segment-number mismatches, broken Adler-32 trailers, `next` vs `done` markers. Extracts the full EWF header (case #, examiner, OS, GUID, stored MD5/SHA-1, sectors/chunk, etc.) and exports an FTK-Imager-style `.txt` report plus CSVs. |
| **Ingest** | Inspect the image, optionally run a pre-flight integrity check, hash the full E01 file with the case's hash policy, walk every filesystem, and index file names + paths into Tantivy. |
| **Search** | Live-status keyword search across every evidence index in the case. Smart fallback (e.g. `system 32` → `system32`), wildcard support, multi-mode (full-text / exact-name / SHA-256 prefix / TLSH). Each query is hash-chained into the audit log. |
| **Audit Log** | Append-only, SHA-256-chained record of every action: case open, evidence add, query, integrity check, manifest sign, examiner note. Tampering breaks the chain — one click to verify. |
| **Deps Status** | Lists every optional dependency, its version, install command, and whether a bundled wheel is available. One-click installer for anything missing. |

## Hash policy

The examiner picks the **Primary** algorithm and any number of **Extras**
on case creation. The policy is persisted in `case.db` and applied
consistently across:

- Full-segment E01 hashing (Ingest → Compute Now)
- Per-segment file hashing during the integrity check
- Future per-file hashing on the filesystem walk

Supported algorithms: **MD5 · SHA-1 · SHA-256 · SHA-512 · BLAKE2b**.
TLSH is computed separately as a fuzzy similarity hash for "find similar"
workflows; it lives in its own column and is not part of the policy.

Defaults: **Primary = SHA-256**, **Extras = MD5** (for NSRL RDS lookup).
Change at any time in the **Case** tab.

## Court-defensibility

- **Hash-chained audit log** — Each row stores
  `SHA-256(timestamp | actor | action | payload | previous_row_hash)`.
  Any modification to historical rows breaks the chain at that point;
  the toolbar **Verify Audit Chain** button walks the table and reports
  the first mismatch.
- **Ed25519-signed manifest** — `Sign Manifest` writes a JSON file
  listing every file in the case folder with its SHA-256 hash, plus
  the tool's dependency versions and host OS, then signs the bytes
  with a per-case Ed25519 keypair (`keys/case_ed25519.key`).
- **Manifest-level reproducibility** — Tantivy segment IDs and worker
  scheduling are non-deterministic, so the underlying index bytes can
  vary across runs. The manifest's promise is: given the inputs named
  inside it, with the tool versions named inside it, output hashes can
  be independently re-verified. This is the reproducibility level
  defensible in court without overpromising bit-identical output.

## Acquisition-time vs case-policy hashes

The **Image info** tab (section 2a) shows two values labelled
"MD5 written by acquisition tool" and "SHA-1 written by acquisition
tool". These are read **directly from the EWF header** — they are the
hashes EnCase / FTK Imager recorded at acquisition time, **not values
computed by this tool**. They will always be MD5/SHA-1 because that's
what EnCase stores, regardless of your case hash policy.

Section 2b ("Compute Now") streams the full E01 file through your
case's hash policy and shows the **tool-computed** hashes side-by-side.
This is the fingerprint that goes into the audit log and the manifest.

## Layout

```
.
├── main.py                       application entry point
├── requirements.txt
├── LICENSE                       Apache 2.0
├── NOTICE                        third-party attribution
├── wheels/                       pre-built C-extension wheels (Win + cp310)
│   ├── pytsk3-20260418-cp310-cp310-win_amd64.whl
│   └── tlsh-4.5.0-cp310-cp310-win_amd64.whl
├── tools/
│   └── build_wheels.py           rebuild wheels for other Python versions
└── app/
    ├── core/
    │   ├── case.py               SQLite case DB + audit log + config
    │   ├── deps.py               dependency probing
    │   ├── encodings.py          parallel encoding sweep (engine)
    │   ├── ewf_integrity.py      segment integrity + case-metadata + FTK txt
    │   ├── ewf_reader.py         libewf-python wrapper + EwfHandle
    │   ├── filesystem.py         pytsk3 walker
    │   ├── hash_policy.py        HashPolicy + single-pass multi-hash engine
    │   ├── hashing.py            md5 / sha256 / TLSH single-shot helpers
    │   ├── indexer.py            tantivy-py wrapper + analyzer
    │   ├── manifest.py           Ed25519 signed manifest
    │   └── worker.py             QThread base (uses 'done', never 'finished')
    └── ui/
        ├── audit_panel.py
        ├── case_panel.py
        ├── centered_msg.py        popup helpers — center on parent screen
        ├── deps_panel.py
        ├── exported_dialog.py     copyable file-path dialog
        ├── help_dialog.py         Audit / Manifest / TLSH / Hash-Policy help
        ├── ingest_panel.py
        ├── install_dialog.py      in-app pip installer (uses ./wheels)
        ├── integrity_panel.py
        ├── main_window.py
        ├── new_case_dialog.py     case-creation wizard
        └── search_panel.py
```

## Build wheels for other Python versions

The bundled wheels are `cp310` (Python 3.10). On a machine with the
MSVC toolchain, build wheels for additional Pythons once:

```
py -3.11 tools/build_wheels.py
py -3.12 tools/build_wheels.py
py -3.13 tools/build_wheels.py
```

Commit the resulting `.whl` files in `wheels/`. The in-app installer
picks them up automatically.

## Implemented

- **Image access** — E01 read, partition enumeration, parallel
  multi-handle media hashing, TSK + direct-libfsntfs/libfsapfs walking
- **Encryption** — BitLocker, FileVault 2 and LUKS detection and
  key-escrow unlock (recovery key / password / startup key / FVEK)
- **VSS** — Volume Shadow Copy snapshot enumeration and walking, with
  cross-snapshot file deduplication
- **Content indexing** — text extraction from PDF, DOCX/XLSX/PPTX,
  MSG, EML, HTML, RTF and plain-text files (pure-Python, no Tika)
- **Raw scan** — paged multi-encoding string sweep over unallocated
  space and slack (ASCII / UTF-8 / UTF-16 / CJK), IoC pattern
  extraction (emails, URLs, IPs, Luhn-checked cards, crypto
  addresses, phones), file-signature carving (JPEG/PNG/GIF/PDF)
  and YARA-X scanning of carved files
- **Specialized artifacts** — looks *inside* container files:
  Outlook PST/OST mail stores, Windows Registry hives, ESE
  databases (Edge/SRUM/Search), SQLite databases (browser/app/chat),
  Microsoft Defender quarantine (RC4-decoded). Encrypted chat DBs
  (WhatsApp crypt14/15, Signal SQLCipher), memory images and PCAPs
  are detected and flagged
- **Search** — keyword / exact-name / regex (RE2) / SHA-256 prefix /
  TLSH similarity; per-file MD5+SHA-256+TLSH; results export
- **Findings** — browse IoC indicators, YARA matches, carved files
  and flagged artifacts; CSV export
- **Integrity** — EWF segment verification + FTK-style reporting
- **Court-defensibility** — hash-chained audit log, Ed25519 manifest

## What's not yet implemented

The following features are designed in the architecture but not yet
wired in. Each is a discrete chunk of future work:

- **TLSH similarity search** — UI button to find files near a chosen
  TLSH hash; engine is already in place
- **NSRL RDS hash filter** — drop known-good files before indexing
- **Custom YARA rule loading** — load examiner `.yar` files alongside
  the built-in pack
- **Specialized artifact parsers** — PST/OST, registry hives, ESE,
  chat-app databases
- **Multi-image case stitching** (one case spanning many evidence sets)
- **AFF4 read support** via `pyaff4`

## Stack

- **Python 3.10** (cp310 bundled wheels). Python 3.11–3.13 also work
  if you build wheels for those versions.
- **GUI**: PySide6 ≥ 6.6
- **Crypto / signing**: cryptography ≥ 42 (Ed25519, FIPS-capable)
- **Search index**: tantivy-py ≥ 0.22, < 0.26
- **E01 reader**: libewf-python 20240506
- **Filesystem**: The Sleuth Kit via pytsk3, plus direct libfsntfs /
  libfsapfs
- **Encryption**: libbde (BitLocker), libfvde (FileVault), libluksde (LUKS)
- **VSS**: libvshadow
- **Content extraction**: PyMuPDF + extract-msg + Python stdlib
- **Fuzzy hash**: python-tlsh ≥ 4.5
- **Optional / future**: YARA-X, libpff, libesedb, libregf

## Development notes

- **Never** name a custom QThread signal `finished` — it shadows
  `QThread.finished` and crashes when emitted. We use `done`.
- The audit log row hash is `SHA-256(ts | actor | action | payload_json | prev_hash)`
  with `|` as a literal separator. Verification re-derives every row
  forward from the genesis (`prev_hash = "0" * 64`).
- The bundled wheels are checked into git so the install path is
  deterministic. They total 390 KB.
- All UI panels are wrapped in a `QScrollArea`. Each scroll area's
  `setMinimumSize` is capped to keep the QMainWindow's minimum size
  smaller than a 1366 × 768 laptop screen.
