# E01 Indexing Tool — try1

A self-contained desktop forensic indexer for EWF / EnCase E01 images.

Phase 0 + minimal Phase 1 from the May 2026 review document.

Licensed under the **[Apache License 2.0](LICENSE)** — the de-facto
standard for forensic open-source tooling (Autopsy, Plaso, Volatility,
pytsk3, TLSH all use it). See [`NOTICE`](NOTICE) for the third-party
attribution required when redistributing.

## Quick start (Windows, Python 3.10) — no compiler required

```
git clone https://github.com/<you>/<repo>.git
cd <repo>/try1
pip install -r requirements.txt
python main.py
```

Then in the app: open the **Deps Status** tab and click **Install Missing**.

Pre-built `.whl` files for the two C-extension packages (`pytsk3` and
`python-tlsh`) are bundled in [`wheels/`](wheels/). The installer
passes `--find-links=./wheels` to pip so they install **offline, in
seconds, with no Microsoft C++ Build Tools download**.

Estimated install time from clean Python 3.10:
- Pure-PyPI wheels (PySide6, tantivy, cryptography, libewf-python,
  charset-normalizer, PyMuPDF, extract-msg, yara-x): ~60 seconds
- Bundled wheels (pytsk3, tlsh): ~2 seconds
- Total: under two minutes on a typical connection

## What's in this try

- **PySide6 desktop GUI** — Case, Integrity Check, Ingest, Search,
  Audit Log, Deps Status tabs.
- **SQLite case database** with **append-only, hash-chained audit log**
  (court-defensibility).
- **Ed25519 signed manifest** of the case (reproducibility contract).
- **Per-case hash policy** — examiner picks Primary
  (MD5/SHA-1/SHA-256/SHA-512/BLAKE2b) plus any Extras; applied to every
  file in the case.
- **libewf-python** E01 reader (graceful fallback if not installed).
- **pytsk3** filesystem walker.
- **tantivy-py >= 0.22** indexer.
- **MD5 + SHA-256 + TLSH** per-file hashing.
- **EWF integrity checker** (Phase 0 pre-flight) — finds missing
  chunks, bad Adler-32 trailers, wrong `next`/`done` markers; extracts
  the full EWF header metadata (case #, examiner, OS, GUID, stored
  hashes, sectors/chunk, etc.) and emits FTK-style TXT + CSV reports.
- **In-app installer** for any missing forensic deps, with live pip
  output and offline wheel fallback.

## Not yet (deferred to try2+)

bulk_extractor, Tika, YARA-X rules, NSRL RDS hash filter, VSS
chunk-level dedup, BitLocker/FileVault/LUKS escrow, mobile-DB
encryption, Quickwit scale-out, BGE-M3 embeddings, AFF4.

## If you're on Python 3.11 / 3.12 / 3.13

The bundled wheels are `cp310` (Python 3.10). For other Python
versions, run the wheel builder once on a machine with the
MSVC toolchain installed:

```
py -3.11 tools/build_wheels.py
py -3.12 tools/build_wheels.py
py -3.13 tools/build_wheels.py
```

Commit the resulting `.whl` files in `wheels/` and the in-app installer
will pick them up automatically.

## Layout

```
try1/
  main.py                       entry point
  requirements.txt
  wheels/                       pre-built C-extension wheels
    pytsk3-20260418-cp310-cp310-win_amd64.whl
    tlsh-4.5.0-cp310-cp310-win_amd64.whl
  tools/
    build_wheels.py             rebuild bundled wheels for other Pythons
  app/
    ui/                         PySide6 widgets
      main_window.py
      case_panel.py
      integrity_panel.py
      ingest_panel.py
      search_panel.py
      audit_panel.py
      deps_panel.py
      install_dialog.py         in-app pip installer (uses ./wheels)
      help_dialog.py            in-app help for Audit / Manifest / TLSH / Policy
      exported_dialog.py        selectable-path copy dialog
      new_case_dialog.py        case-creation wizard
      centered_msg.py           popup centering helpers
    core/
      deps.py                   import-time dependency probing
      case.py                   SQLite case DB + audit log + config
      manifest.py               Ed25519 signed manifest
      hashing.py                MD5 + SHA-256 + TLSH (legacy single-shot)
      hash_policy.py            HashPolicy + multi-hash streaming engine
      ewf_reader.py             libewf-python wrapper + fallback
      filesystem.py             pytsk3 walker + fallback
      indexer.py                tantivy-py writer/reader + fallback
      ewf_integrity.py          segment integrity + case-metadata extractor
      encodings.py              parallel encoding sweep
      worker.py                 QThread base (no "finished" signal — uses "done")
```

## Notes for future tries

- **Never** name custom QThread signals `finished` — shadows the
  built-in and crashes. We use `done` everywhere.
- The audit log is **hash-chained**: each row stores the SHA-256 of
  `(its own payload | the previous row's hash)`, so tampering breaks
  the chain. Verify it from the toolbar.
- The manifest is regenerated and re-signed every time `Sign Manifest`
  is clicked, covering the current case state.
- "Acquired MD5/SHA-1" in the Ingest panel comes from the EWF header
  (recorded by the original acquisition tool). It is **not** something
  this tool computes; click `Compute Now` in section 2b to get hashes
  per your case policy.
