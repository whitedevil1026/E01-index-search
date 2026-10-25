# E01 Index & Search

A self-contained, fully-offline desktop tool for indexing and
searching EWF / EnCase `.E01` (and raw / dd) forensic disk images.
It opens an evidence image, verifies its integrity, walks every
filesystem, extracts and indexes searchable text, parses specialized
artefacts (mailboxes, registry, databases), and lets you search the
whole thing — without ever modifying the evidence.

Licensed under the **[Apache License 2.0](LICENSE)**.

---

## 1. Requirements

- **Windows** with **Python 3.12** (64-bit). Other Python versions
  are covered under "Python versions" in
  [section 5](#5-if-dependencies-are-missing).
- The Python packages listed in [`requirements.txt`](requirements.txt)
  (installed in the next step).

---

## 2. Install

```
git clone https://github.com/KotlaAvinash/E01-index-search.git
cd E01-index-search
pip install -r requirements.txt
```

`requirements.txt` contains **every** dependency, so that single
`pip install -r` command installs the whole tool.

### Fully offline install (no internet, no compiler)

Every dependency in `requirements.txt` — including all transitive
dependencies — is bundled in [`wheels/py312/`](wheels/py312/), the bundle
for Python 3.12 (see [`wheels/README.md`](wheels/README.md)). The one
exception is the optional TLSH package (`py-tlsh`): it has no cp312
wheel, so TLSH fuzzy-similarity search is unavailable on an offline 3.12
install; everything else works. To install the tool without touching the
network at all:

```
pip install -r requirements.txt --find-links wheels/py312 --no-index
```

The `--no-index` flag tells pip to ignore PyPI and use only the
bundled wheels. This works on a fresh Windows + Python 3.12 machine
with no internet and no Microsoft C++ Build Tools.

---

## 3. Run

```
python main.py
```

The application window opens with seven tabs.

---

## 4. How to use it

Work left-to-right through the tabs:

| Tab | What you do here |
|---|---|
| **Case** | Create a new case (or open an existing one) and pick the hash algorithm policy. Do this first — everything else needs an open case. |
| **Integrity Check** | Point at an `.E01` image to verify its segments, check signatures, extract acquisition metadata, and export an integrity report. |
| **Ingest** | Load an image, scan its volumes for encryption (BitLocker / FileVault / LUKS) and Volume Shadow Copies, compute hashes, walk the filesystems, extract file content, and run the raw-string / carving / YARA pass. This is the step that builds the search index. |
| **Search** | Search everything ingested into the case — keyword full-text, exact name, RE2 regex, SHA-256 prefix, or TLSH fuzzy similarity. Export results to CSV. |
| **Findings** | Browse extracted IoCs (emails, URLs, IPs, crypto addresses…), YARA matches, carved files, and flagged artefacts. Export to CSV. |
| **Audit Log** | View the tamper-evident, hash-chained record of every action, and verify the chain with one click. |
| **Deps Status** | See which dependencies are installed, and install any that are missing (see below). |

**Typical workflow:** create a case → (optionally) run an integrity
check → ingest an image → search and review findings → verify the
audit chain.

Every long operation shows live progress and can be cancelled.

---

## 5. If dependencies are missing

The tool still launches even if some packages are missing — affected
features simply degrade until you install them. You have three ways to
fix it:

### Option A — the in-app installer (easiest)

1. Open the **Deps Status** tab. Missing packages are listed in red.
2. Click **Install Missing…**.
3. In the dialog, click **Install Now**.

It installs the missing packages, pointing pip at the bundle in
`wheels/py{major}{minor}/` for the Python it runs under (for example
`wheels/py312/`). Every compiled package the tool needs — PySide6,
cryptography, tantivy, pytsk3, the libyal readers and the rest — comes
from a pre-built wheel there, so **no Microsoft C++ Build Tools** are
needed. The exception is the optional TLSH package (`py-tlsh`), which has
no 3.12 wheel; the dialog leaves it unticked. The installer passes
`--find-links` but not `--no-index`, so pip may still contact PyPI; for a
strictly offline install use Option B. pip output streams live in the
dialog.

### Option B — pip on the command line

```
pip install -r requirements.txt --find-links wheels/py312 --no-index
```

Adding `--no-index` makes pip use only the bundled wheels (no network).
Drop `--no-index` to let pip mix bundled wheels with PyPI; drop both
flags to fetch everything from PyPI.

### Option C — install one package at a time

The **Deps Status** tab shows the exact `pip install` command for each
missing package — copy and run it.

### Python versions

A compiled wheel is tagged for one Python minor version, so bundles are
kept one per interpreter under `wheels/`:

- **Python 3.12 — current.** `wheels/py312` installs fully offline.
- **Python 3.10 — legacy.** `wheels/py310` is kept for older installs
  only; Python 3.10 reaches end of life on 31 October 2026.
- **Any other version** installs from PyPI with
  `pip install -r requirements.txt`, or from a bundle you rebuild with
  the `pip download` commands in the "OFFLINE INSTALL" section of
  [`requirements.txt`](requirements.txt).

---

## Dependencies

Everything is in [`requirements.txt`](requirements.txt). Summary:

| Package | Used for |
|---|---|
| `PySide6-Essentials` | Desktop GUI (Qt 6 Core / Gui / Widgets) |
| `cryptography` | Ed25519 signed manifest, AES-GCM encryption at rest |
| `tantivy` | Full-text search index |
| `charset-normalizer` | Text encoding detection |
| `py-tlsh` *(optional, not bundled on 3.12)* | TLSH fuzzy-similarity hashing — needs a C++ compiler on 3.12 |
| `libewf-python` | EWF / EnCase `.E01` image reader |
| `pytsk3` | The Sleuth Kit filesystem walker |
| `libvshadow-python` | Volume Shadow Copy (VSS) snapshots |
| `libbde-python` | BitLocker decryption |
| `libfvde-python` | FileVault 2 decryption |
| `libluksde-python` | LUKS decryption |
| `libfsntfs-python` | Direct NTFS reader (TSK fallback) |
| `libfsapfs-python` | Direct APFS reader (TSK fallback) |
| `pymupdf` | PDF text extraction |
| `extract-msg` | Outlook `.msg` email parsing |
| `yara-x` | YARA-X malware / IoC scanning |
| `libpff-python` | Outlook PST / OST mail stores |
| `libregf-python` | Windows Registry hives |
| `libesedb-python` | ESE databases (Edge / SRUM / Windows Search) |

**Every** dependency above — plus all transitive dependencies — ships
in [`wheels/py312/`](wheels/py312/) (~120 MB, 43 files). The bundle
mixes cp312 wheels, abi3 wheels and pure-Python `py3-none-any` wheels,
plus two pure-Python source packages (`red-black-tree-mod`,
`win_unicode_console`) that pip builds with the bundled `setuptools` and
`wheel`. A fully air-gapped Windows + Python 3.12 install with
`--no-index` works out of the box: no internet, no Microsoft C++ Build
Tools. The one exception is the optional `py-tlsh`, which has no cp312
wheel, so TLSH fuzzy-similarity search is unavailable on 3.12; the
legacy `wheels/py310` bundle still carries a prebuilt TLSH wheel.

---

## Disclaimer

Provided under the Apache 2.0 license "as is", without warranty. It is
an independent open-source project, not affiliated with any commercial
forensic vendor. Examiners remain responsible for validating tool
output against their own accreditation and evidence-handling
requirements.
