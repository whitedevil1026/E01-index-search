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

- **Windows** with **Python 3.10** (64-bit). Other Python versions
  work too — see [section 5](#5-if-dependencies-are-missing).
- The Python packages listed in [`requirements.txt`](requirements.txt)
  (installed in the next step).

---

## 2. Install

```
git clone https://github.com/whitedevil1026/E01-index-search.git
cd E01-index-search
pip install -r requirements.txt
```

`requirements.txt` contains **every** dependency, so that single
`pip install -r` command installs the whole tool.

To install **offline** — using the pre-built wheels bundled in
[`wheels/`](wheels/), with no C++ compiler needed:

```
pip install -r requirements.txt --find-links wheels/
```

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

It installs the eleven C-extension packages from the pre-built wheels
in `wheels/` — **offline, in seconds, with no Microsoft C++ Build
Tools**. pip output streams live in the dialog.

### Option B — pip on the command line

```
pip install -r requirements.txt --find-links wheels/
```

The `--find-links wheels/` part makes pip use the bundled offline
wheels; drop it to fetch everything from PyPI instead.

### Option C — install one package at a time

The **Deps Status** tab shows the exact `pip install` command for each
missing package — copy and run it.

### Using a Python version other than 3.10

The bundled wheels in `wheels/` are built for **Python 3.10
(cp310, 64-bit)**. On Python 3.11 / 3.12 / 3.13, most packages still
install straight from PyPI with `pip install -r requirements.txt`.
If a C-extension package has no wheel for your version, rebuild the
bundle once on a machine that has the MSVC toolchain:

```
py -3.12 tools/build_wheels.py
```

---

## Dependencies

Everything is in [`requirements.txt`](requirements.txt). Summary:

| Package | Used for |
|---|---|
| `PySide6` | Desktop GUI (Qt 6) |
| `cryptography` | Ed25519 signed manifest, AES-GCM encryption at rest |
| `tantivy` | Full-text search index |
| `charset-normalizer` | Text encoding detection |
| `python-tlsh` | TLSH fuzzy-similarity hashing |
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

The eleven C-extension packages (`pytsk3`, `python-tlsh` and the
`lib*-python` family) ship as pre-built **cp310** wheels in
[`wheels/`](wheels/) for offline, compiler-free installation.

---

## Disclaimer

Provided under the Apache 2.0 license "as is", without warranty. It is
an independent open-source project, not affiliated with any commercial
forensic vendor. Examiners remain responsible for validating tool
output against their own accreditation and evidence-handling
requirements.
