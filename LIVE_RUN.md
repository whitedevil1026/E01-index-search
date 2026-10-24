# Running a real case

> ## Python version — read before installing (updated 2026-10-18)
>
> **Use Python 3.12.** The project originally pinned 3.10, which reaches
> end of life on 31 October 2026; `requirements.txt` now targets 3.12
> (supported to October 2028) and every pin was verified to install from
> a cp312 binary wheel.
>
> ```
> py -3.12 -m venv .venv312
> .venv312\Scripts\python -m pip install -r requirements.txt
> ```
>
> Install by group if pip reports `resolution-too-deep` — the libyal
> family plus PySide6 can exceed its resolver depth in one command.
>
> **Run everything through that interpreter**, including the suite:
> `.venv312\Scripts\python tools/test_ingest_suite.py "<image.E01>"`.
>
> ### What is verified
>
> * 19 of 20 dependencies install and import on 3.12.
> * A fully offline install works: a fresh 3.12 venv installed all 19
>   modules from a local bundle with `--no-index` and no C++ compiler.
>   `setuptools` and `wheel` must be in the bundle — two dependencies
>   publish no wheel and their (pure-Python) sdists need setuptools to
>   build. The rebuild commands are in `requirements.txt`.
> * Offline bundles are kept one per interpreter. `wheels/py312` is the
>   current bundle and installs on 3.12 with `--no-index`;
>   `wheels/py310` is the legacy Python 3.10 bundle (3.10 reaches end of
>   life on 31 October 2026) and cannot be used on 3.12. To rebuild
>   `wheels/py312`, use the commands in `requirements.txt`.
>
> ### The one gap: TLSH
>
> `py-tlsh` has no cp312 wheel — sdist only, so it needs MSVC build
> tools. TLSH is optional (`HAS_TLSH`): without it only the
> fuzzy-similarity search mode is unavailable, and the suite reports
> that as an `[ENV ]` line rather than a failure.
>
> Do **not** install the `tlsh` package from PyPI as a substitute —
> version 0.2.0 is an empty placeholder wheel with dist-info and no
> module.

## 1. Preflight (5 minutes, before touching evidence)

```
cd "F:\e01 indexing\e01-index-search"
python tools/test_ingest_suite.py "X:\path\to\your.E01"
```

Run this against the actual image first. It is read-only — it never
writes to the evidence — and it exits non-zero if anything fails.

It verifies, among ~89 checks:

* the file really is EWF (signature, not just the extension);
* every segment is present and passes the integrity check;
* the computed MD5 matches the acquisition hash in the image header —
  **if this fails, stop: the image is not what it claims to be**;
* volumes, encryption and shadow copies are detected;
* the evidence file is byte-identical after the whole run.

Scratch cases go to `_suite_work/` beside the tool, on the evidence
volume. Override with `E01_SUITE_WORKDIR` if that volume is read-only.

**Confirm the evidence volume is mounted read-only or write-blocked.**
The tool only ever opens images for reading, and the suite proves the
bytes are unchanged, but that is not a substitute for a write blocker.

---

## 2. Settings for a real case

Defaults are already correct for a full case. Verify these before
starting a long run:

| Control | Set to | Why |
|---|---|---|
| **File-count cap** | `0` (default) | Anything else stops the walk partway. The default is 0 precisely so a case is never quietly partial. |
| **Sweep workers** | 4–8 | The sweep is the slowest stage. ~3x faster at 8 workers than 1. Costs ~110 MB RAM per worker. |
| **Encodings** | `windows` (default) | ASCII + UTF-16LE/BE + UTF-8 + cp1252. Choose `full` only if the case may involve Japanese, Chinese or Korean text — it is roughly 2x slower. |
| **Single-pass raw scan** | off (default) | Saves one read of the image but forces the sweep sequential. The parallel sweep wins on any multi-core machine. Turn it on only if disk throughput, not CPU, is the bottleneck. |

Everything else (hashing, content extraction, artifacts, carving, YARA,
VSS) can stay on for a full case.

### Choosing worker count

Peak memory is bounded by workers, **not** by image size — a 1 GB image
peaks no higher than a 150 MB one.

| Workers | Peak RSS | Guidance |
|---|---|---|
| 1 | ~145 MB | Fallback / low-memory host |
| 4 | ~470 MB | Safe default |
| 8 | ~900 MB | Good on 16 GB+ with 8 cores |

Do not exceed physical cores; the work is CPU-bound.

---

## 3. Expected runtime

Byte-level stages scale with image size. Measured throughput on this
machine (8 logical CPUs):

| Stage | Throughput | Per 100 GB |
|---|---|---|
| Whole-image hash (4 workers) | ~206 MB/s | ~0.14 h |
| Raw sweep + IoC, 1 worker | ~11 MB/s | ~2.6 h |
| **Raw sweep + IoC, 8 workers** | **~33 MB/s** | **~0.9 h** |
| Carving | ~50 MB/s | ~0.6 h |

**Budget roughly 2–4 hours per 100 GB** for the byte-level passes with
8 workers, on top of the filesystem walk.

The walk scales with **file count**, not image size, and is the hard
part to predict: per-file hashing and text extraction dominate on a
drive with millions of small files. On a real Windows system image
expect the walk to take longer than every byte-level stage combined.

The Ingest tab shows elapsed time and a per-stage remaining estimate
throughout, and the total on completion.

---

## 4. During the run

* The ingest is cancellable. Cancelling commits what has been indexed
  so far and leaves the audit chain intact.
* If the worker pool cannot start, the tool logs
  `[warn] parallel sweep unavailable … falling back to single process`
  and completes sequentially. Results are identical, only slower — the
  pass is never lost.
* If an ingest dies partway, the index is still committed. Re-ingesting
  creates a **new** evidence item rather than overwriting the old one.

### Watch the log for these

Any line containing `[TRUNCATED]` means collection stopped short and the
case is **incomplete**:

| Message | Meaning | Action |
|---|---|---|
| `the file-count cap of N was reached` | The walk stopped early | Set the cap to 0 and re-ingest |
| `the distinct-IoC cap of 500,000 was reached` | New indicators are no longer being recorded | Findings are partial; narrow the scope or accept the cap knowingly |
| `carving stopped at the cap of 100,000 files` | More carvable files may exist | Accept, or carve a narrower byte range |

Each is also written to the audit log (`ingest.walk_truncated`,
`ingest.ioc_truncated`, `ingest.carve_truncated`), so a partial case is
provable after the fact rather than a surprise in court.

---

## 5. After the run

1. **Audit tab → Verify chain.** Must report the chain verified. This is
   the tamper-evidence for every action taken.
2. **Sign the manifest** (Case tab). Do this after the ingest finishes —
   the index settles its background merges first, so the signed hashes
   match the files on disk.
3. **Search → select a hit → "Where this hit came from"** shows the
   filesystem path, volume, image offset, inode and hashes. The
   **Evidence** column names the source image when a case holds several.
4. **Export this file from the image** recovers the original bytes,
   hashes them under the case policy, and checks them against the hash
   recorded at ingest. Keep **"Write hash receipt"** ticked — it writes a
   `.verify.txt` beside the file recording origin, digests and verdict,
   so the exported copy is self-describing.
5. **Findings tab**: if the summary says *"showing the first N of M"*,
   the view is capped — raise the Rows limit before exporting the CSV.
   The CSV export writes exactly the rows loaded.

---

## 6. Known limits

* **Ex01 encryption is not supported** — libewf cannot decrypt it. Such
  an image is tagged "encrypted, no usable text".
* **AFF4 and VMDK are not readable.** Convert first:
  `qemu-img convert -O raw in.vmdk out.raw`.
* **Registry / PST / ESE parsing has only been validated on synthetic
  data** and graceful-failure paths. A real system image is the first
  genuine test of those parsers — check the artifact counts in the log
  look plausible.
* **The tool reads images, not live disks.** It does not acquire; use a
  write blocker and an imager (FTK Imager, `ewfacquire`, `dc3dd`) to
  produce the E01 first.
* Findings default to at most 500,000 distinct IoC indicators per
  evidence item.

---

## Where these numbers come from

Measured on this build against `drive1.E01` (1.06 GB) and
`2011-10-19-Sample.E01` (150 MB) on an 8-logical-CPU Windows host, with
`psutil` sampling peak RSS across the process family every 50 ms.
Throughput on your hardware and on denser evidence will differ —
re-measure with the suite on a representative image before quoting a
completion time to anyone.

---

## 7. Known-file hash sets (NSRL)

Separates files that shipped with the operating system or an
application from files that were put on the machine. Usually the first
question worth asking, and it cuts the volume an examiner has to read.

**Import once, in the Known Files tab.** Sets live in `known_sets.db`
beside the application, not inside a case, so one import serves every
later case. Override the location with `E01_KNOWN_SETS_DB`.

| Source | Use |
|---|---|
| **NSRL RDSv3 (SQLite)** | NIST retired the old RDS 2.xx text format. Prefer the **minimal** publication: same `FILE` view (sha256, sha1, md5, name, size) at a fraction of the size — a full Modern set runs to hundreds of GB unzipped. Opened read-only; only the hash columns are copied. |
| **Plain hash list (.txt)** | One hash per line, MD5/SHA-1/SHA-256 mixed freely, `#` comments and trailing filenames (as `md5sum` writes) tolerated. Needs no network — the universal path. |
| **CSV** | Any delimited file whose header names `md5`, `sha1` or `sha256`. |

Then tick **"Flag known files"** on the Ingest tab (on by default; it
needs per-file hashing). The log reports how many matched, and
`ingest.known_files` records it in the audit log.

### A match labels; it never deletes

Nothing is removed from the index or the case database — only labelled
with the set that matched. This is deliberate:

* A hash set is not a statement of innocence. Attackers run signed
  vendor binaries (`certutil.exe`, `psexec.exe`) as the attack, and
  those are in NSRL.
* A set can be stale, and a file altered by one byte stops matching.

**"Hide known files"** in Search is a view option, **off by default**,
and whenever it is on the status line states how many rows it hid.

Probabilistic filters are deliberately unsupported for this. CIRCL
publishes a ~700 MB Bloom filter of the NSRL SHA-1 space, which is
tempting for size, but a Bloom filter has false positives by
construction — it can call a suspect's file "known". That is exactly
the error that loses evidence, so only exact hash sets are accepted.
