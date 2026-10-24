# Per-Python Offline Wheel Bundles Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep the old cp310 bundle as a clearly labelled legacy bundle, add a committed Python 3.12 bundle, and make the in-app installer and dependency notes pick the bundle that matches the running interpreter.

**Architecture:** Bundles move to `wheels/py{major}{minor}/` (`wheels/py310/` legacy, `wheels/py312/` current). One new module, `app/core/wheel_bundle.py`, owns "which bundle belongs to this interpreter"; `deps.py` and `install_dialog.py` stop computing the path themselves and ask it. Docs and the build script follow the same layout.

**Tech Stack:** Python 3.12 (`.venv312`), PySide6, pip `--find-links`, pytest (dev-only).

**Spec:** The decision recorded in chat on 2026-10-24 — "label `wheels/` legacy and build on the new Python version" — plus the validation in `PROJECT_HANDOFF.md` §13: 23 of 38 legacy wheels install on 3.12, but the 15 that matter (every libyal reader, `pytsk3`, `tantivy`, `python_tlsh`) are cp310-only, and `requirements.txt` cannot be satisfied from the legacy bundle on 3.12.

## Global Constraints

- Supported interpreter: **Python 3.12**, run through `.venv312\Scripts\python.exe`.
- Python 3.10 reaches end of life on **31 October 2026**. `wheels/py310/` is kept, not deleted, and labelled legacy everywhere it is shown.
- `wheels/py310/python_tlsh-4.5.0-cp310-cp310-win_amd64.whl` is the only prebuilt TLSH binary the project has. It must survive the move unchanged.
- No cp312 TLSH: `py-tlsh` publishes no cp312 wheel and MSVC is not installed on this host (`cl.exe` not on PATH). The py312 bundle ships **without** TLSH; `HAS_TLSH` degrades as today.
- Layout is exactly `wheels/py{major}{minor}/` — `py310`, `py312`. No other folder names.
- The py312 bundle must contain `setuptools` and `wheel`: `red-black-tree-mod` and `win_unicode_console` ship sdists only.
- **Decision to validate:** bundles are committed with **plain git, not Git LFS**. LFS's free quota is 1 GB of bandwidth a month — about eight clones of a 122 MB bundle. Plain git only warns on files between 50 and 100 MB; the largest wheel (`pyside6_essentials-6.12.0-cp310-abi3`) is 78 MB, under the 100 MB hard limit. Cost: the repository grows by ~122 MB.
- Evidence is never read or written by this work.
- Work continues on branch `fix/defect-sweep-provenance-export`.
- Every commit ends with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **An interpreter with no bundle** (this machine's default `python` is 3.14) must get no `--find-links` and a "no bundled wheels for Python 3.14" note — never the py310 wheels. Pinned by `test_bundle_dir_for_none_without_folder` (Task 1) and `test_pip_args_omits_find_links_without_bundle` (Task 2).
2. **Running under 3.10** finds `wheels/py310/` but must say it is legacy and give the end-of-life date. Pinned by `test_c_ext_note_legacy_names_eol` (Task 2).
3. **A bundle folder that exists but holds no `.whl`** is treated as absent, not as a bundle. Pinned by `test_bundle_dir_for_none_when_empty` (Task 1).
4. **A wheel locked to another interpreter inside `wheels/py312/`** (a `-cp310-cp310-` tag) makes the offline install fail on a clean machine. Pinned by the tag check and the fresh-venv `--no-index` install in Task 3.
5. **Stale instructions** that still say `--find-links wheels/` find zero wheels after the move and silently go to the network or fail offline. Pinned by the grep in Task 4.

---

### Task 1: Bundle resolver

**Files:**
- Create: `app/core/wheel_bundle.py`
- Create: `tests/test_wheel_bundle.py`
- Create: `requirements-dev.txt` (one line: `pytest>=8`)

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `WHEELS_ROOT: Path` — `<project root>/wheels`
  - `LEGACY_VERSIONS: frozenset[tuple[int, int]] = frozenset({(3, 10)})`
  - `bundle_dir_for(version: tuple[int, int] | None = None, root: Path | None = None) -> Path | None` — `root / f"py{major}{minor}"` when that folder holds at least one `*.whl`, else `None`. `version` defaults to `sys.version_info[:2]`, `root` to `WHEELS_ROOT`.
  - `bundle_wheel_names(version=None, root=None) -> list[str]` — sorted `.whl` names in that bundle, `[]` if none.
  - `is_legacy(version: tuple[int, int]) -> bool`

- [ ] **Step 1: Install pytest into the venv**

Run: `.venv312\Scripts\python -m pip install -r requirements-dev.txt`
Expected: `Successfully installed pytest-…`

- [ ] **Step 2: Write the failing tests**

```python
from pathlib import Path
from app.core import wheel_bundle as wb

def _mk(root: Path, sub: str, *names: str) -> None:
    (root / sub).mkdir(parents=True, exist_ok=True)
    for n in names:
        (root / sub / n).write_bytes(b"")

def test_bundle_dir_for_selects_matching_interpreter(tmp_path):
    _mk(tmp_path, "py310", "a-cp310-cp310-win_amd64.whl")
    _mk(tmp_path, "py312", "b-cp312-cp312-win_amd64.whl")
    assert wb.bundle_dir_for((3, 12), tmp_path) == tmp_path / "py312"
    assert wb.bundle_dir_for((3, 10), tmp_path) == tmp_path / "py310"

def test_bundle_dir_for_none_without_folder(tmp_path):
    _mk(tmp_path, "py310", "a.whl")
    assert wb.bundle_dir_for((3, 14), tmp_path) is None

def test_bundle_dir_for_none_when_empty(tmp_path):
    _mk(tmp_path, "py312", "README.txt")
    assert wb.bundle_dir_for((3, 12), tmp_path) is None

def test_bundle_wheel_names_sorted(tmp_path):
    _mk(tmp_path, "py312", "z.whl", "a.whl", "notes.txt")
    assert wb.bundle_wheel_names((3, 12), tmp_path) == ["a.whl", "z.whl"]

def test_is_legacy():
    assert wb.is_legacy((3, 10)) is True
    assert wb.is_legacy((3, 12)) is False

def test_default_root_is_project_wheels():
    assert wb.WHEELS_ROOT == Path(__file__).resolve().parent.parent / "wheels"
```

- [ ] **Step 3: Run to verify they fail**

Run: `.venv312\Scripts\python -m pytest tests/test_wheel_bundle.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.core.wheel_bundle'`

- [ ] **Step 4: Implement `app/core/wheel_bundle.py`** with the five names in the Interfaces block. Standard library only (`sys`, `pathlib`).

- [ ] **Step 5: Run to verify they pass**

Run: `.venv312\Scripts\python -m pytest tests/test_wheel_bundle.py -v`
Expected: `6 passed`

- [ ] **Step 6: Commit**

```bash
git add app/core/wheel_bundle.py tests/test_wheel_bundle.py requirements-dev.txt
git commit -m "feat(wheels): resolve the offline bundle for the running interpreter"
```

---

### Task 2: Point the installer and dependency notes at the resolver

**Files:**
- Modify: `app/core/deps.py:41-65`
- Modify: `app/ui/install_dialog.py:7-11`, `:28-37`, `:185-190`
- Modify: `app/ui/deps_panel.py:53-57` (tooltip text)
- Modify: `app/ui/help_dialog.py:40-43` ("Bundled wheels" section text)
- Create: `tests/test_bundle_consumers.py`

**Interfaces:**
- Consumes: `bundle_dir_for`, `bundle_wheel_names`, `is_legacy` from Task 1.
- Produces:
  - `deps._c_ext_note(version: tuple[int, int] | None = None, root: Path | None = None) -> str`
  - `install_dialog._pip_args(pip_args: list[str], version=None, root=None) -> list[str]` — the full `["-m", "pip", "install", "--disable-pip-version-check", ...]` list; adds `["--find-links", str(bundle)]` only when `bundle_dir_for` returns a folder.
  - `install_dialog.BUNDLED_WHEELS_DIR` is **removed**; `bundled_wheel_names()` delegates to `wheel_bundle.bundle_wheel_names()`.

- [ ] **Step 1: Write the failing tests**

```python
from pathlib import Path
from app.core import deps
from app.ui import install_dialog as idlg

def _bundle(root: Path, sub: str) -> None:
    (root / sub).mkdir(parents=True)
    (root / sub / "x.whl").write_bytes(b"")

def test_c_ext_note_names_bundle_folder(tmp_path):
    _bundle(tmp_path, "py312")
    assert "wheels/py312" in deps._c_ext_note((3, 12), tmp_path)

def test_c_ext_note_legacy_names_eol(tmp_path):
    _bundle(tmp_path, "py310")
    note = deps._c_ext_note((3, 10), tmp_path)
    assert "legacy" in note.lower() and "31 October 2026" in note

def test_c_ext_note_without_bundle_names_version(tmp_path):
    note = deps._c_ext_note((3, 14), tmp_path)
    assert "3.14" in note and "switch to Python 3.10" not in note

def test_pip_args_uses_matching_bundle(tmp_path):
    _bundle(tmp_path, "py312")
    args = idlg._pip_args(["pytsk3"], (3, 12), tmp_path)
    assert args[args.index("--find-links") + 1] == str(tmp_path / "py312")
    assert args[-1] == "pytsk3"

def test_pip_args_omits_find_links_without_bundle(tmp_path):
    _bundle(tmp_path, "py310")
    assert "--find-links" not in idlg._pip_args(["pytsk3"], (3, 14), tmp_path)

def test_old_constant_is_gone():
    assert not hasattr(idlg, "BUNDLED_WHEELS_DIR")
```

Run with `QT_QPA_PLATFORM=offscreen` set — `install_dialog` imports PySide6.

- [ ] **Step 2: Run to verify they fail**

Run: `set QT_QPA_PLATFORM=offscreen && .venv312\Scripts\python -m pytest tests/test_bundle_consumers.py -v`
Expected: FAIL — `_c_ext_note() takes 0 positional arguments` / `no attribute '_pip_args'`

- [ ] **Step 3: Implement.** In `deps.py`, replace `_bundled_wheels_exist()` and the two note constants with `_c_ext_note(version, root)`: bundled note names `wheels/py{XY}/`; legacy note adds "legacy — Python 3.10 reaches end of life on 31 October 2026"; no-bundle note names the running version and points at `requirements.txt` for the rebuild commands. In `install_dialog.py`, extract `_pip_args` from the method at `:182-196` and call it there. Update the `deps_panel.py` tooltip and the `help_dialog.py` section to say "the bundle for your Python version in `wheels/py{XY}/`".

- [ ] **Step 4: Run to verify they pass, and nothing else references the old constant**

Run: `set QT_QPA_PLATFORM=offscreen && .venv312\Scripts\python -m pytest tests -v`
Expected: `12 passed`
Run: `git grep -n "BUNDLED_WHEELS_DIR\|_bundled_wheels_exist"`
Expected: no output

- [ ] **Step 5: Commit**

```bash
git add app/core/deps.py app/ui/install_dialog.py app/ui/deps_panel.py app/ui/help_dialog.py tests/test_bundle_consumers.py
git commit -m "feat(wheels): installer and dependency notes follow the running interpreter"
```

---

### Task 3: Move the bundles into the per-interpreter layout

**Files:**
- Move: `wheels/*.whl` → `wheels/py310/` (38 files, `git mv`, history kept)
- Move: `wheels312/*` → `wheels/py312/` (43 files, newly tracked)
- Create: `wheels/README.md`
- Modify: `.gitignore:69-82`

**Interfaces:**
- Consumes: the resolver (Task 1) to verify placement.
- Produces: `wheels/py310/` and `wheels/py312/` on disk and in git.

- [ ] **Step 1: Move the legacy bundle with history**

```bash
git mv wheels wheels_py310_tmp
mkdir wheels
git mv wheels_py310_tmp wheels/py310
```
Expected: `git status` shows 38 renames `wheels/X.whl -> wheels/py310/X.whl`

- [ ] **Step 2: Move the 3.12 bundle in and drop the empty folder**

Run: `mkdir wheels\py312 && move wheels312\* wheels\py312\ && rmdir wheels312`

- [ ] **Step 3: Label them.** `wheels/README.md` has one section per folder: `py312` — current, installs offline with no compiler, rebuild commands; `py310` — **legacy**, Python 3.10 reaches end of life on 31 October 2026, kept because `python_tlsh-4.5.0-cp310-cp310-win_amd64.whl` is the only prebuilt TLSH binary.

- [ ] **Step 4: Fix `.gitignore`.** Delete the `wheels312/` block (`:78-82`). Replace `!wheels/*.whl` with `!wheels/**`.

- [ ] **Step 5: Verify placement, tags and ignore rules**

Run: `dir /b wheels\py310\*.whl | find /c ".whl"` → `38`
Run: `dir /b wheels\py312 | find /c "."` → `43`
Run: `dir /b wheels\py312 | findstr /r "cp3[0-9]*-cp3" | findstr /v "cp312-cp312"`
Expected: no output — no wheel in `py312` is locked to another interpreter (`cp310-abi3` is fine; it is not `cp310-cp310`)
Run: `git check-ignore -v wheels/py312/pytsk3-20260715-cp312-cp312-win_amd64.whl`
Expected: no output
Run: `.venv312\Scripts\python -c "from app.core.wheel_bundle import bundle_dir_for as b; print(b((3,12)), b((3,10)), b((3,14)))"`
Expected: `...\wheels\py312 ...\wheels\py310 None`

- [ ] **Step 6: Prove the offline install on a clean venv**

```bash
py -3.12 -m venv %TEMP%\bundlecheck
%TEMP%\bundlecheck\Scripts\python -m pip install --no-index --find-links wheels\py312 -r requirements.txt
```
Expected: completes with no network and no compiler; importing the 19 modules (`cryptography PySide6 tantivy charset_normalizer pyewf pytsk3 pyvshadow pybde pyfvde pyluksde pyfsntfs pyfsapfs pymupdf extract_msg yara_x pypff pyregf pyesedb psutil`) succeeds for all 19.

- [ ] **Step 7: Commit**

```bash
git add -A wheels .gitignore
git commit -m "chore(wheels): wheels/py310 legacy bundle, wheels/py312 current bundle"
```

---

### Task 4: Build script and documentation follow the layout

**Files:**
- Modify: `tools/build_wheels.py:1-30` (docstring and output folder)
- Modify: `README.md:34-48`, `:88-125`, `:150-158`
- Modify: `requirements.txt:17-33` (the "OFFLINE INSTALL" header)
- Modify: `LIVE_RUN.md` (the bullet that says the committed `wheels/` bundle is unusable on 3.12)
- Create: `tests/test_build_wheels.py`

**Interfaces:**
- Consumes: `WHEELS_ROOT` from Task 1.
- Produces: `build_wheels.WHEELS_DIR == WHEELS_ROOT / f"py{major}{minor}"` for the interpreter running it.

- [ ] **Step 1: Write the failing test**

```python
import importlib.util, sys
from pathlib import Path
from app.core.wheel_bundle import WHEELS_ROOT

def test_build_output_is_per_interpreter():
    path = Path(__file__).resolve().parent.parent / "tools" / "build_wheels.py"
    spec = importlib.util.spec_from_file_location("build_wheels", path)
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    v = sys.version_info
    assert mod.WHEELS_DIR == WHEELS_ROOT / f"py{v.major}{v.minor}"
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv312\Scripts\python -m pytest tests/test_build_wheels.py -v`
Expected: FAIL — `WHEELS_DIR` is `...\wheels`, not `...\wheels\py312`

- [ ] **Step 3: Implement and rewrite the docs.** `build_wheels.py` writes to `WHEELS_ROOT / f"py{XY}"` and its docstring says so. README "Fully offline install" and "Option B" use `--find-links wheels/py312`; the "Using a Python version other than 3.10" section becomes "Python versions": py312 current, py310 legacy with the EOL date, any other version installs from PyPI or a rebuilt bundle. `requirements.txt` and `LIVE_RUN.md` name `wheels/py312` and `wheels/py310` instead of `wheels312` / "dead weight".

- [ ] **Step 4: Verify the test and that no stale command survives**

Run: `set QT_QPA_PLATFORM=offscreen && .venv312\Scripts\python -m pytest tests -v`
Expected: `13 passed`
Run: `git grep -nE "find-links[ =]+wheels/?( |$)|wheels312" -- README.md requirements.txt LIVE_RUN.md app tools`
Expected: no output

- [ ] **Step 5: Commit**

```bash
git add tools/build_wheels.py README.md requirements.txt LIVE_RUN.md tests/test_build_wheels.py
git commit -m "docs(wheels): build script and install docs use wheels/py{XY}"
```

---

### Task 5: Full verification and push

**Files:** none modified.

- [ ] **Step 1: Unit tests**

Run: `set QT_QPA_PLATFORM=offscreen && .venv312\Scripts\python -m pytest tests -v`
Expected: `13 passed`

- [ ] **Step 2: The app shows the right bundle**

Run (offscreen): build `MainWindow`, read the C-extension note in the Deps Status tab.
Expected: 8 tabs; the note names `wheels/py312/` and does not mention Python 3.10.

- [ ] **Step 3: Regression suite on real evidence**

Run: `.venv312\Scripts\python tools/test_ingest_suite.py "F:\e01 indexing\2011-10-19-Image\2011-10-19-Sample.E01"`
Expected: `PASSED 110   FAILED 0   SKIPPED 0   ENV-GAPS 2` (the two TLSH lines)

- [ ] **Step 4: Push**

Run: `git push`
Expected: succeeds; a "larger than GitHub's recommended maximum file size of 50.00 MB" warning for the PySide6 wheel is expected and acceptable.
