# Offline wheel bundles

One folder per Python interpreter. The in-app installer picks
`wheels/py{major}{minor}/` for the interpreter it runs under and passes it to
pip with `--find-links` only: pip prefers the bundled files but may still reach
PyPI for anything the bundle lacks. For a strictly offline install, run pip
yourself with `--no-index` (see `requirements.txt` and the main `README.md`).

## py312 — current

The bundle for Python 3.12. It installs fully offline with `--no-index` and
needs no compiler. It mixes cp312 wheels, abi3 wheels and pure-Python
(`py3-none-any`) wheels.

It has no TLSH: `py-tlsh` publishes no cp312 wheel, so fuzzy-hash matching is
unavailable on 3.12 unless you build `py-tlsh` from source with Microsoft C++
Build Tools. TLSH is optional; nothing else is lost.

Do not prune these files — they look out of place but the offline install
needs them:

- `red-black-tree-mod-1.22.tar.gz` and `win_unicode_console-0.5.zip` are
  source packages. They are dependencies in extract-msg's tree
  (`red-black-tree-mod` of extract-msg itself, `win_unicode_console` of
  pcodedmp) that publish no wheel at all; both are pure Python, so no compiler
  is needed.
- `setuptools-*.whl` and `wheel-*.whl` are what pip uses to build those two
  source packages. With `--no-index` pip cannot fetch them, so without them
  the offline install fails.

The rebuild commands are in `requirements.txt`; they are not repeated here.

## py310 — LEGACY

The bundle for Python 3.10. Python 3.10 reaches end of life on 31 October 2026,
so treat this folder as legacy. It is kept because
`python_tlsh-4.5.0-cp310-cp310-win_amd64.whl` is the only prebuilt TLSH binary
available.

It is **not** a complete `--no-index` bundle for the current
`requirements.txt`. It holds older versions (cryptography 48.0.1, tantivy
0.25.1, libewf-python 20240506, ...) and lacks psutil, setuptools and wheel.
It pairs with the pre-migration requirements and dependency list:

    git show e4c090a^:requirements.txt
    git show e4c090a^:app/core/deps.py

The in-app installer uses the current pins, so on Python 3.10 it will not find
matching versions in this folder (its TLSH wheel is also published as
`python-tlsh`, not the `py-tlsh` name the installer now asks for).

## Refreshing a bundle

Refresh rarely, and refresh a whole bundle at once: empty the folder, then run
the `pip download` commands from `requirements.txt` so old and new versions do
not pile up side by side. Then re-run the offline `--no-index` install in a
fresh venv and the test suite before committing.

Every refresh adds its files to git history permanently — deleting them later
does not shrink the repository. One PySide6 bump alone is about 78 MB.
