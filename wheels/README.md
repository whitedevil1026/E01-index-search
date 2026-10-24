# Offline wheel bundles

One folder per Python interpreter. The installer picks `wheels/py{major}{minor}/`
for the interpreter it runs under, and installs from it with `--no-index`.

## py312 — current

The bundle for Python 3.12. It installs fully offline and needs no compiler.
It has no TLSH: `py-tlsh` publishes no cp312 wheel, so fuzzy-hash matching is
unavailable on 3.12. The rebuild commands are in `requirements.txt`; they are
not repeated here.

## py310 — LEGACY

The bundle for Python 3.10. Python 3.10 reaches end of life on 31 October 2026,
so treat this folder as legacy. It is kept because
`python_tlsh-4.5.0-cp310-cp310-win_amd64.whl` is the only prebuilt TLSH binary
available.
