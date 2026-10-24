"""Build the C-extension wheels (pytsk3, tlsh) for the current Python
interpreter from source and ADD them to that interpreter's bundle.

Output goes into a per-interpreter folder, wheels/py{major}{minor}/
(for example wheels/py312/ when run under Python 3.12), so bundles built
for different Python versions never mix. The installer reads the same
folder for the interpreter it runs under.

This only adds two wheels to an existing bundle; it does not create one.
Populate the folder first with the `pip download` commands in
requirements.txt. Do not let this script's output be the only thing in a
new wheels/py3XX/ folder: the resolver (app/core/wheel_bundle.py) treats
any folder holding a .whl as a full bundle, so a 2-wheel folder would be
offered as the bundle and an offline install would find nothing else.

Needs a C++ compiler: run it on a machine with the build toolchain
(Windows: Microsoft C++ Build Tools with the 'Desktop development with
C++' workload). The resulting .whl files can be checked into the repo so
end users never need to compile anything.

Usage:
    py -3.10 tools/build_wheels.py
    py -3.11 tools/build_wheels.py
    py -3.12 tools/build_wheels.py
    py -3.13 tools/build_wheels.py
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
# Run as a script, sys.path[0] is tools/, not the repo root; add the root
# so the shared bundle layout (app/core/wheel_bundle.py) can be imported.
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.core.wheel_bundle import WHEELS_ROOT  # noqa: E402

WHEELS_DIR = WHEELS_ROOT / f"py{sys.version_info.major}{sys.version_info.minor}"

# Each entry is (display_name, pip-install-spec). The tlsh entry uses
# the upstream Trend Micro repo because the PyPI sdist for python-tlsh
# is broken on Windows (missing Windows/WinFunctions.h header).
TARGETS = [
    ("pytsk3", "pytsk3>=20230125"),
    ("tlsh",   "git+https://github.com/trendmicro/tlsh.git#subdirectory=py_ext"),
]


def main() -> int:
    WHEELS_DIR.mkdir(parents=True, exist_ok=True)
    py_tag = f"cp{sys.version_info.major}{sys.version_info.minor}"
    print(f"Building wheels for Python {sys.version_info.major}."
          f"{sys.version_info.minor}  ({py_tag})")
    print(f"Output: {WHEELS_DIR}")
    print()

    failures: list[str] = []
    for name, spec in TARGETS:
        print(f"=== {name} ===")
        cmd = [sys.executable, "-m", "pip", "wheel", spec,
               "-w", str(WHEELS_DIR), "--no-deps", "--disable-pip-version-check"]
        print("$ " + " ".join(cmd))
        rc = subprocess.call(cmd)
        if rc != 0:
            failures.append(name)
            print(f"  ! {name} failed (exit {rc})")
        print()

    # Show what's in the wheels folder
    print(f"Wheels now in {WHEELS_DIR.name}/:")
    for w in sorted(WHEELS_DIR.glob("*.whl")):
        kb = w.stat().st_size / 1024
        print(f"  {w.name}  ({kb:,.0f} KB)")

    if failures:
        print()
        print(f"FAILED: {failures}")
        print("If the failure mentions Visual C++: install MSVC Build Tools")
        print("(https://visualstudio.microsoft.com/visual-cpp-build-tools/),")
        print("select 'Desktop development with C++', then re-run.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
