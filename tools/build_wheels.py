"""Build the bundled C-extension wheels (pytsk3, tlsh) for the current
Python interpreter and drop them into ../wheels/.

Run this once per Python version on a machine that has the build
toolchain (Windows: VS Build Tools with the 'Desktop development with
C++' workload). The resulting .whl files are checked into the repo so
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
WHEELS_DIR = REPO_ROOT / "wheels"

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
    print("Bundled wheels now in repo:")
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
