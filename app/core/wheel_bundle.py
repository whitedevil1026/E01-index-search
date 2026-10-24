"""Pick the offline wheel bundle that matches the running interpreter.

A compiled wheel (PySide6, pyewf, ...) is tagged for one CPython minor
version, so a folder of wheels built for 3.10 is useless to a 3.12
interpreter. Bundles therefore live one-per-version under ``wheels/``
(``wheels/py310``, ``wheels/py312``) and the installer asks this module
which one belongs to the interpreter it is running under.

Standard library only: this runs before any third-party dependency is
installed, so it must not import anything that is not already there.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

WHEELS_ROOT: Path = Path(__file__).resolve().parent.parent.parent / "wheels"

# Versions whose bundle is kept only for older installs, not the current target.
LEGACY_VERSIONS: frozenset[tuple[int, int]] = frozenset({(3, 10)})


def bundle_folder_name(version: tuple[int, int] | None = None) -> str:
    """Bundle folder name for *version* (default: running interpreter), e.g. ``py312``."""
    major, minor = version if version is not None else sys.version_info[:2]
    return f"py{major}{minor}"


def _resolve(version: tuple[int, int] | None, root: Path | None) -> Path:
    return (root if root is not None else WHEELS_ROOT) / bundle_folder_name(version)


def bundle_wheel_names(
    version: tuple[int, int] | None = None, root: Path | None = None
) -> list[str]:
    """Sorted ``.whl`` file names in the bundle for *version*; ``[]`` if none."""
    folder = _resolve(version, root)
    if not folder.is_dir():
        return []
    return sorted(p.name for p in folder.glob("*.whl") if p.is_file())


def bundle_dir_for(
    version: tuple[int, int] | None = None, root: Path | None = None
) -> Path | None:
    """The bundle folder for *version*, or ``None`` if it holds no wheels."""
    if not bundle_wheel_names(version, root):
        return None
    return _resolve(version, root)


def is_legacy(version: tuple[int, int]) -> bool:
    """True if *version* is a legacy interpreter whose bundle is kept for compatibility."""
    return tuple(version) in LEGACY_VERSIONS


_SDIST_SUFFIXES = (".tar.gz", ".zip")


def _canonical(name: str) -> str:
    """PEP 503 normalised distribution name (same rule as ``packaging``)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _dist_name(filename: str) -> str | None:
    """Canonical distribution name of a wheel or sdist file name, else ``None``.

    A wheel name never contains ``-`` inside the distribution part, so it is
    everything before the first ``-``. An sdist may (``red-black-tree-mod-1.22``),
    so it is everything before the last ``-``.
    """
    if filename.endswith(".whl"):
        return _canonical(filename.split("-", 1)[0])
    for suffix in _SDIST_SUFFIXES:
        if filename.endswith(suffix):
            stem = filename[: -len(suffix)]
            if "-" not in stem:
                return None
            return _canonical(stem.rsplit("-", 1)[0])
    return None


def bundle_has(
    dist_name: str, version: tuple[int, int] | None = None, root: Path | None = None
) -> bool:
    """True if the bundle for interpreter *version* holds a wheel or sdist of *dist_name*.

    Names are compared PEP 503-normalised, so ``libewf-python`` matches
    ``libewf_python-...whl``. *version* is the interpreter (``(3, 12)``), not
    the package version; it defaults to the running interpreter.
    """
    folder = _resolve(version, root)
    if not folder.is_dir():
        return False
    want = _canonical(dist_name)
    return any(
        p.is_file() and _dist_name(p.name) == want for p in folder.iterdir()
    )
