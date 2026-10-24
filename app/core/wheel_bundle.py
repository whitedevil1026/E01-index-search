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

import sys
from pathlib import Path

WHEELS_ROOT: Path = Path(__file__).resolve().parent.parent.parent / "wheels"

# Versions whose bundle is kept only for older installs, not the current target.
LEGACY_VERSIONS: frozenset[tuple[int, int]] = frozenset({(3, 10)})


def _resolve(version: tuple[int, int] | None, root: Path | None) -> Path:
    major, minor = version if version is not None else sys.version_info[:2]
    return (root if root is not None else WHEELS_ROOT) / f"py{major}{minor}"


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
