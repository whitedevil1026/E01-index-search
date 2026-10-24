"""Import-time dependency probing.

Each forensic library is optional at import time. Missing libs degrade
features gracefully and the Deps Status panel tells the user exactly
what to pip install.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from app.core.wheel_bundle import (
    bundle_dir_for, bundle_folder_name, bundle_has, is_legacy,
)


@dataclass
class Dep:
    name: str
    module_name: str
    installed: bool
    version: Optional[str]
    purpose: str
    pip_args: list[str]            # arguments to pass to `pip install`
    install_hint: str              # copy-paste shell command
    notes: str = ""                # extra guidance shown in the UI
    module: Any = None
    optional: bool = False         # True: commented out of requirements.txt;
                                   # the tool runs fully without it


def _probe(module_name: str, purpose: str, pip_args: list[str],
           friendly: str | None = None, notes: str = "",
           optional: bool = False) -> Dep:
    friendly = friendly or module_name
    install_hint = "pip install " + " ".join(f'"{a}"' if any(c in a for c in "<>= ") else a
                                             for a in pip_args)
    try:
        mod = __import__(module_name)
        ver = getattr(mod, "__version__", None) or getattr(mod, "VERSION", None) or "installed"
        return Dep(friendly, module_name, True, str(ver), purpose,
                   pip_args, install_hint, notes, mod, optional)
    except Exception as exc:  # noqa: BLE001
        return Dep(friendly, module_name, False, f"not installed ({exc.__class__.__name__})",
                   purpose, pip_args, install_hint, notes, None, optional)


_MSVC_URL = "https://visualstudio.microsoft.com/visual-cpp-build-tools/"

# What is lost when a C-extension package is absent (keyed by pip name).
_FEATURE_LOST = {
    "py-tlsh": "TLSH fuzzy-similarity search",
    "pytsk3": "Sleuth Kit filesystem walking (the libfs* direct readers remain)",
}


# Note for the C-extension packages (`pytsk3`, `py-tlsh`).
# Pre-built wheels ship one folder per Python version under `wheels/`
# (see app/core/wheel_bundle.py), so the typical user installs from the
# bundle with no compiler. The MSVC fallback matters for a Python version
# we haven't pre-built for, and for a package the bundle does not carry
# (the py312 bundle has no TLSH: py-tlsh publishes no cp312 wheel).
def _c_ext_note(version: tuple[int, int] | None = None,
                root: Path | None = None, *, dist: str | None = None) -> str:
    major, minor = version if version is not None else sys.version_info[:2]
    has_bundle = bundle_dir_for((major, minor), root) is not None
    if has_bundle and dist is not None and not bundle_has(dist, (major, minor), root):
        feature = _FEATURE_LOST.get(dist, "the features that use it")
        return (
            f"No bundled wheel for {dist} on Python {major}.{minor} "
            f"(wheels/py{major}{minor}/ does not include it). Installing it "
            "builds from source, which needs Microsoft C++ Build Tools "
            f"({_MSVC_URL}). Optional - only {feature} is lost without it."
        )
    if has_bundle:
        note = (
            f"Bundled wheel available in wheels/py{major}{minor}/ - installs "
            "offline, no compiler needed. Click 'Install Missing' to use it."
        )
        if is_legacy((major, minor)):
            note += (
                " This is a legacy bundle - Python 3.10 reaches end of life "
                "on 31 October 2026; move to the current Python when you can."
            )
        return note
    return (
        f"No bundled wheel for Python {major}.{minor}. Either use a Python "
        "version that has a bundle in wheels/, or install Microsoft C++ Build "
        f"Tools ({_MSVC_URL}) "
        "and pip will compile from source. requirements.txt lists the "
        "commands to rebuild a bundle. Optional - features degrade gracefully."
    )


def probe_all() -> list[Dep]:
    # Pip specs match requirements.txt exactly; tests/test_deps_bundle.py
    # pins that, and that every non-optional spec installs from wheels/py312.
    return [
        _probe("PySide6", "Desktop GUI framework", ["PySide6-Essentials>=6.8,<7"]),
        _probe("cryptography",
               "Ed25519 manifest signing + AES-GCM at-rest",
               ["cryptography>=50,<51"]),
        _probe("tantivy", "Primary search index (Rust, Lucene-class)",
               ["tantivy>=0.26,<0.27"]),
        _probe("charset_normalizer",
               "File-level encoding detection (MIT)",
               ["charset-normalizer>=3.4,<4"],
               friendly="charset-normalizer"),
        _probe("tlsh", "TLSH fuzzy similarity hash (optional)",
               ["py-tlsh>=4.5"], friendly="py-tlsh",
               notes=_c_ext_note(dist="py-tlsh"), optional=True),
        _probe("pyewf", "E01/Ex01 image reader (libewf-python)",
               ["libewf-python>=20260924"],
               friendly="libewf-python"),
        _probe("pytsk3", "Sleuth Kit filesystem walker",
               ["pytsk3>=20260715"],
               notes=_c_ext_note(dist="pytsk3")),
        _probe("pyvshadow", "Volume Shadow Copy (VSS) snapshots",
               ["libvshadow-python>=20260714"], friendly="libvshadow-python",
               notes="Phase 1 — bundled wheel; prebuilt on PyPI too."),
        _probe("pybde", "BitLocker volume decryption",
               ["libbde-python>=20260916"], friendly="libbde-python",
               notes="Phase 1 — bundled wheel; prebuilt on PyPI too."),
        _probe("pyfvde", "FileVault 2 volume decryption",
               ["libfvde-python>=20260923"], friendly="libfvde-python",
               notes="Phase 1 — bundled wheel; prebuilt on PyPI too."),
        _probe("pyluksde", "LUKS volume decryption",
               ["libluksde-python>=20260902"], friendly="libluksde-python",
               notes="Phase 1 — bundled wheel; prebuilt on PyPI too."),
        _probe("pyfsntfs", "Direct NTFS reader (TSK fallback)",
               ["libfsntfs-python>=20260827"], friendly="libfsntfs-python",
               notes="Phase 1 — bundled wheel; prebuilt on PyPI too."),
        _probe("pyfsapfs", "Direct APFS reader (TSK fallback)",
               ["libfsapfs-python>=20260921"], friendly="libfsapfs-python",
               notes="Phase 1 — bundled wheel; prebuilt on PyPI too."),
        _probe("fitz", "PDF text extraction (PyMuPDF)",
               ["pymupdf>=1.24"], friendly="PyMuPDF"),
        _probe("extract_msg", "Outlook .msg parser",
               ["extract-msg>=0.54,<0.56"], friendly="extract-msg"),
        _probe("yara_x", "YARA-X IoC scanning",
               ["yara-x>=1.21"], friendly="YARA-X"),
        _probe("pypff", "Outlook PST/OST mail-store parser",
               ["libpff-python>=20260926"], friendly="libpff-python",
               notes=f"Phase 4 — bundled wheel in wheels/{bundle_folder_name()}/; "
                     "prebuilt on PyPI too."),
        _probe("pyregf", "Windows Registry hive parser",
               ["libregf-python>=20260526"], friendly="libregf-python",
               notes="Phase 4 — bundled wheel; prebuilt on PyPI too."),
        _probe("pyesedb", "ESE database parser (Edge/SRUM/Search)",
               ["libesedb-python>=20260704"], friendly="libesedb-python",
               notes="Phase 4 — bundled wheel; prebuilt on PyPI too."),
    ]


def missing() -> list[Dep]:
    return [d for d in probe_all() if not d.installed]


def summary() -> dict[str, bool]:
    return {d.name: d.installed for d in probe_all()}
