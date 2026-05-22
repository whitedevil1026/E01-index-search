"""Import-time dependency probing.

Each forensic library is optional at import time. Missing libs degrade
features gracefully and the Deps Status panel tells the user exactly
what to pip install.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


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


def _probe(module_name: str, purpose: str, pip_args: list[str],
           friendly: str | None = None, notes: str = "") -> Dep:
    friendly = friendly or module_name
    install_hint = "pip install " + " ".join(f'"{a}"' if any(c in a for c in "<>= ") else a
                                             for a in pip_args)
    try:
        mod = __import__(module_name)
        ver = getattr(mod, "__version__", None) or getattr(mod, "VERSION", None) or "installed"
        return Dep(friendly, module_name, True, str(ver), purpose,
                   pip_args, install_hint, notes, mod)
    except Exception as exc:  # noqa: BLE001
        return Dep(friendly, module_name, False, f"not installed ({exc.__class__.__name__})",
                   purpose, pip_args, install_hint, notes, None)


# Note for the C-extension packages (`pytsk3`, `python-tlsh`).
# We ship pre-built wheels for Python 3.10/win_amd64 in `try1/wheels/`,
# so the typical user installs them from the bundle with no compiler.
# The MSVC fallback only matters if a user runs a Python version we
# haven't pre-built for.
def _bundled_wheels_exist() -> bool:
    from pathlib import Path
    here = Path(__file__).resolve().parent.parent.parent / "wheels"
    return here.is_dir() and any(here.glob("*.whl"))


_BUNDLED_NOTE = (
    "Bundled wheel available in ./wheels/ — installs offline, no compiler "
    "needed. Click 'Install Missing' to use it."
)
_MSVC_NOTE = (
    "No bundled wheel for your Python version. Either (a) switch to Python "
    "3.10 to use the bundled wheel, or (b) install Microsoft C++ Build Tools "
    "(https://visualstudio.microsoft.com/visual-cpp-build-tools/) and pip "
    "will compile from source. Optional — features degrade gracefully."
)


def _c_ext_note() -> str:
    return _BUNDLED_NOTE if _bundled_wheels_exist() else _MSVC_NOTE


def probe_all() -> list[Dep]:
    return [
        _probe("PySide6", "Desktop GUI framework", ["PySide6>=6.6,<7"]),
        _probe("cryptography",
               "Ed25519 manifest signing + AES-GCM at-rest",
               ["cryptography>=42"]),
        _probe("tantivy", "Primary search index (Rust, Lucene-class)",
               ["tantivy>=0.22,<0.26"]),
        _probe("charset_normalizer",
               "File-level encoding detection (MIT)",
               ["charset-normalizer>=3.4,<4"],
               friendly="charset-normalizer"),
        _probe("tlsh", "TLSH fuzzy similarity hash",
               ["python-tlsh"],
               notes=_c_ext_note()),
        _probe("pyewf", "E01/Ex01 image reader (libewf-python)",
               ["libewf-python==20240506"],
               friendly="libewf-python"),
        _probe("pytsk3", "Sleuth Kit filesystem walker",
               ["pytsk3>=20230125"],
               notes=_c_ext_note()),
        _probe("pyvshadow", "Volume Shadow Copy (VSS) snapshots",
               ["libvshadow-python>=20240504"], friendly="libvshadow-python",
               notes="Phase 1 — bundled wheel; prebuilt on PyPI too."),
        _probe("pybde", "BitLocker volume decryption",
               ["libbde-python>=20240502"], friendly="libbde-python",
               notes="Phase 1 — bundled wheel; prebuilt on PyPI too."),
        _probe("pyfvde", "FileVault 2 volume decryption",
               ["libfvde-python>=20240502"], friendly="libfvde-python",
               notes="Phase 1 — bundled wheel; prebuilt on PyPI too."),
        _probe("pyluksde", "LUKS volume decryption",
               ["libluksde-python>=20240503"], friendly="libluksde-python",
               notes="Phase 1 — bundled wheel; prebuilt on PyPI too."),
        _probe("pyfsntfs", "Direct NTFS reader (TSK fallback)",
               ["libfsntfs-python>=20240501"], friendly="libfsntfs-python",
               notes="Phase 1 — bundled wheel; prebuilt on PyPI too."),
        _probe("pyfsapfs", "Direct APFS reader (TSK fallback)",
               ["libfsapfs-python>=20240429"], friendly="libfsapfs-python",
               notes="Phase 1 — bundled wheel; prebuilt on PyPI too."),
        _probe("fitz", "PDF text extraction (PyMuPDF)",
               ["pymupdf"], friendly="PyMuPDF"),
        _probe("extract_msg", "Outlook .msg parser",
               ["extract-msg"], friendly="extract-msg"),
        _probe("yara_x", "YARA-X IoC scanning",
               ["yara-x"], friendly="YARA-X"),
        _probe("pypff", "Outlook PST/OST mail-store parser",
               ["libpff-python"], friendly="libpff-python",
               notes="Phase 4 — bundled wheel in ./wheels/."),
        _probe("pyregf", "Windows Registry hive parser",
               ["libregf-python>=20240421"], friendly="libregf-python",
               notes="Phase 4 — bundled wheel; prebuilt on PyPI too."),
        _probe("pyesedb", "ESE database parser (Edge/SRUM/Search)",
               ["libesedb-python>=20240420"], friendly="libesedb-python",
               notes="Phase 4 — bundled wheel; prebuilt on PyPI too."),
    ]


def missing() -> list[Dep]:
    return [d for d in probe_all() if not d.installed]


def summary() -> dict[str, bool]:
    return {d.name: d.installed for d in probe_all()}
