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
