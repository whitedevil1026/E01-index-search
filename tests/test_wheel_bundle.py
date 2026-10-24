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
