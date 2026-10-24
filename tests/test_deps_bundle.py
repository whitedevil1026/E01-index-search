"""The in-app installer's pip specs must be installable from the py312 bundle.

`app/core/deps.py` carries its own pip spec per dependency; the installer
runs `pip install --find-links wheels/py312 <spec>`. If a spec excludes the
version the bundle holds, the offline install of that package fails.
"""
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import (
    canonicalize_name, parse_sdist_filename, parse_wheel_filename,
)

from app.core import deps
from app.core.wheel_bundle import WHEELS_ROOT

REPO_ROOT = Path(__file__).resolve().parent.parent


def _bundle_versions(folder: Path) -> dict[str, list]:
    """canonical distribution name -> versions present in *folder*."""
    out: dict[str, list] = {}
    for p in folder.iterdir():
        if p.name.endswith(".whl"):
            name, ver, _build, _tags = parse_wheel_filename(p.name)
        elif p.name.endswith((".tar.gz", ".zip")):
            name, ver = parse_sdist_filename(p.name)
        else:
            continue
        out.setdefault(canonicalize_name(name), []).append(ver)
    return out


def _specs(dep) -> list[str]:
    return [a for a in dep.pip_args if not a.startswith("-")]


def test_every_required_spec_is_satisfied_by_py312_bundle():
    have = _bundle_versions(WHEELS_ROOT / "py312")
    unsatisfied = []
    for dep in deps.probe_all():
        if getattr(dep, "optional", False):
            continue
        for spec in _specs(dep):
            req = Requirement(spec)
            versions = have.get(canonicalize_name(req.name), [])
            if not any(req.specifier.contains(v, prereleases=True) for v in versions):
                unsatisfied.append(f"{spec} (bundle has {[str(v) for v in versions]})")
    assert not unsatisfied, "not installable from wheels/py312: " + "; ".join(unsatisfied)


def _requirements_txt() -> dict[str, Requirement]:
    out = {}
    for line in (REPO_ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            req = Requirement(line)
            out[canonicalize_name(req.name)] = req
    return out


def test_deps_specs_match_requirements_txt():
    reqs = _requirements_txt()
    drift = []
    for dep in deps.probe_all():
        for spec in _specs(dep):
            req = Requirement(spec)
            want = reqs.get(canonicalize_name(req.name))
            if want is not None and want.specifier != req.specifier:
                drift.append(f"deps.py {spec!r} vs requirements.txt {str(want)!r}")
    assert not drift, "; ".join(drift)


def _tlsh():
    return next(d for d in deps.probe_all() if d.module_name == "tlsh")


def test_tlsh_is_optional_and_named_py_tlsh():
    dep = _tlsh()
    assert dep.optional is True
    assert [canonicalize_name(Requirement(s).name) for s in _specs(dep)] == ["py-tlsh"]


def test_c_ext_note_honest_when_bundle_lacks_package(tmp_path):
    (tmp_path / "py312").mkdir()
    (tmp_path / "py312" / "pytsk3-20260715-cp312-cp312-win_amd64.whl").write_bytes(b"")
    note = deps._c_ext_note((3, 12), tmp_path, dist="py-tlsh")
    assert "Bundled wheel available" not in note
    assert "3.12" in note and "Build Tools" in note and "optional" in note.lower()
    # A package the bundle does hold still gets the bundled-wheel note.
    assert "wheels/py312" in deps._c_ext_note((3, 12), tmp_path, dist="pytsk3")
    assert "Bundled wheel available" in deps._c_ext_note((3, 12), tmp_path, dist="pytsk3")
