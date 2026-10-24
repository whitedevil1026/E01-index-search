import importlib.util
import sys
from pathlib import Path

from app.core.wheel_bundle import WHEELS_ROOT


def test_build_output_is_per_interpreter():
    path = Path(__file__).resolve().parent.parent / "tools" / "build_wheels.py"
    spec = importlib.util.spec_from_file_location("build_wheels", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    v = sys.version_info
    assert mod.WHEELS_DIR == WHEELS_ROOT / f"py{v.major}{v.minor}"
