"""Ed25519-signed reproducibility manifest.

Per the May 2026 review: we do not promise bit-identical index bytes
across runs. We promise a manifest of (inputs, versions, options,
output hashes) signed with Ed25519 — that's the level of reproducibility
the user's accreditation regime can audit.
"""
from __future__ import annotations

import hashlib
import json
import platform
import sys
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization


def ensure_keypair(keys_dir: Path) -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    keys_dir.mkdir(parents=True, exist_ok=True)
    priv_path = keys_dir / "case_ed25519.key"
    pub_path = keys_dir / "case_ed25519.pub"
    if priv_path.exists():
        priv_bytes = priv_path.read_bytes()
        priv = serialization.load_pem_private_key(priv_bytes, password=None)
        assert isinstance(priv, Ed25519PrivateKey)
        return priv, priv.public_key()
    priv = Ed25519PrivateKey.generate()
    priv_path.write_bytes(priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    pub_path.write_bytes(priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    return priv, priv.public_key()


def _hash_file(path: Path, limit: int = 64 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    n = 0
    with open(path, "rb") as f:
        while n < limit:
            chunk = f.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
            n += len(chunk)
    return h.hexdigest()


def build_manifest(case_root: Path, deps_summary: dict[str, str]) -> dict[str, Any]:
    """Walk the case dir and produce a manifest dict (not yet signed)."""
    case_root = Path(case_root)
    files: list[dict] = []
    for p in sorted(case_root.rglob("*")):
        if not p.is_file():
            continue
        if p.name in ("manifest.json", "manifest.sig"):
            continue  # excluded — would create a chicken/egg
        try:
            rel = p.relative_to(case_root).as_posix()
            files.append({
                "path": rel,
                "size": p.stat().st_size,
                "sha256": _hash_file(p),
            })
        except Exception as exc:  # noqa: BLE001
            files.append({"path": str(p), "error": str(exc)})

    return {
        "manifest_version": 1,
        "generated_at": time.time(),
        "platform": {
            "python": sys.version,
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "deps": deps_summary,
        "files": files,
    }


def sign_manifest(case_root: Path, manifest: dict[str, Any],
                  priv: Ed25519PrivateKey) -> tuple[Path, Path]:
    case_root = Path(case_root)
    mpath = case_root / "manifest.json"
    spath = case_root / "manifest.sig"
    canon = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig = priv.sign(canon)
    mpath.write_bytes(canon)
    spath.write_bytes(sig)
    return mpath, spath


def verify_manifest(case_root: Path, pub: Ed25519PublicKey) -> bool:
    case_root = Path(case_root)
    canon = (case_root / "manifest.json").read_bytes()
    sig = (case_root / "manifest.sig").read_bytes()
    try:
        pub.verify(sig, canon)
        return True
    except Exception:
        return False
