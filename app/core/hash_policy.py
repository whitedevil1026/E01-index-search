"""Per-case hash algorithm policy.

The examiner picks which hashes to compute on case create:

  Primary  — MD5 (default), SHA-1, SHA-256, SHA-512, or BLAKE2b
  Extras   — any zero-or-more of the others

The policy is persisted in the case database (kv table) so every later
ingest, every integrity export, and every audit-log entry uses the same
set of digests for the lifetime of the case.

Why a policy and not "always compute everything"?
- MD5 is required by NSRL and most evidence SOPs but cryptographically dead.
- SHA-256 is the modern courtroom default.
- BLAKE2b is faster than SHA-256 on large evidence on commodity CPUs.
- Computing all five on a 4 TB image is unnecessarily slow if only one is
  required by the receiving agency.

TLSH is *not* in this policy because it's a fuzzy hash with different
semantics (similarity, not identity). It stays in its own column.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import BinaryIO, Iterable


SUPPORTED_ALGOS: tuple[str, ...] = ("md5", "sha1", "sha256", "sha512", "blake2b")

DEFAULT_PRIMARY = "sha256"
DEFAULT_EXTRAS: tuple[str, ...] = ("md5",)   # MD5 retained for NSRL backwards-compat


@dataclass
class HashPolicy:
    primary: str = DEFAULT_PRIMARY
    extras: list[str] = field(default_factory=lambda: list(DEFAULT_EXTRAS))

    # ---- query helpers --------------------------------------------------

    def all_algos(self) -> list[str]:
        seen: list[str] = []
        for a in [self.primary, *self.extras]:
            if a not in seen and a in SUPPORTED_ALGOS:
                seen.append(a)
        return seen

    def describe(self) -> str:
        extras = ", ".join(self.extras) if self.extras else "(none)"
        return f"primary={self.primary.upper()}  extras={extras}"

    # ---- serialization --------------------------------------------------

    def to_json(self) -> str:
        return json.dumps({"primary": self.primary, "extras": self.extras},
                          sort_keys=True)

    @classmethod
    def from_json(cls, s: str | None) -> "HashPolicy":
        if not s:
            return cls()
        try:
            d = json.loads(s)
            primary = str(d.get("primary") or DEFAULT_PRIMARY).lower()
            extras = [str(x).lower() for x in d.get("extras") or []
                      if str(x).lower() in SUPPORTED_ALGOS and str(x).lower() != primary]
            if primary not in SUPPORTED_ALGOS:
                primary = DEFAULT_PRIMARY
            return cls(primary=primary, extras=extras)
        except Exception:
            return cls()

    # ---- validation -----------------------------------------------------

    def normalized(self) -> "HashPolicy":
        primary = self.primary.lower()
        if primary not in SUPPORTED_ALGOS:
            primary = DEFAULT_PRIMARY
        extras = []
        for e in self.extras:
            ex = e.lower()
            if ex in SUPPORTED_ALGOS and ex != primary and ex not in extras:
                extras.append(ex)
        return HashPolicy(primary=primary, extras=extras)


# ---- hashing engine -------------------------------------------------------

def _new_hasher(algo: str):
    algo = algo.lower()
    if algo == "blake2b":
        return hashlib.blake2b()
    return hashlib.new(algo)


def hash_stream_with_policy(stream: BinaryIO, policy: HashPolicy,
                            chunk: int = 1 << 20) -> dict[str, object]:
    """Compute every algorithm in `policy` in a single pass. Returns a dict
    with one key per algorithm, plus 'size_bytes'.
    """
    hashers = {a: _new_hasher(a) for a in policy.all_algos()}
    size = 0
    while True:
        buf = stream.read(chunk)
        if not buf:
            break
        size += len(buf)
        for h in hashers.values():
            h.update(buf)
    out: dict[str, object] = {a: h.hexdigest() for a, h in hashers.items()}
    out["size_bytes"] = size
    return out


def hash_path_with_policy(path: str, policy: HashPolicy) -> dict[str, object]:
    with open(path, "rb") as fh:
        return hash_stream_with_policy(fh, policy)
