"""IoC / artifact pattern extraction.

Pure-Python regex extraction of the high-value indicators a raw scan
should surface — the same artifact classes bulk_extractor's scanners
target, without needing the (Windows-unbuildable) bulk_extractor
binary.

Patterns covered:
    email          RFC-ish addresses
    url            http/https/ftp URLs
    ipv4           dotted-quad, octet-range validated
    ipv6           compressed and full forms
    domain         bare hostnames
    cc             credit-card numbers, Luhn-validated
    btc            Bitcoin addresses (legacy P2PKH/P2SH + bech32)
    phone          international / NANP phone numbers
    mac            MAC addresses
    onion          Tor v3 .onion addresses

Every match is returned with its byte offset so an examiner can pivot
back to the exact location in the image.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable


# ---- compiled patterns ----------------------------------------------------

_RE = {
    "email": re.compile(
        rb"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}"),
    "url": re.compile(
        rb"(?:https?|ftp)://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+"),
    "ipv4": re.compile(
        rb"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
        rb"(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])"),
    "ipv6": re.compile(
        rb"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}"
        rb"(?![0-9A-Fa-f:])"),
    "domain": re.compile(
        rb"(?<![A-Za-z0-9.\-])(?:[A-Za-z0-9\-]{1,63}\.)+"
        rb"(?:com|net|org|info|biz|gov|edu|mil|io|co|ru|cn|uk|de|fr|jp|"
        rb"in|us|xyz|top|onion|live|app|dev|me)(?![A-Za-z0-9.\-])"),
    # linear (no nested quantifiers) — a digit-led/ended run of digits
    # and separators; Luhn validation downstream rejects non-cards
    "cc": re.compile(
        rb"(?<![\dA-Za-z])\d[\d \-]{11,21}\d(?![\dA-Za-z])"),
    "btc": re.compile(
        rb"(?<![A-Za-z0-9])(?:[13][A-HJ-NP-Za-km-z1-9]{25,34}"
        rb"|bc1[a-z0-9]{11,71})(?![A-Za-z0-9])"),
    # linear — optional +, then a digit-led/ended run of digits and
    # phone separators. Dots are deliberately excluded: version strings
    # like 6.1.7600.16385 would otherwise match. Validation downstream.
    "phone": re.compile(
        rb"(?<![\dA-Za-z+.])\+?\d[\d \-()]{6,16}\d(?![\dA-Za-z.])"),
    "mac": re.compile(
        rb"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"
        rb"(?![0-9A-Fa-f:])"),
    "onion": re.compile(
        rb"(?<![a-z2-7])[a-z2-7]{56}\.onion(?![a-z2-7])"),
}

# Order patterns are scanned in. Broad patterns last.
_PATTERN_ORDER = ("email", "url", "btc", "onion", "mac", "ipv6",
                  "ipv4", "cc", "phone", "domain")

PATTERN_TYPES = tuple(_PATTERN_ORDER)


@dataclass
class PatternHit:
    kind: str
    value: str
    offset: int          # byte offset of the match start

    def as_tuple(self):
        return (self.kind, self.value, self.offset)


@dataclass
class PatternStats:
    total: int = 0
    per_kind: dict = field(default_factory=dict)

    def add(self, kind: str, n: int = 1):
        self.total += n
        self.per_kind[kind] = self.per_kind.get(kind, 0) + n


# ---- validation helpers ---------------------------------------------------

def _luhn_ok(digits: str) -> bool:
    """Luhn checksum — filters most false-positive credit-card hits."""
    digits = re.sub(r"\D", "", digits)
    if not (13 <= len(digits) <= 19):
        return False
    total = 0
    parity = len(digits) % 2
    for i, ch in enumerate(digits):
        d = ord(ch) - 48
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _plausible_phone(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if not (7 <= len(digits) <= 15):
        return False
    # reject all-identical digit runs (00000000, 11111111, …)
    if len(set(digits)) <= 1:
        return False
    # reject leading-zero runs (0000xxxx) — binary integer padding,
    # not a phone number
    if digits.startswith("0000"):
        return False
    return True


# ---- scanning -------------------------------------------------------------

def scan_bytes(data: bytes, base_offset: int = 0,
               kinds: Iterable[str] = PATTERN_TYPES,
               max_per_kind: int = 0) -> list[PatternHit]:
    """Scan a byte buffer for all requested pattern kinds.

    base_offset is added to every match offset so callers scanning a
    page get absolute image offsets. max_per_kind > 0 caps the number
    of hits kept per kind (0 = unlimited).
    """
    kinds = set(kinds)
    hits: list[PatternHit] = []
    counts: dict[str, int] = {}
    for kind in _PATTERN_ORDER:
        if kind not in kinds:
            continue
        rx = _RE[kind]
        for m in rx.finditer(data):
            raw = m.group()
            try:
                value = raw.decode("ascii", errors="replace")
            except Exception:  # noqa: BLE001
                continue
            # type-specific validation
            if kind == "cc" and not _luhn_ok(value):
                continue
            if kind == "phone" and not _plausible_phone(value):
                continue
            if kind == "email" and value.count("@") != 1:
                continue
            c = counts.get(kind, 0)
            if max_per_kind and c >= max_per_kind:
                break
            counts[kind] = c + 1
            hits.append(PatternHit(kind, value, base_offset + m.start()))
    return hits


def scan_text(text: str, kinds: Iterable[str] = PATTERN_TYPES) -> list[PatternHit]:
    """Convenience wrapper to scan an already-decoded string."""
    return scan_bytes(text.encode("utf-8", errors="replace"), 0, kinds)


def summarize(hits: list[PatternHit]) -> PatternStats:
    stats = PatternStats()
    for h in hits:
        stats.add(h.kind)
    return stats
