"""YARA-X rule scanning.

Wraps the yara-x Python binding (VirusTotal's Rust rewrite of YARA;
YARA proper went into maintenance mode in 2025, so YARA-X is the
current engine). Used to scan carved files, extracted documents and
raw image pages against IoC / malware / sensitive-data rule sets.

The module ships a small built-in rule pack covering generic
indicators so the feature is useful out of the box; the examiner can
also load their own .yar / .yara files.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

try:
    import yara_x
    HAS_YARA_X = True
except Exception:  # noqa: BLE001
    HAS_YARA_X = False


# A compact starter rule pack. Deliberately conservative — broad
# enough to be useful, specific enough to avoid drowning the examiner.
BUILTIN_RULES = r"""
rule Contains_Private_Key {
    meta:
        description = "PEM private key block"
        category = "credentials"
    strings:
        $a = "-----BEGIN RSA PRIVATE KEY-----"
        $b = "-----BEGIN PRIVATE KEY-----"
        $c = "-----BEGIN OPENSSH PRIVATE KEY-----"
        $d = "-----BEGIN EC PRIVATE KEY-----"
    condition:
        any of them
}

rule Contains_AWS_Key {
    meta:
        description = "AWS access key id"
        category = "credentials"
    strings:
        $a = /AKIA[0-9A-Z]{16}/
    condition:
        $a
}

rule Windows_PE_Executable {
    meta:
        description = "Windows PE executable"
        category = "executable"
    strings:
        $mz = { 4D 5A }
    condition:
        $mz at 0 and uint32(uint32(0x3C)) == 0x00004550
}

rule ELF_Executable {
    meta:
        description = "ELF executable"
        category = "executable"
    strings:
        $elf = { 7F 45 4C 46 }
    condition:
        $elf at 0
}

rule Bitcoin_Wallet_Strings {
    meta:
        description = "Bitcoin wallet / blockchain references"
        category = "cryptocurrency"
    strings:
        $a = "wallet.dat" nocase
        $b = "bitcoin" nocase
        $c = "blockchain" nocase
    condition:
        2 of them
}

rule Email_Credentials_Config {
    meta:
        description = "SMTP / IMAP credentials in config"
        category = "credentials"
    strings:
        $a = "smtp_password" nocase
        $b = "imap_password" nocase
        $c = "mail_password" nocase
    condition:
        any of them
}

rule Browser_Saved_Passwords {
    meta:
        description = "Browser password store artefacts"
        category = "credentials"
    strings:
        $a = "Login Data" nocase
        $b = "moz_logins"
        $c = "encryptedUsername"
    condition:
        any of them
}
"""


@dataclass
class YaraMatch:
    rule: str
    namespace: str
    tags: list = field(default_factory=list)
    meta: dict = field(default_factory=dict)
    source: str = ""        # file path / region the match came from


@dataclass
class YaraScanStats:
    scanned: int = 0
    matched: int = 0
    per_rule: dict = field(default_factory=dict)

    def add(self, rule: str):
        self.matched += 1
        self.per_rule[rule] = self.per_rule.get(rule, 0) + 1


class YaraScanner:
    """Compiled YARA-X rules ready to scan buffers and files."""

    def __init__(self, rules_text: str = BUILTIN_RULES):
        if not HAS_YARA_X:
            raise RuntimeError("yara-x is not installed")
        self._rules = yara_x.compile(rules_text)
        self._scanner = yara_x.Scanner(self._rules)

    @classmethod
    def from_files(cls, paths: list[str], include_builtin: bool = True
                   ) -> "YaraScanner":
        """Compile rules from one or more .yar / .yara files."""
        chunks = [BUILTIN_RULES] if include_builtin else []
        for p in paths:
            try:
                with open(p, "r", encoding="utf-8", errors="replace") as fh:
                    chunks.append(fh.read())
            except Exception as exc:  # noqa: BLE001
                raise RuntimeError(f"could not read rule file {p}: {exc}")
        return cls("\n\n".join(chunks))

    # ---- scanning ------------------------------------------------------

    def scan_bytes(self, data: bytes, source: str = "") -> list[YaraMatch]:
        if not data:
            return []
        try:
            results = self._scanner.scan(data)
        except Exception:  # noqa: BLE001
            return []
        out: list[YaraMatch] = []
        for r in results.matching_rules:
            out.append(YaraMatch(
                rule=r.identifier,
                namespace=getattr(r, "namespace", "") or "",
                tags=list(getattr(r, "tags", []) or []),
                meta=_meta_to_dict(getattr(r, "metadata", None)),
                source=source,
            ))
        return out

    def scan_file(self, path: str) -> list[YaraMatch]:
        try:
            with open(path, "rb") as fh:
                return self.scan_bytes(fh.read(), source=path)
        except Exception:  # noqa: BLE001
            return []


def _meta_to_dict(metadata) -> dict:
    out: dict = {}
    if not metadata:
        return out
    try:
        for item in metadata:
            # yara-x metadata items are (identifier, value) pairs
            if isinstance(item, (tuple, list)) and len(item) == 2:
                out[str(item[0])] = item[1]
    except Exception:  # noqa: BLE001
        pass
    return out


def builtin_rule_count() -> int:
    """How many rules are in the built-in pack (best-effort)."""
    return BUILTIN_RULES.count("\nrule ") + BUILTIN_RULES.startswith("rule ")
