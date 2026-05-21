"""Full-disk / full-volume encryption support.

Detects and unlocks the three encryption schemes a forensic examiner
routinely meets, using the libyal bindings:

    BitLocker  ->  pybde      (libbde)
    FileVault  ->  pyfvde     (libfvde)
    LUKS       ->  pyluksde   (libluksde)

Key-escrow model
----------------
The tool never stores keys. The examiner supplies, per encrypted
volume, one of:

    * recovery password   (BitLocker 48-digit, FileVault recovery key)
    * user password
    * a startup-key file  (BitLocker .BEK)            -- BitLocker only
    * a raw FVEK / volume master key (hex)            -- advanced

If unlock fails the volume is tagged "encrypted, no usable text" and
the walk continues — exactly the policy the project review specified.

All libyal volume objects already expose read / seek / tell /
get_size, so a successfully-unlocked volume IS the decrypted file-like
stream and can be handed straight to the filesystem layer.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

try:
    import pybde
    HAS_PYBDE = True
except Exception:  # noqa: BLE001
    HAS_PYBDE = False

try:
    import pyfvde
    HAS_PYFVDE = True
except Exception:  # noqa: BLE001
    HAS_PYFVDE = False

try:
    import pyluksde
    HAS_PYLUKSDE = True
except Exception:  # noqa: BLE001
    HAS_PYLUKSDE = False


# kind constants
BITLOCKER = "bitlocker"
FILEVAULT = "filevault"
LUKS = "luks"
NONE = ""


class EncryptionError(Exception):
    """Raised when an encrypted volume cannot be unlocked."""


@dataclass
class Credentials:
    """What the examiner supplies to unlock a volume."""
    password: str = ""
    recovery_password: str = ""
    startup_key_path: str = ""    # BitLocker .BEK file
    fvek_hex: str = ""            # raw full-volume encryption key (advanced)

    def is_empty(self) -> bool:
        return not (self.password or self.recovery_password
                    or self.startup_key_path or self.fvek_hex)


@dataclass
class DecryptedStream:
    """A successfully unlocked volume, presented as a file-like stream.

    Holds references to every layer below it so nothing is garbage
    collected while the libyal volume is still in use.
    """
    kind: str
    volume: Any                       # the libyal volume object
    _keepalive: list = field(default_factory=list)

    # ---- file-like delegation ------------------------------------------

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            size = self.volume.get_size() - self.volume.get_offset()
        return self.volume.read_buffer(size)

    def seek(self, offset: int, whence: int = 0) -> int:
        self.volume.seek_offset(offset, whence)
        return self.volume.get_offset()

    def tell(self) -> int:
        return self.volume.get_offset()

    def get_size(self) -> int:
        return self.volume.get_size()

    def get_offset(self) -> int:
        return self.volume.get_offset()

    def close(self) -> None:
        try:
            self.volume.close()
        except Exception:  # noqa: BLE001
            pass


# ---- detection ------------------------------------------------------------

def _rewind(stream: Any) -> None:
    try:
        stream.seek(0)
    except Exception:  # noqa: BLE001
        pass


def detect_encryption(stream: Any) -> str:
    """Return BITLOCKER / FILEVAULT / LUKS / NONE for the given volume
    stream. The stream is rewound before and after each probe.
    """
    # BitLocker
    if HAS_PYBDE:
        _rewind(stream)
        try:
            if pybde.check_volume_signature_file_object(stream):
                _rewind(stream)
                return BITLOCKER
        except Exception:  # noqa: BLE001
            pass
    # LUKS
    if HAS_PYLUKSDE:
        _rewind(stream)
        try:
            if pyluksde.check_volume_signature_file_object(stream):
                _rewind(stream)
                return LUKS
        except Exception:  # noqa: BLE001
            pass
    # FileVault
    if HAS_PYFVDE:
        _rewind(stream)
        try:
            if pyfvde.check_volume_signature_file_object(stream):
                _rewind(stream)
                return FILEVAULT
        except Exception:  # noqa: BLE001
            pass
    _rewind(stream)
    return NONE


def detector_availability() -> dict[str, bool]:
    return {
        BITLOCKER: HAS_PYBDE,
        FILEVAULT: HAS_PYFVDE,
        LUKS: HAS_PYLUKSDE,
    }


# ---- unlock ---------------------------------------------------------------

def _unlock_bitlocker(stream: Any, creds: Credentials,
                      keepalive: list) -> DecryptedStream:
    vol = pybde.volume()
    _rewind(stream)
    vol.open_file_object(stream)
    keepalive.append(stream)

    if creds.recovery_password:
        try:
            vol.set_recovery_password(creds.recovery_password)
        except Exception as exc:  # noqa: BLE001
            raise EncryptionError(f"BitLocker recovery password rejected: {exc}")
    if creds.password:
        try:
            vol.set_password(creds.password)
        except Exception as exc:  # noqa: BLE001
            raise EncryptionError(f"BitLocker password rejected: {exc}")
    if creds.startup_key_path:
        try:
            vol.read_startup_key(creds.startup_key_path)
        except Exception as exc:  # noqa: BLE001
            raise EncryptionError(f"BitLocker startup key (.BEK) rejected: {exc}")
    if creds.fvek_hex:
        try:
            vol.set_keys(bytes.fromhex(creds.fvek_hex))
        except Exception as exc:  # noqa: BLE001
            raise EncryptionError(f"BitLocker FVEK rejected: {exc}")

    try:
        if vol.is_locked():
            vol.unlock()
    except Exception as exc:  # noqa: BLE001
        raise EncryptionError(f"BitLocker unlock failed: {exc}")
    if vol.is_locked():
        raise EncryptionError(
            "BitLocker volume is still locked — the supplied key does not "
            "match any key protector on this volume."
        )
    return DecryptedStream(BITLOCKER, vol, keepalive)


def _unlock_luks(stream: Any, creds: Credentials,
                 keepalive: list) -> DecryptedStream:
    vol = pyluksde.volume()
    _rewind(stream)
    vol.open_file_object(stream)
    keepalive.append(stream)

    if creds.password:
        try:
            vol.set_password(creds.password)
        except Exception as exc:  # noqa: BLE001
            raise EncryptionError(f"LUKS password rejected: {exc}")
    if creds.fvek_hex:
        try:
            vol.set_key(bytes.fromhex(creds.fvek_hex))
        except Exception as exc:  # noqa: BLE001
            raise EncryptionError(f"LUKS master key rejected: {exc}")

    try:
        if vol.is_locked():
            vol.unlock()
    except Exception as exc:  # noqa: BLE001
        raise EncryptionError(f"LUKS unlock failed: {exc}")
    if vol.is_locked():
        raise EncryptionError(
            "LUKS volume is still locked — wrong passphrase, or a LUKS "
            "version / cipher this build of libluksde does not support."
        )
    return DecryptedStream(LUKS, vol, keepalive)


def _unlock_filevault(stream: Any, creds: Credentials,
                      keepalive: list) -> DecryptedStream:
    vol = pyfvde.volume()
    _rewind(stream)
    vol.open_file_object(stream)
    keepalive.append(stream)

    if creds.recovery_password:
        try:
            vol.set_recovery_password(creds.recovery_password)
        except Exception as exc:  # noqa: BLE001
            raise EncryptionError(f"FileVault recovery password rejected: {exc}")
    if creds.password:
        try:
            vol.set_password(creds.password)
        except Exception as exc:  # noqa: BLE001
            raise EncryptionError(f"FileVault password rejected: {exc}")
    if creds.fvek_hex:
        try:
            vol.set_keys(bytes.fromhex(creds.fvek_hex))
        except Exception as exc:  # noqa: BLE001
            raise EncryptionError(f"FileVault key rejected: {exc}")

    try:
        if vol.is_locked():
            vol.unlock()
    except Exception as exc:  # noqa: BLE001
        raise EncryptionError(f"FileVault unlock failed: {exc}")
    if vol.is_locked():
        raise EncryptionError(
            "FileVault volume is still locked — wrong password / recovery key."
        )
    return DecryptedStream(FILEVAULT, vol, keepalive)


def unlock_volume(stream: Any, kind: str, creds: Credentials,
                  keepalive: Optional[list] = None) -> DecryptedStream:
    """Unlock an encrypted volume and return a decrypted file-like stream.

    Raises EncryptionError on any failure (wrong key, unsupported
    cipher, missing library). The caller is expected to catch it and
    tag the volume "encrypted, no usable text".
    """
    keepalive = keepalive if keepalive is not None else []
    if creds.is_empty():
        raise EncryptionError("no key material supplied")

    if kind == BITLOCKER:
        if not HAS_PYBDE:
            raise EncryptionError("libbde (pybde) is not installed")
        return _unlock_bitlocker(stream, creds, keepalive)
    if kind == LUKS:
        if not HAS_PYLUKSDE:
            raise EncryptionError("libluksde (pyluksde) is not installed")
        return _unlock_luks(stream, creds, keepalive)
    if kind == FILEVAULT:
        if not HAS_PYFVDE:
            raise EncryptionError("libfvde (pyfvde) is not installed")
        return _unlock_filevault(stream, creds, keepalive)
    raise EncryptionError(f"unknown encryption kind: {kind!r}")


def human_name(kind: str) -> str:
    return {
        BITLOCKER: "BitLocker",
        FILEVAULT: "FileVault 2",
        LUKS: "LUKS",
        NONE: "(not encrypted)",
    }.get(kind, kind)
