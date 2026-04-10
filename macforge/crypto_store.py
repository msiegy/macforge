"""Fernet-based symmetric encryption for sensitive config values.

A random AES key is generated on first use and stored in DATA_DIR/macforge.key.
Both the key and the encrypted values live in the container data volume —
security depends on restricting access to that volume at the host level.

This module is intentionally simple: it is a lab-grade secret store, not an HSM.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

DATA_DIR = Path(os.environ.get("MACFORGE_DATA_DIR", "/app/data"))
_KEY_PATH = DATA_DIR / "macforge.key"

_fernet: Fernet | None = None


def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is not None:
        return _fernet
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if _KEY_PATH.exists():
        key = _KEY_PATH.read_bytes().strip()
    else:
        key = Fernet.generate_key()
        _KEY_PATH.write_bytes(key)
        try:
            _KEY_PATH.chmod(0o600)
        except Exception:
            pass
        logger.info("Generated new Fernet encryption key at %s", _KEY_PATH)
    _fernet = Fernet(key)
    return _fernet


def encrypt_secret(plaintext: str) -> str:
    """Return a Fernet-encrypted token for *plaintext*. Empty input → empty output."""
    if not plaintext:
        return ""
    return _get_fernet().encrypt(plaintext.encode()).decode()


def decrypt_secret(token: str) -> str:
    """Decrypt a Fernet token and return plaintext.

    Handles legacy plaintext values gracefully: if *token* is not a valid
    Fernet token it is returned as-is and will be re-encrypted on the next save.
    """
    if not token:
        return ""
    try:
        return _get_fernet().decrypt(token.encode()).decode()
    except (InvalidToken, Exception):
        logger.debug("decrypt_secret: value is not a Fernet token — treating as legacy plaintext")
        return token
