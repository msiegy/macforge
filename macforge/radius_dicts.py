"""File-backed credential and MAC dictionaries for RADIUS bulk session generation.

Provides CRUD operations and CSV import for two dictionary types:
  - credentials: {id, username, password}
  - macs:        {id, mac}

Data is stored in DATA_DIR/radius_dicts/ and survives container restarts.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import os
import uuid
from pathlib import Path
from typing import Iterator

logger = logging.getLogger(__name__)

DATA_DIR = Path(os.environ.get("MACFORGE_DATA_DIR", "/app/data"))
DICTS_DIR = DATA_DIR / "radius_dicts"


def _ensure_dir() -> None:
    DICTS_DIR.mkdir(parents=True, exist_ok=True)


# ─── Credentials ─────────────────────────────────────────────────────

CREDS_PATH = DICTS_DIR / "credentials.json"


def load_credentials() -> list[dict]:
    _ensure_dir()
    if CREDS_PATH.exists():
        try:
            return json.loads(CREDS_PATH.read_text())
        except Exception:
            logger.debug("Could not load credentials.json", exc_info=True)
    return []


def _save_credentials(entries: list[dict]) -> None:
    _ensure_dir()
    CREDS_PATH.write_text(json.dumps(entries, indent=2))


def add_credential(username: str, password: str) -> dict:
    entries = load_credentials()
    entry = {"id": str(uuid.uuid4())[:8], "username": username, "password": password}
    entries.append(entry)
    _save_credentials(entries)
    return entry


def delete_credential(entry_id: str) -> bool:
    entries = load_credentials()
    new = [e for e in entries if e.get("id") != entry_id]
    if len(new) == len(entries):
        return False
    _save_credentials(new)
    return True


def clear_credentials() -> int:
    entries = load_credentials()
    count = len(entries)
    _save_credentials([])
    return count


def import_credentials_csv(csv_text: str) -> int:
    """Parse username,password CSV (one pair per row) and append to the dict."""
    entries = load_credentials()
    reader = csv.reader(io.StringIO(csv_text.strip()))
    added = 0
    for row in reader:
        if len(row) >= 2:
            username = row[0].strip()
            password = row[1].strip()
            if username:
                entries.append({"id": str(uuid.uuid4())[:8],
                                 "username": username, "password": password})
                added += 1
    _save_credentials(entries)
    return added


def cycle_credentials() -> Iterator[tuple[str, str]]:
    """Yield (username, password) pairs in round-robin from the stored dict."""
    entries = load_credentials()
    if not entries:
        return
    idx = 0
    while True:
        e = entries[idx % len(entries)]
        yield e["username"], e["password"]
        idx += 1


# ─── MACs ─────────────────────────────────────────────────────────────

MACS_PATH = DICTS_DIR / "macs.json"


def load_macs() -> list[dict]:
    _ensure_dir()
    if MACS_PATH.exists():
        try:
            return json.loads(MACS_PATH.read_text())
        except Exception:
            logger.debug("Could not load macs.json", exc_info=True)
    return []


def _save_macs(entries: list[dict]) -> None:
    _ensure_dir()
    MACS_PATH.write_text(json.dumps(entries, indent=2))


def add_mac(mac: str) -> dict:
    entries = load_macs()
    entry = {"id": str(uuid.uuid4())[:8], "mac": mac.strip()}
    entries.append(entry)
    _save_macs(entries)
    return entry


def delete_mac(entry_id: str) -> bool:
    entries = load_macs()
    new = [e for e in entries if e.get("id") != entry_id]
    if len(new) == len(entries):
        return False
    _save_macs(new)
    return True


def clear_macs() -> int:
    entries = load_macs()
    count = len(entries)
    _save_macs([])
    return count


def import_macs_csv(csv_text: str) -> int:
    """Parse one MAC per row (with optional label in column 2) and append to the dict."""
    entries = load_macs()
    added = 0
    for line in csv_text.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(",")
        mac = parts[0].strip()
        if mac:
            entries.append({"id": str(uuid.uuid4())[:8], "mac": mac})
            added += 1
    _save_macs(entries)
    return added


def cycle_macs() -> Iterator[str]:
    """Yield MAC addresses in round-robin from the stored dict."""
    entries = load_macs()
    if not entries:
        return
    idx = 0
    while True:
        yield entries[idx % len(entries)]["mac"]
        idx += 1
