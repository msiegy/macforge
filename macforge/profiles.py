"""Load and validate device profiles from YAML files."""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import logging
import os
import secrets
import socket
import struct
from pathlib import Path
from typing import Optional

import yaml

from macforge.models import DeviceProfile

logger = logging.getLogger(__name__)

_cached_seed: Optional[bytes] = None

DEFAULT_PROFILES_DIR = Path(__file__).parent.parent / "profiles"


def load_profiles(profiles_dir: str | Path | None = None) -> list[DeviceProfile]:
    """Load all device profiles from YAML files in the given directory."""
    search_dir = Path(profiles_dir) if profiles_dir else DEFAULT_PROFILES_DIR
    if not search_dir.exists():
        logger.warning("Profiles directory does not exist: %s", search_dir)
        return []

    profiles: list[DeviceProfile] = []
    for yaml_file in sorted(search_dir.glob("*.yaml")):
        try:
            loaded = _load_yaml_file(yaml_file)
            profiles.extend(loaded)
            logger.info("Loaded %d profile(s) from %s", len(loaded), yaml_file.name)
        except Exception:
            logger.exception("Failed to load profile %s", yaml_file)

    logger.info("Total profiles loaded: %d", len(profiles))
    return profiles


def _load_yaml_file(path: Path) -> list[DeviceProfile]:
    with open(path) as fh:
        raw = yaml.safe_load(fh)

    if raw is None:
        return []

    items = raw if isinstance(raw, list) else raw.get("devices", [raw])
    return [DeviceProfile(**item) for item in items]


VENDOR_OUIS: dict[str, list[dict[str, str]]] = {
    "laptop": [
        {"vendor": "Intel",     "oui": "58:82:A8"},
        {"vendor": "Intel/MS",  "oui": "00:50:F2"},
        {"vendor": "Apple",     "oui": "FC:9C:A7"},
        {"vendor": "Apple",     "oui": "F8:4D:89"},
        {"vendor": "Dell",      "oui": "18:03:73"},
        {"vendor": "Lenovo",    "oui": "98:FA:9B"},
    ],
    "desktop": [
        {"vendor": "Intel/MS",  "oui": "00:50:F2"},
        {"vendor": "Intel",     "oui": "58:82:A8"},
        {"vendor": "Dell",      "oui": "18:03:73"},
        {"vendor": "HP",        "oui": "3C:D9:2B"},
    ],
    "workstation": [
        {"vendor": "Intel/MS",  "oui": "00:50:F2"},
        {"vendor": "Dell",      "oui": "18:03:73"},
        {"vendor": "HP",        "oui": "3C:D9:2B"},
    ],
    "smartphone": [
        {"vendor": "Apple",     "oui": "00:03:93"},
        {"vendor": "Apple",     "oui": "F8:4D:89"},
        {"vendor": "Samsung",   "oui": "8C:F5:A3"},
        {"vendor": "Google",    "oui": "3C:5A:B4"},
    ],
    "tablet": [
        {"vendor": "Apple",     "oui": "10:93:E9"},
        {"vendor": "Samsung",   "oui": "8C:F5:A3"},
    ],
    "server": [
        {"vendor": "Parallels", "oui": "00:1C:42"},
        {"vendor": "Dell",      "oui": "18:03:73"},
        {"vendor": "HP/HPE",    "oui": "3C:D9:2B"},
    ],
    "printer": [
        {"vendor": "HP",        "oui": "64:4E:D7"},
        {"vendor": "Brother",   "oui": "00:1C:7A"},
        {"vendor": "Xerox",     "oui": "9C:93:4E"},
        {"vendor": "Ricoh",     "oui": "00:26:73"},
        {"vendor": "Lexmark",   "oui": "00:04:00"},
        {"vendor": "Canon",     "oui": "18:0C:AC"},
        {"vendor": "Epson",     "oui": "00:26:AB"},
    ],
    "iot": [
        {"vendor": "Amazon",    "oui": "34:D2:70"},
        {"vendor": "Google",    "oui": "3C:5A:B4"},
        {"vendor": "Roku",      "oui": "8A:C7:2E"},
        {"vendor": "Samsung",   "oui": "FA:63:E1"},
        {"vendor": "Cisco",     "oui": "00:1B:54"},
        {"vendor": "Sonos",     "oui": "5C:AA:FD"},
        {"vendor": "Ring",      "oui": "34:D2:70"},
    ],
    "gaming": [
        {"vendor": "Nintendo",  "oui": "7C:BB:8A"},
        {"vendor": "Sony/PS",   "oui": "04:5D:4B"},
        {"vendor": "Microsoft", "oui": "7C:ED:8D"},
        {"vendor": "Valve",     "oui": "00:01:97"},
    ],
    "medical": [
        {"vendor": "Philips",       "oui": "00:17:62"},
        {"vendor": "BD/Alaris",     "oui": "00:1A:C2"},
        {"vendor": "GE Healthcare", "oui": "00:09:E8"},
    ],
    "industrial": [
        {"vendor": "Siemens",        "oui": "00:0E:8C"},
        {"vendor": "Allen-Bradley",  "oui": "00:00:BC"},
        {"vendor": "Honeywell",      "oui": "00:0F:7F"},
        {"vendor": "Schneider",      "oui": "00:80:F4"},
    ],
}


def get_oui_table() -> dict[str, list[dict[str, str]]]:
    """Return the vendor OUI table for API consumption."""
    return VENDOR_OUIS


# ── Deterministic MAC seed ──────────────────────────────────────────


def _read_nic_mac(interface: str) -> Optional[str]:
    """Read the hardware MAC address of a NIC via ioctl."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(
            s.fileno(), 0x8927,
            struct.pack("256s", interface[:15].encode()),
        )
        return ":".join(f"{b:02x}" for b in info[18:24])
    except Exception:
        return None


def compute_seed(interface: str) -> bytes:
    """Derive a 32-byte deterministic seed from the host NIC MAC.

    Same hardware + same MACFORGE_INSTANCE_ID = same seed every time.
    Different hardware or different instance ID = different seed.
    Falls back to a random seed (persisted to disk) if the NIC MAC
    cannot be read.
    """
    global _cached_seed
    if _cached_seed is not None:
        return _cached_seed

    nic_mac = _read_nic_mac(interface)
    instance_id = os.environ.get("MACFORGE_INSTANCE_ID", "").strip()

    if nic_mac:
        material = f"macforge-seed:{nic_mac}:{instance_id}"
        _cached_seed = hashlib.sha256(material.encode()).digest()
        logger.info(
            "MAC seed: NIC %s instance=%s fingerprint=%s",
            nic_mac, instance_id or "(default)",
            _cached_seed[:4].hex(),
        )
    else:
        seed_path = Path(os.environ.get("MACFORGE_DATA_DIR", "/app/data")) / ".mac_seed"
        if seed_path.exists():
            _cached_seed = seed_path.read_bytes()[:32]
            logger.info("MAC seed: loaded from %s fingerprint=%s",
                        seed_path, _cached_seed[:4].hex())
        else:
            _cached_seed = secrets.token_bytes(32)
            seed_path.parent.mkdir(parents=True, exist_ok=True)
            seed_path.write_bytes(_cached_seed)
            logger.info("MAC seed: generated random, saved to %s fingerprint=%s",
                        seed_path, _cached_seed[:4].hex())

    return _cached_seed


def get_seed_fingerprint() -> str:
    """Return the first 8 hex chars of the cached seed, or empty string."""
    if _cached_seed is None:
        return ""
    return _cached_seed[:4].hex()


def _derive_mac_suffix(seed: bytes, discriminator: str, n_bytes: int = 3) -> bytes:
    """HMAC-SHA256 the seed with a discriminator, return first n_bytes."""
    h = hmac.new(seed, discriminator.encode(), hashlib.sha256)
    return h.digest()[:n_bytes]


_derive_counter: int = 0


def remap_profile_macs(profiles: list[DeviceProfile], seed: bytes) -> None:
    """Remap YAML-loaded profile MACs to be deterministic per-host.

    Preserves each profile's OUI (first 3 bytes) for realistic vendor
    identification. Replaces the last 3 bytes using HMAC(seed, OUI+name).
    """
    seen: set[str] = set()
    for profile in profiles:
        oui = ":".join(profile.mac.split(":")[:3]).upper()
        disc = f"profile:{oui}:{profile.name}"
        suffix_bytes = _derive_mac_suffix(seed, disc)
        new_mac = oui + ":" + ":".join(f"{b:02X}" for b in suffix_bytes)

        attempt = 0
        while new_mac in seen:
            attempt += 1
            suffix_bytes = _derive_mac_suffix(seed, f"{disc}:{attempt}")
            new_mac = oui + ":" + ":".join(f"{b:02X}" for b in suffix_bytes)
        seen.add(new_mac)

        old_mac = profile.mac
        profile.mac = new_mac
        logger.debug("Remapped %s: %s → %s", profile.name, old_mac, new_mac)


# ── MAC generation ──────────────────────────────────────────────────


def generate_mac(
    existing_macs: set[str] | None = None,
    category: str = "",
    oui_hint: str = "",
    seed: Optional[bytes] = None,
) -> str:
    """Generate a MAC address with a realistic vendor OUI.

    When seed is provided, MACs are deterministic per-host using
    HMAC derivation. When seed is None, falls back to random generation.

    Priority for OUI selection:
      1. oui_hint  - use an exact OUI prefix (e.g. from a clone or vendor pick)
      2. category  - pick a vendor OUI from the category
      3. fallback  - locally-administered 02:CF:xx:xx:xx:xx
    """
    global _derive_counter
    used = existing_macs or set()

    if oui_hint:
        prefix = oui_hint.upper()
    elif category and category.lower() in VENDOR_OUIS:
        entries = VENDOR_OUIS[category.lower()]
        if seed:
            idx_hash = hmac.new(seed, f"oui-select:{category}:{_derive_counter}".encode(), hashlib.sha256)
            idx = int.from_bytes(idx_hash.digest()[:2], "big") % len(entries)
            prefix = entries[idx]["oui"].upper()
        else:
            prefix = secrets.choice(entries)["oui"].upper()
    else:
        prefix = "02:CF"

    prefix_parts = prefix.split(":")
    n_random = 6 - len(prefix_parts)

    for attempt in range(1000):
        if seed:
            _derive_counter += 1
            disc = f"gen:{prefix}:{_derive_counter}:{attempt}"
            raw = _derive_mac_suffix(seed, disc, n_random)
        else:
            raw = secrets.token_bytes(n_random)
        suffix = ":".join("%02X" % b for b in raw)
        mac = prefix + ":" + suffix
        if mac not in used:
            return mac
    raise RuntimeError("Failed to generate unique MAC after 1000 attempts")
