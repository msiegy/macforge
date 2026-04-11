"""RADIUS NAD Emulator for MACforge.

Emulates a RADIUS Network Access Device (NAS/switch), sending
authentication and accounting packets directly to ISE without a
physical or virtual NAD.

Supported auth flows:
  - MAB   – MAC Authentication Bypass (pyrad, pure Python)
  - PAP   – Password Authentication Protocol (pyrad, pure Python)
  - PEAP  – EAP-PEAP-MSCHAPv2 via eapol_test subprocess

All flows include a full Accounting Start/Stop lifecycle.
CoA listener (UDP :1700) receives ISE-initiated reauth/disconnect.
Port 1700 is the Cisco IOS CoA default used by ISE's built-in "Cisco" network
device profile. Change to 3799 (RFC 5176) if using a custom NAD profile.
"""

from __future__ import annotations

import asyncio
import csv
import hashlib
import io
import json
import logging
import os
import random
import secrets
import shutil
import socket
import struct
import tempfile
import time
import uuid
from collections import deque
from pathlib import Path
from typing import Any, Literal, Optional

from pydantic import BaseModel

logger = logging.getLogger(__name__)

DATA_DIR = Path(os.environ.get("MACFORGE_DATA_DIR", "/app/data"))
RADIUS_NAD_CONFIG_PATH = DATA_DIR / "radius_nad_config.json"
RADIUS_JOBS_PATH = DATA_DIR / "radius_jobs.json"
ATTR_SETS_PATH = DATA_DIR / "radius_dicts" / "attr_sets.json"
EAPOL_TEST_BIN = shutil.which("eapol_test") or "/usr/local/bin/eapol_test"

# Minimal RADIUS dictionary embedded inline so we never depend on pyrad's
# bundled dictionary file location (which varies by install / pyrad version).
_RADIUS_DICT = """\
# RFC 2865 — Remote Authentication Dial-In User Service
ATTRIBUTE User-Name 1 string
ATTRIBUTE User-Password 2 string
ATTRIBUTE CHAP-Password 3 octets
ATTRIBUTE NAS-IP-Address 4 ipaddr
ATTRIBUTE NAS-Port 5 integer
ATTRIBUTE Service-Type 6 integer
ATTRIBUTE Framed-Protocol 7 integer
ATTRIBUTE Framed-IP-Address 8 ipaddr
ATTRIBUTE Framed-IP-Netmask 9 ipaddr
ATTRIBUTE Framed-Routing 10 integer
ATTRIBUTE Filter-Id 11 string
ATTRIBUTE Framed-MTU 12 integer
ATTRIBUTE Framed-Compression 13 integer
ATTRIBUTE Login-IP-Host 14 ipaddr
ATTRIBUTE Login-Service 15 integer
ATTRIBUTE Login-TCP-Port 16 integer
ATTRIBUTE Reply-Message 18 string
ATTRIBUTE Callback-Number 19 string
ATTRIBUTE Callback-Id 20 string
ATTRIBUTE Framed-Route 22 string
ATTRIBUTE Framed-IPX-Network 23 ipaddr
ATTRIBUTE State 24 octets
ATTRIBUTE Class 25 octets
ATTRIBUTE Vendor-Specific 26 octets
ATTRIBUTE Session-Timeout 27 integer
ATTRIBUTE Idle-Timeout 28 integer
ATTRIBUTE Termination-Action 29 integer
ATTRIBUTE Called-Station-Id 30 string
ATTRIBUTE Calling-Station-Id 31 string
ATTRIBUTE NAS-Identifier 32 string
ATTRIBUTE Proxy-State 33 octets
ATTRIBUTE Login-LAT-Service 34 string
ATTRIBUTE Login-LAT-Node 35 string
ATTRIBUTE Login-LAT-Group 36 octets
ATTRIBUTE Framed-AppleTalk-Link 37 integer
ATTRIBUTE Framed-AppleTalk-Network 38 integer
ATTRIBUTE Framed-AppleTalk-Zone 39 string
ATTRIBUTE CHAP-Challenge 60 octets
ATTRIBUTE NAS-Port-Type 61 integer
ATTRIBUTE Port-Limit 62 integer
ATTRIBUTE Login-LAT-Port 63 string
# RFC 2866 — RADIUS Accounting
ATTRIBUTE Acct-Status-Type 40 integer
ATTRIBUTE Acct-Delay-Time 41 integer
ATTRIBUTE Acct-Input-Octets 42 integer
ATTRIBUTE Acct-Output-Octets 43 integer
ATTRIBUTE Acct-Session-Id 44 string
ATTRIBUTE Acct-Authentic 45 integer
ATTRIBUTE Acct-Session-Time 46 integer
ATTRIBUTE Acct-Input-Packets 47 integer
ATTRIBUTE Acct-Output-Packets 48 integer
ATTRIBUTE Acct-Terminate-Cause 49 integer
ATTRIBUTE Acct-Multi-Session-Id 50 string
ATTRIBUTE Acct-Link-Count 51 integer
ATTRIBUTE Acct-Input-Gigawords 52 integer
ATTRIBUTE Acct-Output-Gigawords 53 integer
ATTRIBUTE Event-Timestamp 55 integer
ATTRIBUTE Egress-VLANID 56 integer
ATTRIBUTE Ingress-Filters 57 integer
ATTRIBUTE Egress-VLAN-Name 58 string
ATTRIBUTE User-Priority-Table 59 octets
# RFC 2867 — RADIUS Accounting Modifications for Tunnel Protocol Support
ATTRIBUTE Tunnel-Type 64 integer
ATTRIBUTE Tunnel-Medium-Type 65 integer
ATTRIBUTE Tunnel-Client-Endpoint 66 string
ATTRIBUTE Tunnel-Server-Endpoint 67 string
ATTRIBUTE Acct-Tunnel-Connection 68 string
ATTRIBUTE Tunnel-Password 69 string
ATTRIBUTE ARAP-Password 70 string
ATTRIBUTE ARAP-Features 71 string
ATTRIBUTE ARAP-Zone-Access 72 integer
ATTRIBUTE ARAP-Security 73 integer
ATTRIBUTE ARAP-Security-Data 74 string
ATTRIBUTE Password-Retry 75 integer
ATTRIBUTE Prompt 76 integer
ATTRIBUTE Connect-Info 77 string
ATTRIBUTE Configuration-Token 78 string
ATTRIBUTE EAP-Message 79 octets
ATTRIBUTE Message-Authenticator 80 octets
ATTRIBUTE Tunnel-Private-Group-Id 81 string
ATTRIBUTE Tunnel-Assignment-Id 82 string
ATTRIBUTE Tunnel-Preference 83 integer
ATTRIBUTE ARAP-Challenge-Response 84 string
ATTRIBUTE Acct-Interim-Interval 85 integer
ATTRIBUTE Acct-Tunnel-Packets-Lost 86 integer
ATTRIBUTE NAS-Port-Id 87 string
ATTRIBUTE Framed-Pool 88 string
ATTRIBUTE Chargeable-User-Identity 89 string
ATTRIBUTE Tunnel-Client-Auth-Id 90 string
ATTRIBUTE Tunnel-Server-Auth-Id 91 string
ATTRIBUTE NAS-Filter-Rule 92 string
ATTRIBUTE Originating-Line-Info 94 string
ATTRIBUTE NAS-IPv6-Address 95 ipv6addr
ATTRIBUTE Framed-Interface-Id 96 ifid
ATTRIBUTE Framed-IPv6-Prefix 97 ipv6prefix
ATTRIBUTE Login-IPv6-Host 98 ipv6addr
ATTRIBUTE Framed-IPv6-Route 99 string
ATTRIBUTE Framed-IPv6-Pool 100 string
# RFC 3162 — RADIUS and IPv6
ATTRIBUTE Error-Cause 101 integer
# VALUES
VALUE Service-Type Login 1
VALUE Service-Type Framed 2
VALUE Service-Type Callback-Login 3
VALUE Service-Type Callback-Framed 4
VALUE Service-Type Outbound 5
VALUE Service-Type Administrative 6
VALUE Service-Type NAS-Prompt 7
VALUE Service-Type Authenticate-Only 8
VALUE Service-Type Callback-NAS-Prompt 9
VALUE Service-Type Call-Check 10
VALUE Service-Type Callback-Administrative 11
VALUE Acct-Status-Type Start 1
VALUE Acct-Status-Type Stop 2
VALUE Acct-Status-Type Interim-Update 3
VALUE Acct-Status-Type Accounting-On 7
VALUE Acct-Status-Type Accounting-Off 8
VALUE NAS-Port-Type Async 0
VALUE NAS-Port-Type Sync 1
VALUE NAS-Port-Type ISDN 2
VALUE NAS-Port-Type ISDN-V120 3
VALUE NAS-Port-Type ISDN-V110 4
VALUE NAS-Port-Type Virtual 5
VALUE NAS-Port-Type PIAFS 6
VALUE NAS-Port-Type HDLC-Clear-Channel 7
VALUE NAS-Port-Type X25 8
VALUE NAS-Port-Type X75 9
VALUE NAS-Port-Type G.3-Fax 10
VALUE NAS-Port-Type SDSL 11
VALUE NAS-Port-Type ADSL-CAP 12
VALUE NAS-Port-Type ADSL-DMT 13
VALUE NAS-Port-Type IDSL 14
VALUE NAS-Port-Type Ethernet 15
VALUE NAS-Port-Type xDSL 16
VALUE NAS-Port-Type Cable 17
VALUE NAS-Port-Type Wireless-Other 18
VALUE NAS-Port-Type Wireless-802.11 19
VALUE NAS-Port-Type Token-Ring 20
VALUE NAS-Port-Type FDDI 21
VALUE NAS-Port-Type Wireless-CDMA2000 22
VALUE NAS-Port-Type Wireless-UMTS 23
VALUE NAS-Port-Type Wireless-1X-EV 24
VALUE NAS-Port-Type IAPP 25
VALUE Acct-Terminate-Cause User-Request 1
VALUE Acct-Terminate-Cause Lost-Carrier 2
VALUE Acct-Terminate-Cause Lost-Service 3
VALUE Acct-Terminate-Cause Idle-Timeout 4
VALUE Acct-Terminate-Cause Session-Timeout 5
VALUE Acct-Terminate-Cause Admin-Reset 6
VALUE Acct-Terminate-Cause Admin-Reboot 7
VALUE Acct-Terminate-Cause Port-Error 8
VALUE Acct-Terminate-Cause NAS-Error 9
VALUE Acct-Terminate-Cause NAS-Request 10
VALUE Acct-Terminate-Cause NAS-Reboot 11
VALUE Acct-Terminate-Cause Port-Unneeded 12
VALUE Acct-Terminate-Cause Port-Preempted 13
VALUE Acct-Terminate-Cause Port-Suspended 14
VALUE Acct-Terminate-Cause Service-Unavailable 15
VALUE Acct-Terminate-Cause Callback 16
VALUE Acct-Terminate-Cause User-Error 17
VALUE Acct-Terminate-Cause Host-Request 18
VALUE Acct-Terminate-Cause Supplicant-Restart 19
VALUE Acct-Terminate-Cause Reauthorization-Failure 20
VALUE Acct-Terminate-Cause Port-Reinit 21
VALUE Acct-Terminate-Cause Port-Disabled 22
VALUE Acct-Terminate-Cause Lost-Power 23
VALUE Tunnel-Type PPTP 1
VALUE Tunnel-Type L2F 2
VALUE Tunnel-Type L2TP 3
VALUE Tunnel-Type ATMP 4
VALUE Tunnel-Type VTP 5
VALUE Tunnel-Type AH 6
VALUE Tunnel-Type IP-IP 7
VALUE Tunnel-Type MIN-IP-IP 8
VALUE Tunnel-Type ESP 9
VALUE Tunnel-Type GRE 10
VALUE Tunnel-Type DVS 11
VALUE Tunnel-Type IP-in-IP-Tunneling 12
VALUE Tunnel-Type VLAN 13
VALUE Tunnel-Medium-Type IPv4 1
VALUE Tunnel-Medium-Type IPv6 2
VALUE Tunnel-Medium-Type NSAP 3
VALUE Tunnel-Medium-Type HDLC 4
VALUE Tunnel-Medium-Type BBN-1822 5
VALUE Tunnel-Medium-Type IEEE-802 6
VALUE Tunnel-Medium-Type E.163 7
VALUE Tunnel-Medium-Type E.164 8
VALUE Tunnel-Medium-Type F.69 9
VALUE Tunnel-Medium-Type X.121 10
VALUE Tunnel-Medium-Type IPX 11
VALUE Tunnel-Medium-Type Appletalk 12
VALUE Tunnel-Medium-Type DecNet-IV 13
VALUE Tunnel-Medium-Type Banyan-Vines 14
VALUE Tunnel-Medium-Type E.164-NSAP 15
# Vendors
VENDOR Cisco 9
BEGIN-VENDOR Cisco
ATTRIBUTE Cisco-AVPair 1 string
ATTRIBUTE Cisco-NAS-Port 2 string
ATTRIBUTE Cisco-Fax-Account-Id-Origin 10 string
ATTRIBUTE Cisco-Fax-Msg-Id 11 string
ATTRIBUTE Cisco-Fax-Pages 12 string
ATTRIBUTE Cisco-Fax-Coverpage-Flag 13 string
ATTRIBUTE Cisco-Fax-Modem-Time 14 string
ATTRIBUTE Cisco-Fax-Connect-Speed 15 string
ATTRIBUTE Cisco-Fax-Recipient-Count 16 string
ATTRIBUTE Cisco-Fax-Process-Abort-Flag 17 string
ATTRIBUTE Cisco-Fax-DSN-Address 18 string
ATTRIBUTE Cisco-Fax-DSN-Flag 19 string
ATTRIBUTE Cisco-Fax-MDN-Address 20 string
ATTRIBUTE Cisco-Fax-MDN-Flag 21 string
ATTRIBUTE Cisco-Fax-Auth-Status 22 string
ATTRIBUTE Cisco-Email-Server-Address 23 string
ATTRIBUTE Cisco-Email-Server-Ack-Flag 24 string
ATTRIBUTE Cisco-Gateway-Id 25 string
ATTRIBUTE Cisco-Call-Type 26 string
ATTRIBUTE Cisco-Port-Used 27 string
ATTRIBUTE Cisco-Abort-Cause 28 string
ATTRIBUTE Cisco-VLAN 35 integer
ATTRIBUTE Cisco-Account-Info 250 string
ATTRIBUTE Cisco-Service-Info 251 string
ATTRIBUTE Cisco-Command-Code 252 string
ATTRIBUTE Cisco-Control-Info 253 string
ATTRIBUTE Cisco-Xmit-Rate 255 integer
END-VENDOR Cisco
VENDOR Microsoft 311
BEGIN-VENDOR Microsoft
ATTRIBUTE MS-CHAP-Response 1 octets
ATTRIBUTE MS-CHAP-Error 2 string
ATTRIBUTE MS-CHAP-CPW-1 3 octets
ATTRIBUTE MS-CHAP-CPW-2 4 octets
ATTRIBUTE MS-CHAP-LM-Enc-PW 5 octets
ATTRIBUTE MS-CHAP-NT-Enc-PW 6 octets
ATTRIBUTE MS-MPPE-Encryption-Policy 7 integer
ATTRIBUTE MS-MPPE-Encryption-Types 8 integer
ATTRIBUTE MS-RAS-Vendor 9 integer
ATTRIBUTE MS-CHAP-Domain 10 string
ATTRIBUTE MS-CHAP-Challenge 11 octets
ATTRIBUTE MS-CHAP-MPPE-Keys 12 octets
ATTRIBUTE MS-BAP-Usage 13 integer
ATTRIBUTE MS-Link-Utilization-Threshold 14 integer
ATTRIBUTE MS-Link-Drop-Time-Limit 15 integer
ATTRIBUTE MS-MPPE-Send-Key 16 octets
ATTRIBUTE MS-MPPE-Recv-Key 17 octets
ATTRIBUTE MS-RAS-Version 18 string
ATTRIBUTE MS-Old-ARAP-Password 19 octets
ATTRIBUTE MS-New-ARAP-Password 20 octets
ATTRIBUTE MS-ARAP-PW-Change-Reason 21 integer
ATTRIBUTE MS-Filter 22 octets
ATTRIBUTE MS-Acct-Auth-Type 23 integer
ATTRIBUTE MS-Acct-EAP-Type 24 integer
ATTRIBUTE MS-CHAP2-Response 25 octets
ATTRIBUTE MS-CHAP2-Success 26 octets
ATTRIBUTE MS-CHAP2-CPW 27 octets
ATTRIBUTE MS-Primary-DNS-Server 28 ipaddr
ATTRIBUTE MS-Secondary-DNS-Server 29 ipaddr
ATTRIBUTE MS-Primary-NBNS-Server 30 ipaddr
ATTRIBUTE MS-Secondary-NBNS-Server 31 ipaddr
END-VENDOR Microsoft
"""

# RFC 2866 Acct-Terminate-Cause name → integer (fallback if pyrad VALUE lookup fails)
_CAUSE_CODES: dict[str, int] = {
    "User-Request":   1,
    "Lost-Carrier":   2,
    "Session-Timeout": 5,
    "Admin-Reset":    6,
    "Lost-Power":     23,
}

# ─── Config Model ────────────────────────────────────────────────────


class RADIUSNADConfig(BaseModel):
    ise_radius_ip: str = ""
    radius_port: int = 1812
    acct_port: int = 1813
    shared_secret: str = ""
    nas_ip: str = ""
    nas_identifier: str = "macforge-nad"
    coa_port: int = 1700
    coa_enabled: bool = False


def load_radius_nad_config() -> RADIUSNADConfig:
    if RADIUS_NAD_CONFIG_PATH.exists():
        try:
            data = json.loads(RADIUS_NAD_CONFIG_PATH.read_text())
            return RADIUSNADConfig(**data)
        except Exception:
            logger.exception("Failed to load RADIUS NAD config")
    return RADIUSNADConfig()


def save_radius_nad_config(cfg: RADIUSNADConfig) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    RADIUS_NAD_CONFIG_PATH.write_text(cfg.model_dump_json(indent=2))
    logger.info("Saved RADIUS NAD config for %s", cfg.ise_radius_ip)


# ─── Session Models & Live Session Store ─────────────────────────────


_CERTS_DIR = DATA_DIR / "certs"


class BulkJob(BaseModel):
    """Record of a completed (or running) bulk session run."""
    job_id: str = ""
    auth_type: str = "mab"
    count: int = 0
    accepted: int = 0
    rejected: int = 0
    errors: int = 0
    status: str = "running"      # running | completed | cancelled | failed
    started_at: float = 0.0
    finished_at: float = 0.0
    params: dict = {}            # snapshot of BulkRunPayload for Repeat


class CustomAttr(BaseModel):
    """A user-defined RADIUS attribute to inject into session packets."""
    name: str           # e.g. "Tunnel-Pvt-Group-Id"
    value: str          # raw string; encoded by pyrad based on attribute type
    packet: str = "all" # "auth" | "acct-start" | "acct-stop" | "all"


def _load_attr_sets() -> dict:
    """Load named attribute sets from disk. Returns {name: [CustomAttr dicts]}."""
    if ATTR_SETS_PATH.exists():
        try:
            return json.loads(ATTR_SETS_PATH.read_text())
        except Exception:
            pass
    return {}


def _save_attr_sets(sets: dict) -> None:
    ATTR_SETS_PATH.parent.mkdir(parents=True, exist_ok=True)
    ATTR_SETS_PATH.write_text(json.dumps(sets, indent=2))


def get_attr_sets() -> dict:
    return _load_attr_sets()


def save_attr_set(name: str, attrs: list[dict]) -> None:
    sets = _load_attr_sets()
    sets[name] = attrs
    _save_attr_sets(sets)


def delete_attr_set(name: str) -> bool:
    sets = _load_attr_sets()
    if name not in sets:
        return False
    del sets[name]
    _save_attr_sets(sets)
    return True


def _apply_custom_attrs(req: Any, custom_attrs: list[CustomAttr], phase: str) -> None:
    """Apply custom attributes to a RADIUS packet for the given phase.

    phase must be one of: "auth", "acct-start", "acct-stop".
    Attributes with packet="all" are applied to all phases.

    Cisco-AVPair is treated specially: existing values (e.g. subscriber: DHCP hints
    already set by _send_accounting_sync) are preserved and custom values are appended
    rather than replaced. All other attributes overwrite whatever was set previously.
    """
    for attr in custom_attrs:
        if attr.packet not in ("all", phase):
            continue
        try:
            if attr.name == "Cisco-AVPair":
                # Retrieve current value(s) and merge so we don't stomp on
                # subscriber: DHCP hints or other AVPairs already in the packet.
                existing = req.get("Cisco-AVPair") or []
                if isinstance(existing, (str, bytes)):
                    existing = [existing]
                existing = list(existing)
                existing.append(attr.value)
                req["Cisco-AVPair"] = existing if len(existing) > 1 else existing[0]
            else:
                req[attr.name] = attr.value
        except Exception as exc:
            logger.debug("Could not set custom attr %s=%r: %s", attr.name, attr.value, exc)


# Build a RADIUS attribute reference for the UI attribute picker.
# Parses the embedded _RADIUS_DICT to extract attribute metadata.
def _build_attr_catalog() -> list[dict]:
    """Return a list of {name, id, type, vendor} dicts from the embedded dictionary."""
    catalog = []
    current_vendor = ""
    for line in _RADIUS_DICT.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if parts[0] == "VENDOR":
            pass
        elif parts[0] == "BEGIN-VENDOR" and len(parts) >= 2:
            current_vendor = parts[1]
        elif parts[0] == "END-VENDOR":
            current_vendor = ""
        elif parts[0] == "ATTRIBUTE" and len(parts) >= 4:
            catalog.append({
                "name": parts[1],
                "id": parts[2],
                "type": parts[3],
                "vendor": current_vendor or "RFC",
            })
    return catalog


_ATTR_CATALOG: list[dict] = []  # lazily populated on first request


def get_attr_catalog() -> list[dict]:
    global _ATTR_CATALOG
    if not _ATTR_CATALOG:
        _ATTR_CATALOG = _build_attr_catalog()
    return _ATTR_CATALOG


class RADIUSSessionResult(BaseModel):
    session_id: str = ""
    auth_type: Literal["mab", "pap", "peap", "eap-tls"] = "mab"
    mac: str = ""
    username: str = ""
    result: Literal["accept", "reject", "error", "timeout"] = "error"
    detail: str = ""
    acct_session_id: str = ""
    duration_ms: int = 0
    timestamp: float = 0.0


class CoAEvent(BaseModel):
    event_id: str = ""
    event_type: str = ""        # "CoA-Request" | "Disconnect-Request"
    source_ip: str = ""
    mac: str = ""
    session_id: str = ""
    response: str = ""          # "CoA-ACK" | "CoA-NAK"
    timestamp: float = 0.0


# ─── In-memory state ─────────────────────────────────────────────────

_session_log: deque[RADIUSSessionResult] = deque(maxlen=5000)
_coa_events: deque[CoAEvent] = deque(maxlen=500)
_coa_event_queue: asyncio.Queue = asyncio.Queue()

_bulk_state: dict[str, Any] = {
    "running": False,
    "total": 0,
    "accepted": 0,
    "rejected": 0,
    "errors": 0,
    "started_at": 0.0,
    "cancelled": False,
}

_coa_transport: Optional[asyncio.DatagramTransport] = None

# Job history — keeps last 50 bulk run records; persisted to radius_jobs.json.
_jobs: deque[BulkJob] = deque(maxlen=50)
_jobs_loaded = False


def _load_jobs() -> None:
    global _jobs_loaded
    if _jobs_loaded:
        return
    _jobs_loaded = True
    if RADIUS_JOBS_PATH.exists():
        try:
            raw = json.loads(RADIUS_JOBS_PATH.read_text())
            for item in raw:
                _jobs.append(BulkJob(**item))
        except Exception:
            logger.debug("Could not load radius_jobs.json", exc_info=True)


def _persist_jobs() -> None:
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        RADIUS_JOBS_PATH.write_text(
            json.dumps([j.model_dump() for j in _jobs], indent=2)
        )
    except Exception:
        logger.debug("Could not persist radius_jobs.json", exc_info=True)


def get_jobs() -> list[dict]:
    _load_jobs()
    return [j.model_dump() for j in reversed(list(_jobs))]


def delete_job(job_id: str) -> bool:
    _load_jobs()
    before = len(_jobs)
    new = deque((j for j in _jobs if j.job_id != job_id), maxlen=50)
    _jobs.clear()
    _jobs.extend(new)
    _persist_jobs()
    return len(_jobs) < before


def clear_completed_jobs() -> int:
    _load_jobs()
    before = len(_jobs)
    new = deque((j for j in _jobs if j.status == "running"), maxlen=50)
    _jobs.clear()
    _jobs.extend(new)
    _persist_jobs()
    return before - len(_jobs)


# Live session store — sessions that have sent Acct-Start but NOT yet Acct-Stop.
# Keyed by Acct-Session-Id. Allows CoA testing: ISE sees an active session until
# we explicitly terminate it (manual, timer, or on receiving Disconnect-Request).
_live_sessions: dict[str, dict] = {}


# ─── Live session helpers ─────────────────────────────────────────────

def _register_live_session(
    cfg: RADIUSNADConfig,
    acct_session_id: str,
    mac: str,
    username: str,
    nas_port: int,
    auth_type: str,
    framed_ip: str = "",
    terminate_cause: str = "auto",
) -> None:
    _live_sessions[acct_session_id] = {
        "acct_session_id": acct_session_id,
        "mac": mac,
        "username": username,
        "nas_port": nas_port,
        "auth_type": auth_type,
        "framed_ip": framed_ip,
        "terminate_cause": terminate_cause,
        "start_time": time.time(),
        "_cfg": cfg,
        "_timer_handle": None,
    }
    logger.info("Live session registered: %s (%s / %s)", acct_session_id, mac, username)


def terminate_live_session_sync(
    acct_session_id: str,
    cause: str = "User-Request",
) -> bool:
    """Send Acct-Stop for a live session and remove it from the store.

    Returns True if a live session was found and terminated, False otherwise.
    The Acct-Session-Time is the real elapsed time since Acct-Start.
    """
    entry = _live_sessions.pop(acct_session_id, None)
    if not entry:
        return False
    cfg: RADIUSNADConfig = entry["_cfg"]
    elapsed = max(1, int(time.time() - entry["start_time"]))
    in_oct, out_oct = _simulated_bytes(entry["auth_type"])
    # Explicit cause overrides stored cause (e.g. CoA Disconnect always uses Admin-Reset)
    effective_cause = cause
    if effective_cause == "User-Request" and entry.get("terminate_cause", "auto") not in ("auto", ""):
        # Preserve stored cause only for timer-driven termination; manual/CoA overrides win
        pass
    try:
        _send_accounting_sync(
            cfg, "Stop",
            entry["mac"], entry["username"],
            acct_session_id, entry["nas_port"],
            auth_type=entry["auth_type"],
            session_time_s=elapsed,
            input_octets=in_oct,
            output_octets=out_oct,
            framed_ip=entry.get("framed_ip", ""),
            terminate_cause=effective_cause,
        )
        logger.info(
            "Live session terminated: %s (uptime %ds, cause=%s)",
            acct_session_id, elapsed, effective_cause,
        )
    except Exception as exc:
        logger.warning("Acct-Stop failed for %s: %s", acct_session_id, exc)
    return True


async def terminate_live_session(acct_session_id: str, cause: str = "User-Request") -> bool:
    """Async wrapper — terminate a live session from async context."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None, terminate_live_session_sync, acct_session_id, cause
    )


async def terminate_all_live_sessions(cause: str = "User-Request") -> int:
    """Terminate all live sessions. Returns count of sessions terminated."""
    ids = list(_live_sessions.keys())
    count = 0
    for sid in ids:
        if await terminate_live_session(sid, cause):
            count += 1
    return count


def get_live_sessions() -> list[dict]:
    """Return a serialisable list of currently live sessions, newest first."""
    now = time.time()
    result = []
    for entry in _live_sessions.values():
        result.append({
            "acct_session_id": entry["acct_session_id"],
            "mac": entry["mac"],
            "username": entry["username"],
            "auth_type": entry["auth_type"],
            "framed_ip": entry.get("framed_ip", ""),
            "start_time": entry["start_time"],
            "uptime_secs": int(now - entry["start_time"]),
        })
    return sorted(result, key=lambda x: x["start_time"], reverse=True)


async def _auto_terminate_after(acct_session_id: str, delay_secs: int) -> None:
    """Asyncio task: wait delay_secs then send Acct-Stop for a live session."""
    await asyncio.sleep(delay_secs)
    entry = _live_sessions.get(acct_session_id)
    stored = entry.get("terminate_cause", "auto") if entry else "auto"
    # "auto" for a timed session means the NAS timer expired
    cause = "Session-Timeout" if stored in ("auto", "") else stored
    await terminate_live_session(acct_session_id, cause)


def get_session_log() -> list[RADIUSSessionResult]:
    return list(_session_log)


def clear_session_log() -> None:
    _session_log.clear()


def get_coa_events() -> list[CoAEvent]:
    return list(_coa_events)


def clear_coa_events() -> None:
    _coa_events.clear()


def get_bulk_state() -> dict:
    elapsed = time.time() - _bulk_state["started_at"] if _bulk_state["running"] else 0
    done = _bulk_state["accepted"] + _bulk_state["rejected"] + _bulk_state["errors"]
    rate = round(done / elapsed, 1) if elapsed > 0 else 0
    return {**_bulk_state, "elapsed_sec": round(elapsed, 1), "rate": rate}


def export_sessions_csv() -> str:
    buf = io.StringIO()
    fields = ["session_id", "auth_type", "mac", "username", "result",
              "detail", "acct_session_id", "duration_ms", "timestamp"]
    w = csv.DictWriter(buf, fieldnames=fields)
    w.writeheader()
    for s in _session_log:
        w.writerow(s.model_dump())
    return buf.getvalue()


# ─── pyrad helpers ───────────────────────────────────────────────────

def _build_radius_dict():
    """Build a pyrad Dictionary from our embedded attribute definitions.

    pyrad's DictFile parser only accepts file paths (not file-like objects),
    so we write the embedded dictionary to a temp file and load from there.
    The file is kept alive for the process lifetime via the module-level ref.
    """
    from pyrad import dictionary as pdict
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".dict", prefix="/tmp/mf_radius_", delete=False
    )
    tmp.write(_RADIUS_DICT)
    tmp.flush()
    tmp.close()
    try:
        d = pdict.Dictionary(tmp.name)
    finally:
        try:
            Path(tmp.name).unlink()
        except Exception:
            pass
    return d


# Module-level singleton — built once, shared across all pyrad calls.
_PYRAD_DICT = None


def _get_pyrad_dict():
    global _PYRAD_DICT
    if _PYRAD_DICT is None:
        try:
            _PYRAD_DICT = _build_radius_dict()
        except Exception as exc:
            logger.error("Failed to build RADIUS dictionary: %s", exc)
            raise
    return _PYRAD_DICT


def _make_pyrad_client(cfg: RADIUSNADConfig, acct: bool = False):
    """Create a pyrad UDP client targeting ISE."""
    try:
        from pyrad import client as pclient
    except ImportError as exc:
        raise RuntimeError("pyrad is not installed — rebuild the Docker image") from exc

    c = pclient.Client(
        server=cfg.ise_radius_ip,
        authport=cfg.radius_port,
        acctport=cfg.acct_port,
        secret=cfg.shared_secret.encode(),
        dict=_get_pyrad_dict(),
    )
    c.timeout = 10
    c.retries = 1
    return c


def _fill_nas_attrs(req: Any, cfg: RADIUSNADConfig, nas_port: int,
                    calling_mac: str, called_id: str) -> None:
    """Populate standard NAS attributes on an auth request."""
    req["NAS-IP-Address"] = cfg.nas_ip or _local_ip()
    req["NAS-Identifier"] = cfg.nas_identifier
    req["NAS-Port"] = nas_port
    req["NAS-Port-Id"] = f"GigabitEthernet1/0/{nas_port}"
    req["NAS-Port-Type"] = 15           # Ethernet
    req["Called-Station-Id"] = called_id or cfg.nas_identifier
    req["Calling-Station-Id"] = calling_mac


def _local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


# ─── MAB Session ─────────────────────────────────────────────────────

def _run_mab_session_sync(cfg: RADIUSNADConfig, mac: str,
                           nas_port: int,
                           _mab_live_session: bool = False,
                           profile_attrs: dict | None = None,
                           terminate_cause: str = "auto",
                           custom_attrs: list | None = None) -> RADIUSSessionResult:
    """Send a MAB Access-Request to ISE (synchronous).

    MAB flow on a real switch:
      1. Detect link-up + no EAP response within 30s → send Access-Request
         (Service-Type=Call-Check, User-Name=MAC-with-dashes, User-Password=same)
      2. On Accept → send Acct-Start (with subscriber: DHCP AVPairs if profiling
         attrs are supplied), hold session, send Acct-Stop.

    profile_attrs keys: vendor_class, hostname, param_request_list, profile_name.
    DHCP hints are sent in Accounting-Start (subscriber: namespace) to mirror
    Cisco Device Sensor behaviour — *not* in the Access-Request.
    """
    from pyrad import packet as ppacket

    mac_clean = mac.lower().replace(":", "").replace("-", "")
    mac_colons = ":".join(mac_clean[i:i+2] for i in range(0, 12, 2))
    # Real Cisco switches format the MAB User-Name as uppercase dashes (DE-AD-BE-AA-BB-CC)
    mac_dashes = "-".join(mac_clean[i:i+2].upper() for i in range(0, 12, 2))
    acct_session_id = str(uuid.uuid4())[:8].upper()
    framed_ip = (
        f"10.{random.randint(1, 254)}"
        f".{random.randint(0, 254)}"
        f".{random.randint(1, 254)}"
    )

    result = RADIUSSessionResult(
        session_id=str(uuid.uuid4()),
        auth_type="mab",
        mac=mac_colons,
        username=mac_dashes,
        acct_session_id=acct_session_id,
        timestamp=time.time(),
    )

    t0 = time.monotonic()
    try:
        c = _make_pyrad_client(cfg)
        req = c.CreateAuthPacket(code=ppacket.AccessRequest)
        req["User-Name"] = mac_dashes
        req["User-Password"] = req.PwCrypt(mac_dashes)
        req["Service-Type"] = 10    # Call-Check — the MAB signal ISE looks for
        _fill_nas_attrs(req, cfg, nas_port, mac_colons, cfg.nas_identifier)
        # DHCP profiling hints belong in Accounting-Start (subscriber: namespace),
        # not in the Access-Request — see plan §1d.
        if custom_attrs:
            _apply_custom_attrs(req, custom_attrs, "auth")

        reply = c.SendPacket(req)

        if reply.code == ppacket.AccessAccept:
            result.result = "accept"
            _send_accounting_sync(cfg, "Start", mac_colons, mac_dashes,
                                  acct_session_id, nas_port, auth_type="mab",
                                  framed_ip=framed_ip, profile_attrs=profile_attrs)
            if _mab_live_session:
                _register_live_session(cfg, acct_session_id, mac_colons, mac_dashes,
                                       nas_port, "mab", framed_ip=framed_ip,
                                       terminate_cause=terminate_cause)
            else:
                sess_secs = random.randint(60, 600)
                in_oct, out_oct = _simulated_bytes("mab")
                _send_accounting_sync(cfg, "Stop", mac_colons, mac_dashes,
                                      acct_session_id, nas_port, auth_type="mab",
                                      session_time_s=sess_secs,
                                      input_octets=in_oct, output_octets=out_oct,
                                      framed_ip=framed_ip,
                                      terminate_cause="User-Request")
        elif reply.code == ppacket.AccessReject:
            result.result = "reject"
            msgs = reply.get("Reply-Message", [])
            if msgs:
                result.detail = msgs[0] if isinstance(msgs[0], str) else msgs[0].decode(errors="replace")
        else:
            result.result = "error"
            result.detail = f"Unexpected reply code {reply.code}"

    except Exception as exc:
        result.result = "error"
        result.detail = str(exc)[:200]

    result.duration_ms = int((time.monotonic() - t0) * 1000)
    return result


# ─── PAP Session ─────────────────────────────────────────────────────

def _run_pap_session_sync(cfg: RADIUSNADConfig, username: str,
                           password: str, nas_port: int,
                           mac: str = "",
                           live_session: bool = False,
                           terminate_cause: str = "auto",
                           custom_attrs: list | None = None) -> RADIUSSessionResult:
    """Send a PAP Access-Request to ISE (synchronous).

    PAP flow (e.g. VPN gateway, admin console, or non-EAP wired NAD):
      1. User presents credentials → NAS sends Access-Request with PAP password
      2. On Accept → Acct-Start, session, Acct-Stop
    """
    from pyrad import packet as ppacket

    # Generate a locally-administered MAC if caller didn't supply one.
    # Using a real MAC avoids the all-zeros endpoint being mis-profiled by ISE.
    mac_colons = mac if mac else _random_mac()
    acct_session_id = str(uuid.uuid4())[:8].upper()
    # Simulate a host IP in a private range for Framed-IP-Address in accounting
    framed_ip = f"10.{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(1,254)}"

    result = RADIUSSessionResult(
        session_id=str(uuid.uuid4()),
        auth_type="pap",
        mac=mac_colons,
        username=username,
        acct_session_id=acct_session_id,
        timestamp=time.time(),
    )

    t0 = time.monotonic()
    try:
        c = _make_pyrad_client(cfg)
        req = c.CreateAuthPacket(code=ppacket.AccessRequest)
        req["User-Name"] = username
        req["User-Password"] = req.PwCrypt(password)
        req["Service-Type"] = 2   # Framed — typical for network access auth
        _fill_nas_attrs(req, cfg, nas_port, mac_colons, cfg.nas_identifier)
        if custom_attrs:
            _apply_custom_attrs(req, custom_attrs, "auth")

        reply = c.SendPacket(req)

        if reply.code == ppacket.AccessAccept:
            result.result = "accept"
            _send_accounting_sync(cfg, "Start", mac_colons, username,
                                  acct_session_id, nas_port, auth_type="pap",
                                  framed_ip=framed_ip)
            if live_session:
                _register_live_session(cfg, acct_session_id, mac_colons, username,
                                       nas_port, "pap", framed_ip=framed_ip,
                                       terminate_cause=terminate_cause)
            else:
                sess_secs = random.randint(300, 3600)
                in_oct, out_oct = _simulated_bytes("pap")
                _send_accounting_sync(cfg, "Stop", mac_colons, username,
                                      acct_session_id, nas_port, auth_type="pap",
                                      session_time_s=sess_secs,
                                      input_octets=in_oct, output_octets=out_oct,
                                      framed_ip=framed_ip,
                                      terminate_cause="User-Request")
        elif reply.code == ppacket.AccessReject:
            result.result = "reject"
            msgs = reply.get("Reply-Message", [])
            if msgs:
                result.detail = msgs[0] if isinstance(msgs[0], str) else msgs[0].decode(errors="replace")
        else:
            result.result = "error"
            result.detail = f"Unexpected reply code {reply.code}"

    except Exception as exc:
        result.result = "error"
        result.detail = str(exc)[:200]

    result.duration_ms = int((time.monotonic() - t0) * 1000)
    return result


# ─── PEAP-MSCHAPv2 Session (via eapol_test) ──────────────────────────

async def _run_peap_session_async(cfg: RADIUSNADConfig, username: str,
                                   password: str, nas_port: int,
                                   mac: str = "",
                                   live_session: bool = False,
                                   terminate_cause: str = "auto",
                                   custom_attrs: list | None = None) -> RADIUSSessionResult:
    """Run EAP-PEAP-MSCHAPv2 via eapol_test subprocess.

    PEAP-MSCHAPv2 flow on a real wired switch:
      1. Link-up → switch sends EAP-Request/Identity
      2. Client NAK → switch negotiates PEAP with ISE
      3. TLS tunnel established → MSCHAPv2 inner auth
      4. Access-Accept with MPPE keys → Acct-Start, session, Acct-Stop
    """
    # Generate a locally-administered MAC if caller didn't supply one.
    mac_colons = mac if mac else _random_mac()
    acct_session_id = str(uuid.uuid4())[:8].upper()
    anonymous = f"anonymous@{username.split('@')[1]}" if "@" in username else "anonymous"

    result = RADIUSSessionResult(
        session_id=str(uuid.uuid4()),
        auth_type="peap",
        mac=mac_colons,
        username=username,
        acct_session_id=acct_session_id,
        timestamp=time.time(),
    )

    if not Path(EAPOL_TEST_BIN).exists():
        result.result = "error"
        result.detail = (
            f"eapol_test not found at {EAPOL_TEST_BIN}. "
            "Rebuild the Docker image to compile eapol_test from the hostap source."
        )
        return result

    conf_content = (
        "network={\n"
        '  key_mgmt=IEEE8021X\n'
        '  eap=PEAP\n'
        f'  identity="{username}"\n'
        f'  anonymous_identity="{anonymous}"\n'
        f'  password="{password}"\n'
        '  phase2="auth=MSCHAPV2"\n'
        '  phase1="peaplabel=0"\n'
        '  eap_workaround=0\n'
        '}\n'
    )

    t0 = time.monotonic()
    tmp_conf = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".conf", delete=False, prefix="/tmp/mf_peap_"
        ) as f:
            f.write(conf_content)
            tmp_conf = f.name

        nas_ip = cfg.nas_ip or _local_ip()
        # NAS-IP-Address is an ipaddr type — must be 4-byte hex for eapol_test -N.
        import binascii as _ba
        nas_ip_hex = _ba.hexlify(socket.inet_aton(nas_ip)).decode()
        cmd = [
            EAPOL_TEST_BIN,
            "-c", tmp_conf,
            "-a", cfg.ise_radius_ip,
            "-p", str(cfg.radius_port),
            "-s", cfg.shared_secret,
            "-N", f"4:x:{nas_ip_hex}",                          # NAS-IP-Address (ipaddr, hex)
            "-N", f"32:s:{cfg.nas_identifier}",                 # NAS-Identifier
            "-N", f"31:s:{mac_colons}",                         # Calling-Station-Id
            "-N", f"5:d:{nas_port}",                            # NAS-Port
            "-N", f"87:s:GigabitEthernet1/0/{nas_port}",        # NAS-Port-Id
            "-N", "61:d:15",                                    # NAS-Port-Type = Ethernet
            # eapol_test hard-codes "CONNECT 11Mbps 802.11b" (WiFi) as Connect-Info.
            # Override with a wired Gigabit Ethernet string so ISE profiling and logs
            # don't show a spurious 802.11 connection speed for a simulated wired session.
            "-N", "77:s:CONNECT 1Gbps 802.3",                  # Connect-Info = wired GigE
            "-r", "0",                                          # no retries on failure
        ]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=20)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            result.result = "timeout"
            result.detail = "eapol_test timed out after 20s"
            result.duration_ms = int((time.monotonic() - t0) * 1000)
            return result

        output = (stdout + stderr).decode(errors="replace")
        logger.debug("eapol_test output:\n%s", output[-2000:])

        if "SUCCESS" in output:
            result.result = "accept"
            loop = asyncio.get_event_loop()
            framed_ip = (
                f"10.{random.randint(1,254)}.{random.randint(0,254)}"
                f".{random.randint(1,254)}"
            )
            await loop.run_in_executor(
                None,
                lambda: _send_accounting_sync(
                    cfg, "Start", mac_colons, username, acct_session_id, nas_port,
                    auth_type="peap", framed_ip=framed_ip,
                ),
            )
            if live_session:
                _register_live_session(cfg, acct_session_id, mac_colons, username,
                                       nas_port, "peap", framed_ip=framed_ip,
                                       terminate_cause=terminate_cause)
            else:
                sess_secs = random.randint(300, 3600)
                in_oct, out_oct = _simulated_bytes("peap")
                await loop.run_in_executor(
                    None,
                    lambda: _send_accounting_sync(
                        cfg, "Stop", mac_colons, username, acct_session_id, nas_port,
                        auth_type="peap", session_time_s=sess_secs,
                        input_octets=in_oct, output_octets=out_oct, framed_ip=framed_ip,
                        terminate_cause="User-Request",
                    ),
                )
        elif "FAILURE" in output:
            result.result = "reject"
            # Extract the most informative failure reason from the log.
            # Preference order: EAP failure text → last EAP state line.
            detail = ""
            for line in output.splitlines():
                low = line.lower()
                if "failure" in low and "eap" in low and "state" not in low:
                    detail = line.strip()
                    break
                if any(kw in low for kw in ("wrong password", "access-reject", "failed")):
                    detail = line.strip()
                    break
            result.detail = detail[:200] if detail else "Access-Reject from ISE"
        else:
            # Neither SUCCESS nor FAILURE — usually a connectivity/config error.
            # Grab the last meaningful output line.
            meaningful = [
                l.strip() for l in output.splitlines()
                if l.strip() and not l.startswith("OpenSSL")
            ]
            result.result = "error"
            result.detail = (meaningful[-1] if meaningful else output[-200:])[:200]

    except Exception as exc:
        result.result = "error"
        result.detail = str(exc)[:200]
    finally:
        if tmp_conf:
            Path(tmp_conf).unlink(missing_ok=True)

    result.duration_ms = int((time.monotonic() - t0) * 1000)
    return result


# ─── EAP-TLS Session (via eapol_test) ────────────────────────────────

async def _run_eaptls_session_async(
    cfg: RADIUSNADConfig,
    identity: str,
    cert_file: str,
    key_file: str,
    nas_port: int = 1,
    mac: str = "",
    validate_server_cert: bool = False,
    ise_ca_cert_file: str = "",
    live_session: bool = False,
    terminate_cause: str = "auto",
    custom_attrs: list | None = None,
) -> RADIUSSessionResult:
    """Run EAP-TLS via eapol_test subprocess.

    EAP-TLS flow on a real wired switch:
      1. Client sends EAP-Response/Identity (often anonymous for outer, real
         identity embedded in the certificate)
      2. TLS handshake — client presents certificate, ISE validates against
         trusted CA, checks CN/SAN against identity store (AD or Internal PKI)
      3. Access-Accept with MPPE keying material → Acct-Start/Stop

    Two separate CA chains:
      - Client cert CA (our lab-ca.pem) → loaded into ISE Trusted Certificates
        so ISE can verify the client certificate.
      - ISE server cert CA → needed by eapol_test to verify ISE's TLS cert.
        For lab testing set validate_server_cert=False, which omits the ca_cert
        line entirely from the wpa_supplicant config. Per the wpa_supplicant docs,
        omitting ca_cert causes the server certificate to be skipped. This is the
        same behaviour as our PEAP sessions and is appropriate for most lab scenarios.
        (Note: ca_cert="/dev/null" was used previously but OpenSSL 3.x now rejects
        it with "no certificate or crl found".)
        Set validate_server_cert=True and supply ise_ca_cert_file when strict
        mutual TLS validation is required.
    """
    mac_colons = mac if mac else _random_mac()
    acct_session_id = str(uuid.uuid4())[:8].upper()

    result = RADIUSSessionResult(
        session_id=str(uuid.uuid4()),
        auth_type="eap-tls",
        mac=mac_colons,
        username=identity,
        acct_session_id=acct_session_id,
        timestamp=time.time(),
    )

    if not Path(EAPOL_TEST_BIN).exists():
        result.result = "error"
        result.detail = (
            f"eapol_test not found at {EAPOL_TEST_BIN}. "
            "Rebuild the Docker image to compile eapol_test from hostap source."
        )
        return result

    cert_path = _CERTS_DIR / cert_file
    key_path  = _CERTS_DIR / key_file

    for path, label in [(cert_path, "client cert"), (key_path, "private key")]:
        if not path.exists():
            result.result = "error"
            result.detail = f"File not found: {label} ({path.name}) — check Certificates tab"
            return result

    # Determine ca_cert line for eapol_test:
    #   validate_server_cert=True  → include ca_cert pointing to the supplied ISE CA file.
    #   validate_server_cert=False → OMIT ca_cert entirely. Per wpa_supplicant docs,
    #     when ca_cert is absent the server certificate is not verified. This is the
    #     correct way to skip validation with OpenSSL 3.x; the old ca_cert="/dev/null"
    #     trick no longer works because OpenSSL now requires at least one valid PEM cert.
    if validate_server_cert and ise_ca_cert_file:
        ise_ca_path = _CERTS_DIR / ise_ca_cert_file
        if not ise_ca_path.exists():
            result.result = "error"
            result.detail = f"ISE CA cert not found: {ise_ca_cert_file}"
            return result
        ca_cert_line = f'  ca_cert="{ise_ca_path}"\n'
    else:
        # Omit ca_cert — wpa_supplicant will skip server cert verification.
        ca_cert_line = ""

    conf_content = (
        "network={\n"
        "  key_mgmt=IEEE8021X\n"
        "  eap=TLS\n"
        f'  identity="{identity}"\n'
        + ca_cert_line
        + f'  client_cert="{cert_path}"\n'
        f'  private_key="{key_path}"\n'
        '  private_key_passwd=""\n'
        '}\n'
    )

    t0 = time.monotonic()
    tmp_conf = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".conf", delete=False, prefix="/tmp/mf_eaptls_"
        ) as f:
            f.write(conf_content)
            tmp_conf = f.name

        nas_ip = cfg.nas_ip or _local_ip()
        import binascii as _ba
        nas_ip_hex = _ba.hexlify(socket.inet_aton(nas_ip)).decode()
        cmd = [
            EAPOL_TEST_BIN,
            "-c", tmp_conf,
            "-a", cfg.ise_radius_ip,
            "-p", str(cfg.radius_port),
            "-s", cfg.shared_secret,
            "-N", f"4:x:{nas_ip_hex}",                        # NAS-IP-Address
            "-N", f"32:s:{cfg.nas_identifier}",               # NAS-Identifier
            "-N", f"31:s:{mac_colons}",                       # Calling-Station-Id
            "-N", f"5:d:{nas_port}",                          # NAS-Port
            "-N", f"87:s:GigabitEthernet1/0/{nas_port}",      # NAS-Port-Id
            "-N", "61:d:15",                                  # NAS-Port-Type = Ethernet
            "-N", "77:s:CONNECT 1Gbps 802.3",                 # Connect-Info = wired GigE
            "-r", "0",                                        # no retries
        ]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            result.result = "timeout"
            result.detail = "eapol_test timed out after 30s — check ISE EAP-TLS policy and trusted CA"
            result.duration_ms = int((time.monotonic() - t0) * 1000)
            return result

        output = (stdout + stderr).decode(errors="replace")
        logger.debug("eapol_test EAP-TLS output:\n%s", output[-2000:])

        if "SUCCESS" in output:
            result.result = "accept"
            loop = asyncio.get_event_loop()
            framed_ip = (
                f"10.{random.randint(1,254)}.{random.randint(0,254)}"
                f".{random.randint(1,254)}"
            )
            await loop.run_in_executor(
                None,
                lambda: _send_accounting_sync(
                    cfg, "Start", mac_colons, identity, acct_session_id, nas_port,
                    auth_type="peap", framed_ip=framed_ip,
                ),
            )
            if live_session:
                _register_live_session(cfg, acct_session_id, mac_colons, identity,
                                       nas_port, "eap-tls", framed_ip=framed_ip,
                                       terminate_cause=terminate_cause)
            else:
                sess_secs = random.randint(300, 3600)
                in_oct, out_oct = _simulated_bytes("eap-tls")
                await loop.run_in_executor(
                    None,
                    lambda: _send_accounting_sync(
                        cfg, "Stop", mac_colons, identity, acct_session_id, nas_port,
                        auth_type="eap-tls", session_time_s=sess_secs,
                        input_octets=in_oct, output_octets=out_oct, framed_ip=framed_ip,
                        terminate_cause="User-Request",
                    ),
                )
        elif "FAILURE" in output:
            result.result = "reject"
            detail = ""
            for line in output.splitlines():
                low = line.lower()
                if any(kw in low for kw in ("tls alert", "certificate", "verify", "ssl_connect")):
                    detail = line.strip()
                    break
            result.detail = detail[:200] if detail else "Access-Reject from ISE"
        else:
            meaningful = [
                l.strip() for l in output.splitlines()
                if l.strip() and not l.startswith("OpenSSL")
            ]
            result.result = "error"
            result.detail = (meaningful[-1] if meaningful else output[-200:])[:200]

    except Exception as exc:
        result.result = "error"
        result.detail = str(exc)[:200]
    finally:
        if tmp_conf:
            Path(tmp_conf).unlink(missing_ok=True)

    result.duration_ms = int((time.monotonic() - t0) * 1000)
    return result


# ─── Cert helpers ─────────────────────────────────────────────────────

def list_available_certs() -> list[dict]:
    """Return metadata for all PEM files in CERTS_DIR that have a matching key."""
    from macforge.certgen import parse_cert_info
    results = []
    if not _CERTS_DIR.exists():
        return results
    for pem in sorted(_CERTS_DIR.glob("*.pem")):
        try:
            info = parse_cert_info(pem.name)
            info["key_file"] = pem.stem + ".key"
            info["has_key"] = (_CERTS_DIR / (pem.stem + ".key")).exists()
            results.append(info)
        except Exception:
            results.append({
                "filename": pem.name,
                "cn": pem.stem,
                "is_ca": False,
                "has_key": (_CERTS_DIR / (pem.stem + ".key")).exists(),
            })
    return results


# ─── RADIUS Accounting ────────────────────────────────────────────────

def _simulated_bytes(auth_type: str) -> tuple[int, int]:
    """Return (input_octets, output_octets) representative of a short session.

    MAB  → typically just DHCP + a few ARP probes (a few KB).
    PAP/PEAP → simulated user data exchange (~100 KB – 2 MB).
    Values are randomised so aggregate reports look natural.
    """
    if auth_type == "mab":
        return (random.randint(512, 8192), random.randint(1024, 16384))
    return (random.randint(65536, 2097152), random.randint(131072, 4194304))


def _send_accounting_sync(
    cfg: RADIUSNADConfig,
    status: str,
    calling_mac: str,
    username: str,
    acct_session_id: str,
    nas_port: int,
    *,
    auth_type: str = "mab",
    session_time_s: int = 0,
    input_octets: int = 0,
    output_octets: int = 0,
    framed_ip: str = "",
    profile_attrs: dict | None = None,
    terminate_cause: str = "User-Request",
) -> None:
    """Send Accounting-Request (Start or Stop) to ISE.

    Acct-Start packets for MAB sessions include subscriber:-prefixed Cisco-AVPairs
    carrying DHCP profiling data (as Cisco Device Sensor would relay from the switch).

    Stop packets include Acct-Session-Time, Acct-Input/Output-Octets,
    Acct-Terminate-Cause, and an optional Framed-IP-Address.
    """
    from pyrad import packet as ppacket
    try:
        c = _make_pyrad_client(cfg, acct=True)
        req = c.CreateAcctPacket(code=ppacket.AccountingRequest)
        req["Acct-Status-Type"] = status
        req["Acct-Session-Id"] = acct_session_id
        req["User-Name"] = username
        req["Calling-Station-Id"] = calling_mac
        req["Called-Station-Id"] = cfg.nas_identifier
        req["NAS-IP-Address"] = cfg.nas_ip or _local_ip()
        req["NAS-Identifier"] = cfg.nas_identifier
        req["NAS-Port"] = nas_port
        req["NAS-Port-Id"] = f"GigabitEthernet1/0/{nas_port}"
        req["NAS-Port-Type"] = 15   # Ethernet
        if framed_ip:
            req["Framed-IP-Address"] = framed_ip

        # Accounting-Start: inject DHCP profiling hints as subscriber: AVPairs.
        # This mirrors Cisco Device Sensor which collects DHCP options on the
        # switch and ships them to ISE in RADIUS Accounting-Start packets.
        if status == "Start" and profile_attrs:
            avpairs: list[str] = []
            vc  = profile_attrs.get("vendor_class", "")
            hn  = profile_attrs.get("hostname", "")
            prl = profile_attrs.get("param_request_list", [])
            mac_lower = calling_mac.lower().replace(":", "").replace("-", "")
            if vc:
                avpairs.append(f"subscriber:dhcp-class-identifier={vc}")
            if hn:
                avpairs.append(f"subscriber:dhcp-hostname={hn}")
            if prl:
                avpairs.append(
                    "subscriber:dhcp-parameter-request-list="
                    + ",".join(str(o) for o in prl)
                )
            # dhcp-client-identifier: 01 prefix = Ethernet hardware type
            avpairs.append(f"subscriber:dhcp-client-identifier=01:{mac_lower}")
            if avpairs:
                try:
                    req["Cisco-AVPair"] = avpairs if len(avpairs) > 1 else avpairs[0]
                except Exception:
                    pass

        if status == "Stop":
            req["Acct-Session-Time"] = session_time_s
            req["Acct-Input-Octets"] = input_octets
            req["Acct-Output-Octets"] = output_octets
            req["Acct-Terminate-Cause"] = _CAUSE_CODES.get(terminate_cause, 1)

        c.SendPacket(req)
        logger.debug("Accounting %s sent for %s", status, acct_session_id)
    except Exception:
        logger.debug("Accounting %s failed for %s", status, acct_session_id, exc_info=True)


# ─── Public async session entrypoints ────────────────────────────────

async def run_single_session(
    cfg: RADIUSNADConfig,
    auth_type: Literal["mab", "pap", "peap", "eap-tls"],
    mac: str = "",
    username: str = "",
    password: str = "",
    nas_port: int = 1,
    oui_prefix: str = "",
    # Session lifetime:
    #   -1 = immediate simulated close (Acct-Start + Acct-Stop back-to-back)
    #    0 = live until manually terminated (good for CoA testing)
    #   >0 = live for N seconds then auto-terminate
    session_lifetime_secs: int = 0,
    # EAP-TLS specific
    cert_file: str = "",
    key_file: str = "",
    validate_server_cert: bool = False,
    ise_ca_cert_file: str = "",
    # MAB profiling hints from a selected device profile
    profile_attrs: dict | None = None,
    # Termination cause for live sessions ("auto" = best-fit per trigger)
    terminate_cause: str = "auto",
    # User-defined custom RADIUS attributes
    custom_attrs: list[CustomAttr] | None = None,
) -> RADIUSSessionResult:
    """Run one auth+accounting session and record it in the log."""
    loop = asyncio.get_event_loop()
    live = (session_lifetime_secs != -1)

    _custom = custom_attrs or []
    if auth_type == "mab":
        target_mac = mac or _random_mac(oui_prefix) if oui_prefix else (mac or _random_mac())
        result = await loop.run_in_executor(
            None, _run_mab_session_sync, cfg, target_mac, nas_port, live,
            profile_attrs, terminate_cause, _custom
        )
    elif auth_type == "pap":
        result = await loop.run_in_executor(
            None, _run_pap_session_sync, cfg, username, password, nas_port,
            mac, live, terminate_cause, _custom
        )
    elif auth_type == "peap":
        result = await _run_peap_session_async(cfg, username, password, nas_port, mac,
                                               live_session=live,
                                               terminate_cause=terminate_cause,
                                               custom_attrs=_custom)
    elif auth_type == "eap-tls":
        if not cert_file or not key_file:
            r = RADIUSSessionResult(auth_type="eap-tls", timestamp=time.time())
            r.result = "error"
            r.detail = "cert_file and key_file are required for EAP-TLS"
            _session_log.appendleft(r)
            return r
        result = await _run_eaptls_session_async(
            cfg, username, cert_file, key_file, nas_port, mac,
            validate_server_cert=validate_server_cert,
            ise_ca_cert_file=ise_ca_cert_file,
            live_session=live,
            terminate_cause=terminate_cause,
            custom_attrs=_custom,
        )
    else:
        raise ValueError(f"Unknown auth_type: {auth_type!r}")

    # Schedule auto-terminate for timed live sessions
    if live and result.result == "accept" and session_lifetime_secs > 0:
        asyncio.create_task(
            _auto_terminate_after(result.acct_session_id, session_lifetime_secs)
        )

    _session_log.appendleft(result)
    return result


# ─── Bulk Runner ─────────────────────────────────────────────────────

def _random_mac(oui: str = "DE:AD:BE") -> str:
    tail = ":".join(f"{random.randint(0,255):02X}" for _ in range(3))
    return f"{oui}:{tail}"


async def run_bulk_sessions(
    cfg: RADIUSNADConfig,
    auth_type: Literal["mab", "pap", "peap", "eap-tls"],
    count: int,
    concurrency: int,
    delay_ms: int,
    base_mac: str = "",
    oui_prefix: str = "",       # e.g. "64:4E:D7" for HP printers; overrides random OUI
    username_template: str = "user{n}@lab.local",
    password: str = "",
    # EAP-TLS (bulk uses same cert for all sessions — machine/device cert scenario)
    cert_file: str = "",
    key_file: str = "",
    validate_server_cert: bool = False,
    ise_ca_cert_file: str = "",
    # Profile pool: when set, each session picks a random profile entry for
    # realistic OUI + DHCP vendor class diversity across the bulk run.
    # Each entry: {"oui": "AA:BB:CC", "vendor_class": "...", "hostname": "...", ...}
    profile_pool: list[dict] | None = None,
    # Session lifetime — same semantics as run_single_session:
    #   -1 = immediate close (Acct-Start + Stop back-to-back)
    #    0 = live until manually terminated
    #   >0 = live for N seconds then auto-terminate
    session_lifetime_secs: int = -1,
    # Termination cause applied to all sessions in this bulk run
    terminate_cause: str = "auto",
    # job_id is optional; when supplied, a BulkJob record is created and updated.
    job_id: str = "",
    job_params: dict | None = None,
    # Dictionary-based MAC cycling for MAB (overrides oui_prefix/profile_pool)
    mac_pool: list[str] | None = None,
    # Dictionary-based credential cycling for PAP/PEAP/EAP-TLS
    cred_pool: list[dict] | None = None,
    # User-defined custom RADIUS attributes (applied to every session in the bulk run)
    custom_attrs: list[CustomAttr] | None = None,
) -> None:
    """Run multiple sessions concurrently, updating _bulk_state in real time."""
    global _bulk_state

    started = time.time()
    _bulk_state.update({
        "running": True,
        "total": count,
        "accepted": 0,
        "rejected": 0,
        "errors": 0,
        "started_at": started,
        "cancelled": False,
    })

    # Create a BulkJob record for history tracking
    _load_jobs()
    jid = job_id or str(uuid.uuid4())[:8].upper()
    job = BulkJob(
        job_id=jid,
        auth_type=auth_type,
        count=count,
        status="running",
        started_at=started,
        params=job_params or {},
    )
    _jobs.appendleft(job)
    _persist_jobs()

    sem = asyncio.Semaphore(concurrency)
    loop = asyncio.get_event_loop()

    async def _one(n: int) -> None:
        if _bulk_state["cancelled"]:
            return
        async with sem:
            if _bulk_state["cancelled"]:
                return
            if delay_ms > 0:
                await asyncio.sleep(delay_ms / 1000.0)

            p_attrs: dict | None = None
            if mac_pool:
                # MAC dictionary cycling
                mac = mac_pool[n % len(mac_pool)]
            elif profile_pool:
                chosen = random.choice(profile_pool)
                mac = _random_mac(chosen["oui"])
                p_attrs = chosen
            elif base_mac:
                mac = _increment_mac(base_mac, n)
            elif oui_prefix:
                mac = _random_mac(oui_prefix)
            else:
                mac = _random_mac()

            if cred_pool:
                # Credential dictionary cycling
                cred = cred_pool[n % len(cred_pool)]
                uname = cred["username"]
                pwd = cred["password"]
            else:
                uname = username_template.format(n=n)
                pwd = password
            live = (session_lifetime_secs != -1)

            _catrs = custom_attrs or []
            if auth_type == "mab":
                result = await loop.run_in_executor(
                    None, _run_mab_session_sync, cfg, mac, n + 1, live,
                    p_attrs, terminate_cause, _catrs
                )
            elif auth_type == "pap":
                result = await loop.run_in_executor(
                    None, _run_pap_session_sync, cfg, uname, pwd, n + 1,
                    mac, live, terminate_cause, _catrs
                )
            elif auth_type == "eap-tls":
                result = await _run_eaptls_session_async(
                    cfg, uname, cert_file, key_file, n + 1, mac,
                    validate_server_cert=validate_server_cert,
                    ise_ca_cert_file=ise_ca_cert_file,
                    live_session=live,
                    terminate_cause=terminate_cause,
                    custom_attrs=_catrs,
                )
            else:
                result = await _run_peap_session_async(
                    cfg, uname, pwd, n + 1, mac, live_session=live,
                    terminate_cause=terminate_cause,
                    custom_attrs=_catrs,
                )

            # Schedule auto-terminate for timed live sessions
            if live and result.result == "accept" and session_lifetime_secs > 0:
                asyncio.create_task(
                    _auto_terminate_after(result.acct_session_id, session_lifetime_secs)
                )

            _session_log.appendleft(result)
            if result.result == "accept":
                _bulk_state["accepted"] += 1
                job.accepted += 1
            elif result.result == "reject":
                _bulk_state["rejected"] += 1
                job.rejected += 1
            else:
                _bulk_state["errors"] += 1
                job.errors += 1

    tasks = [asyncio.create_task(_one(n)) for n in range(count)]
    await asyncio.gather(*tasks, return_exceptions=True)
    _bulk_state["running"] = False

    # Finalise the job record
    job.finished_at = time.time()
    job.status = "cancelled" if _bulk_state["cancelled"] else "completed"
    _persist_jobs()


def cancel_bulk() -> None:
    _bulk_state["cancelled"] = True


def _increment_mac(base_mac: str, n: int) -> str:
    """Increment a base MAC address by n."""
    clean = base_mac.lower().replace(":", "").replace("-", "")
    val = int(clean, 16) + n
    val &= 0xFFFFFFFFFFFF
    hex_str = f"{val:012X}"
    return ":".join(hex_str[i:i+2] for i in range(0, 12, 2))


# ─── RADIUS test ─────────────────────────────────────────────────────

def test_radius_connection_sync(cfg: RADIUSNADConfig) -> dict:
    """Send a minimal Access-Request to verify RADIUS reachability.

    Uses a clearly synthetic MAC/username (DE:AD:C0:DE:00:01 / deadc0de0001)
    and a NAS-Port-Id of 'macforge-test-probe' so the entry is immediately
    recognisable in ISE live logs and reports.
    """
    from pyrad import packet as ppacket
    test_mac = "DE:AD:C0:DE:00:01"
    test_user = "deadc0de0001"
    try:
        c = _make_pyrad_client(cfg)
        c.timeout = 5
        req = c.CreateAuthPacket(code=ppacket.AccessRequest)
        req["User-Name"] = test_user
        req["User-Password"] = req.PwCrypt(test_user)
        req["Service-Type"] = 10   # Call-Check → MAB probe
        req["NAS-IP-Address"] = cfg.nas_ip or _local_ip()
        req["NAS-Identifier"] = cfg.nas_identifier
        req["NAS-Port"] = 0
        req["NAS-Port-Type"] = 15
        req["Calling-Station-Id"] = test_mac
        req["NAS-Port-Id"] = "macforge-test-probe"  # visible label in ISE logs

        reply = c.SendPacket(req)
        code_name = {
            2: "Access-Accept",
            3: "Access-Reject",
            11: "Access-Challenge",
        }.get(reply.code, f"code={reply.code}")
        return {
            "status": "ok",
            "message": f"ISE responded: {code_name} — RADIUS reachable",
        }
    except Exception as exc:
        return {"status": "error", "message": str(exc)}


# ─── CoA Listener ────────────────────────────────────────────────────

# RADIUS CoA codes
_COA_REQUEST = 43
_DISCONNECT_REQUEST = 40
_COA_ACK = 44
_COA_NAK = 45


def _build_coa_reply(request_bytes: bytes, reply_code: int,
                     shared_secret: bytes) -> bytes:
    """Build CoA-ACK or CoA-NAK for an incoming CoA/Disconnect-Request."""
    req_id = request_bytes[1]
    req_auth = request_bytes[4:20]
    length = 20
    # Build header with zero authenticator first
    header = bytes([reply_code, req_id]) + struct.pack("!H", length) + bytes(16)
    # Response Authenticator = MD5(Code+ID+Length+RequestAuth+Attrs+Secret)
    auth_input = header[:4] + req_auth + shared_secret
    auth = hashlib.md5(auth_input).digest()
    return header[:4] + auth


def _parse_radius_attrs(data: bytes) -> dict[int, list[bytes]]:
    """Parse RADIUS attribute TLVs from the attributes portion of a packet."""
    attrs: dict[int, list[bytes]] = {}
    i = 0
    while i + 2 <= len(data):
        attr_type = data[i]
        attr_len = data[i + 1]
        if attr_len < 2 or i + attr_len > len(data):
            break
        value = data[i + 2:i + attr_len]
        attrs.setdefault(attr_type, []).append(value)
        i += attr_len
    return attrs


def _decode_string_attr(value: bytes) -> str:
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        return value.hex()


class _CoAListenerProtocol(asyncio.DatagramProtocol):
    def __init__(self, shared_secret: bytes, event_queue: asyncio.Queue) -> None:
        self._secret = shared_secret
        self._queue = event_queue
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport
        logger.info("CoA listener started on UDP port")

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        if len(data) < 20:
            return
        code = data[0]
        if code not in (_COA_REQUEST, _DISCONNECT_REQUEST):
            return

        # Parse attributes to extract user/session info
        attrs = _parse_radius_attrs(data[20:])

        # Type 1 = User-Name, Type 44 = Acct-Session-Id, Type 31 = Calling-Station-Id
        username = ""
        session_id = ""
        calling_mac = ""
        for attr_type, values in attrs.items():
            if attr_type == 1:
                username = _decode_string_attr(values[0])
            elif attr_type == 44:
                session_id = _decode_string_attr(values[0])
            elif attr_type == 31:
                calling_mac = _decode_string_attr(values[0])

        event_type = "CoA-Request" if code == _COA_REQUEST else "Disconnect-Request"
        reply_code = _COA_ACK

        reply_bytes = _build_coa_reply(data, reply_code, self._secret)
        if self.transport:
            self.transport.sendto(reply_bytes, addr)

        event = CoAEvent(
            event_id=str(uuid.uuid4()),
            event_type=event_type,
            source_ip=addr[0],
            mac=calling_mac,
            session_id=session_id,
            response="CoA-ACK",
            timestamp=time.time(),
        )
        _coa_events.appendleft(event)

        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            pass

        logger.info(
            "CoA: %s from %s — MAC=%s session=%s → CoA-ACK",
            event_type, addr[0], calling_mac, session_id,
        )

        # If ISE sent a Disconnect-Request for one of our live sessions,
        # send Acct-Stop now so ISE's session cache is cleanly closed.
        if event_type == "Disconnect-Request" and session_id in _live_sessions:
            asyncio.ensure_future(
                terminate_live_session(session_id, "Admin-Reset")
            )
            logger.info(
                "CoA Disconnect-Request matched live session %s — Acct-Stop queued",
                session_id,
            )

    def error_received(self, exc: Exception) -> None:
        logger.warning("CoA listener error: %s", exc)

    def connection_lost(self, exc: Exception | None) -> None:
        logger.info("CoA listener closed")


async def start_coa_listener(cfg: RADIUSNADConfig) -> None:
    """Start the async UDP CoA listener if enabled and not already running."""
    global _coa_transport

    if not cfg.coa_enabled:
        logger.debug("CoA listener disabled in config")
        return

    if _coa_transport is not None and not _coa_transport.is_closing():
        logger.debug("CoA listener already running")
        return

    loop = asyncio.get_event_loop()
    secret = cfg.shared_secret.encode()

    try:
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _CoAListenerProtocol(secret, _coa_event_queue),
            local_addr=("0.0.0.0", cfg.coa_port),
        )
        _coa_transport = transport
        logger.info("CoA listener bound on UDP 0.0.0.0:%d", cfg.coa_port)
    except OSError as exc:
        logger.error("Cannot bind CoA listener on port %d: %s", cfg.coa_port, exc)


def stop_coa_listener() -> None:
    global _coa_transport
    if _coa_transport and not _coa_transport.is_closing():
        _coa_transport.close()
        _coa_transport = None
        logger.info("CoA listener stopped")


def restart_coa_listener(cfg: RADIUSNADConfig) -> None:
    """Schedule a CoA listener restart (stop + start) on the event loop."""
    stop_coa_listener()
    try:
        loop = asyncio.get_event_loop()
        loop.create_task(start_coa_listener(cfg))
    except RuntimeError:
        pass


# ─── ISE ERS: NAD registration ────────────────────────────────────────

def register_nad_in_ise(ise_config: Any, radius_cfg: RADIUSNADConfig) -> dict:
    """Create a Network Device entry in ISE via ERS API."""
    import urllib.request
    import urllib.error
    import ssl as _ssl
    import base64

    if not ise_config.hostname:
        return {"status": "error", "message": "ISE REST not configured"}

    nas_ip = radius_cfg.nas_ip or _local_ip()
    secret = radius_cfg.shared_secret
    name = radius_cfg.nas_identifier or "macforge-nad"

    payload = json.dumps({
        "NetworkDevice": {
            "name": name,
            "description": "MACforge NAD emulator — auto-registered",
            "authenticationSettings": {
                "radiusSharedSecret": secret,
                "enableKeyWrap": False,
            },
            "NetworkDeviceIPList": [
                {"ipaddress": nas_ip, "mask": 32}
            ],
        }
    }).encode()

    credentials = base64.b64encode(
        f"{ise_config.username}:{ise_config.password}".encode()
    ).decode()
    url = f"https://{ise_config.hostname}:9060/ers/config/networkdevice"

    ctx = _ssl.create_default_context()
    if not ise_config.verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE

    req = urllib.request.Request(
        url,
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Basic {credentials}",
        },
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            loc = resp.headers.get("Location", "")
            device_id = loc.rstrip("/").split("/")[-1] if loc else ""
            _save_registered_nad_id(device_id)
            return {
                "status": "ok",
                "message": f"Network Device '{name}' registered in ISE (IP: {nas_ip})",
                "device_id": device_id,
            }
    except urllib.error.HTTPError as exc:
        body = exc.read(512).decode(errors="replace")
        if exc.code == 409:
            return {"status": "error", "message": f"Network Device already exists: {body[:200]}"}
        return {"status": "error", "message": f"ISE ERS HTTP {exc.code}: {body[:200]}"}
    except Exception as exc:
        return {"status": "error", "message": str(exc)}


def remove_nad_from_ise(ise_config: Any, radius_cfg: RADIUSNADConfig) -> dict:
    """Delete the auto-registered Network Device from ISE via ERS API."""
    import urllib.request
    import urllib.error
    import ssl as _ssl
    import base64

    if not ise_config.hostname:
        return {"status": "error", "message": "ISE REST not configured"}

    device_id = _load_registered_nad_id()
    if not device_id:
        return {"status": "error", "message": "No auto-registered NAD ID found — delete manually from ISE"}

    credentials = base64.b64encode(
        f"{ise_config.username}:{ise_config.password}".encode()
    ).decode()
    url = f"https://{ise_config.hostname}:9060/ers/config/networkdevice/{device_id}"

    ctx = _ssl.create_default_context()
    if not ise_config.verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE

    req = urllib.request.Request(
        url,
        method="DELETE",
        headers={
            "Accept": "application/json",
            "Authorization": f"Basic {credentials}",
        },
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10):
            _save_registered_nad_id("")
            return {"status": "ok", "message": "Network Device removed from ISE"}
    except urllib.error.HTTPError as exc:
        body = exc.read(256).decode(errors="replace")
        return {"status": "error", "message": f"ISE ERS HTTP {exc.code}: {body[:200]}"}
    except Exception as exc:
        return {"status": "error", "message": str(exc)}


_NAD_ID_PATH = DATA_DIR / "radius_nad_device_id.txt"


def _save_registered_nad_id(device_id: str) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    _NAD_ID_PATH.write_text(device_id)


def _load_registered_nad_id() -> str:
    try:
        return _NAD_ID_PATH.read_text().strip() if _NAD_ID_PATH.exists() else ""
    except Exception:
        return ""
