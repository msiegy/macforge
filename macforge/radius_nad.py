"""RADIUS NAD Emulator for MACforge.

Emulates a RADIUS Network Access Device (NAS/switch), sending
authentication and accounting packets directly to ISE without a
physical or virtual NAD.

Supported auth flows:
  - MAB   – MAC Authentication Bypass (pyrad, pure Python)
  - PAP   – Password Authentication Protocol (pyrad, pure Python)
  - PEAP  – EAP-PEAP-MSCHAPv2 via eapol_test subprocess

All flows include a full Accounting Start/Stop lifecycle.
CoA listener (UDP :3799) receives ISE-initiated reauth/disconnect.
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
EAPOL_TEST_BIN = shutil.which("eapol_test") or "/usr/local/bin/eapol_test"

# ─── Config Model ────────────────────────────────────────────────────


class RADIUSNADConfig(BaseModel):
    ise_radius_ip: str = ""
    radius_port: int = 1812
    acct_port: int = 1813
    shared_secret: str = ""
    nas_ip: str = ""
    nas_identifier: str = "macforge-nad"
    coa_port: int = 3799
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


# ─── Session Models ───────────────────────────────────────────────────


class RADIUSSessionResult(BaseModel):
    session_id: str = ""
    auth_type: Literal["mab", "pap", "peap"] = "mab"
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


def get_session_log() -> list[RADIUSSessionResult]:
    return list(_session_log)


def clear_session_log() -> None:
    _session_log.clear()


def get_coa_events() -> list[CoAEvent]:
    return list(_coa_events)


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

def _make_pyrad_client(cfg: RADIUSNADConfig, acct: bool = False):
    """Create a pyrad UDP client targeting ISE."""
    try:
        import pyrad
        from pyrad import client as pclient, dictionary as pdict
    except ImportError as exc:
        raise RuntimeError("pyrad is not installed — rebuild the Docker image") from exc

    # pyrad ships a standard RADIUS dictionary inside its package directory.
    # Dictionary() with no args creates an EMPTY dict — attributes wouldn't resolve.
    pkg_dir = Path(pyrad.__file__).parent
    dict_file = pkg_dir / "dictionary"
    if dict_file.exists():
        radius_dict = pdict.Dictionary(str(dict_file))
    else:
        # Fallback: try loading without a file (attributes will need integer keys)
        logger.warning("pyrad dictionary file not found at %s — attribute names may not resolve", dict_file)
        radius_dict = pdict.Dictionary()

    c = pclient.Client(
        server=cfg.ise_radius_ip,
        authport=cfg.radius_port,
        acctport=cfg.acct_port,
        secret=cfg.shared_secret.encode(),
        dict=radius_dict,
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
                           nas_port: int) -> RADIUSSessionResult:
    """Send a MAB Access-Request to ISE (synchronous)."""
    from pyrad import packet as ppacket

    mac_clean = mac.lower().replace(":", "").replace("-", "")
    mac_colons = ":".join(mac_clean[i:i+2] for i in range(0, 12, 2))
    acct_session_id = str(uuid.uuid4())[:8].upper()

    result = RADIUSSessionResult(
        session_id=str(uuid.uuid4()),
        auth_type="mab",
        mac=mac_colons,
        username=mac_clean,
        acct_session_id=acct_session_id,
        timestamp=time.time(),
    )

    t0 = time.monotonic()
    try:
        c = _make_pyrad_client(cfg)
        req = c.CreateAuthPacket(code=ppacket.AccessRequest)
        req["User-Name"] = mac_clean
        req["User-Password"] = req.PwCrypt(mac_clean)
        req["Service-Type"] = 10    # Call-Check (MAB indicator for ISE)
        _fill_nas_attrs(req, cfg, nas_port, mac_colons, cfg.nas_identifier)

        reply = c.SendPacket(req)

        if reply.code == ppacket.AccessAccept:
            result.result = "accept"
            _send_accounting_sync(cfg, "Start", mac_colons, mac_clean,
                                  acct_session_id, nas_port)
            _send_accounting_sync(cfg, "Stop", mac_colons, mac_clean,
                                  acct_session_id, nas_port)
        elif reply.code == ppacket.AccessReject:
            result.result = "reject"
            # Extract Reply-Message if present
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
                           mac: str = "") -> RADIUSSessionResult:
    """Send a PAP Access-Request to ISE (synchronous)."""
    from pyrad import packet as ppacket

    mac_colons = mac or "00:00:00:00:00:00"
    acct_session_id = str(uuid.uuid4())[:8].upper()

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
        req["Service-Type"] = 1   # Login
        _fill_nas_attrs(req, cfg, nas_port, mac_colons, cfg.nas_identifier)

        reply = c.SendPacket(req)

        if reply.code == ppacket.AccessAccept:
            result.result = "accept"
            _send_accounting_sync(cfg, "Start", mac_colons, username,
                                  acct_session_id, nas_port)
            _send_accounting_sync(cfg, "Stop", mac_colons, username,
                                  acct_session_id, nas_port)
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
                                   mac: str = "") -> RADIUSSessionResult:
    """Run EAP-PEAP-MSCHAPv2 via eapol_test subprocess."""
    mac_colons = mac or "00:00:00:00:00:00"
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
        cmd = [
            EAPOL_TEST_BIN,
            "-c", tmp_conf,
            "-a", cfg.ise_radius_ip,
            "-p", str(cfg.radius_port),
            "-s", cfg.shared_secret,
            "-N", f"4:s:{nas_ip}",          # NAS-IP-Address
            "-N", f"32:s:{cfg.nas_identifier}",  # NAS-Identifier
            "-N", f"31:s:{mac_colons}",     # Calling-Station-Id
            "-N", f"5:d:{nas_port}",        # NAS-Port
            "-N", "61:d:15",                # NAS-Port-Type = Ethernet
            "-t", "15",                     # timeout seconds
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

        if "SUCCESS" in output:
            result.result = "accept"
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                _send_accounting_sync,
                cfg, "Start", mac_colons, username, acct_session_id, nas_port,
            )
            await loop.run_in_executor(
                None,
                _send_accounting_sync,
                cfg, "Stop", mac_colons, username, acct_session_id, nas_port,
            )
        elif "FAILURE" in output:
            result.result = "reject"
            # Try to extract a reason from the log
            for line in output.splitlines():
                if "EAP:" in line or "error" in line.lower():
                    result.detail = line.strip()[:200]
                    break
        else:
            result.result = "error"
            result.detail = output[-400:].strip()

    except Exception as exc:
        result.result = "error"
        result.detail = str(exc)[:200]
    finally:
        if tmp_conf:
            Path(tmp_conf).unlink(missing_ok=True)

    result.duration_ms = int((time.monotonic() - t0) * 1000)
    return result


# ─── RADIUS Accounting ────────────────────────────────────────────────

def _send_accounting_sync(cfg: RADIUSNADConfig, status: str,
                           calling_mac: str, username: str,
                           acct_session_id: str, nas_port: int) -> None:
    """Send Accounting-Request (Start or Stop) to ISE."""
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
        req["NAS-Port-Type"] = 15
        if status == "Stop":
            req["Acct-Session-Time"] = 5
        c.SendPacket(req)
        logger.debug("Accounting %s sent for %s", status, acct_session_id)
    except Exception:
        logger.debug("Accounting %s failed for %s", status, acct_session_id, exc_info=True)


# ─── Public async session entrypoints ────────────────────────────────

async def run_single_session(
    cfg: RADIUSNADConfig,
    auth_type: Literal["mab", "pap", "peap"],
    mac: str = "",
    username: str = "",
    password: str = "",
    nas_port: int = 1,
) -> RADIUSSessionResult:
    """Run one auth+accounting session and record it in the log."""
    loop = asyncio.get_event_loop()

    if auth_type == "mab":
        target_mac = mac or _random_mac()
        result = await loop.run_in_executor(
            None, _run_mab_session_sync, cfg, target_mac, nas_port
        )
    elif auth_type == "pap":
        result = await loop.run_in_executor(
            None, _run_pap_session_sync, cfg, username, password, nas_port, mac
        )
    elif auth_type == "peap":
        result = await _run_peap_session_async(cfg, username, password, nas_port, mac)
    else:
        raise ValueError(f"Unknown auth_type: {auth_type!r}")

    _session_log.appendleft(result)
    return result


# ─── Bulk Runner ─────────────────────────────────────────────────────

def _random_mac(oui: str = "DE:AD:BE") -> str:
    tail = ":".join(f"{random.randint(0,255):02X}" for _ in range(3))
    return f"{oui}:{tail}"


async def run_bulk_sessions(
    cfg: RADIUSNADConfig,
    auth_type: Literal["mab", "pap", "peap"],
    count: int,
    concurrency: int,
    delay_ms: int,
    base_mac: str = "",
    username_template: str = "user{n}@lab.local",
    password: str = "",
) -> None:
    """Run multiple sessions concurrently, updating _bulk_state in real time."""
    global _bulk_state

    _bulk_state.update({
        "running": True,
        "total": count,
        "accepted": 0,
        "rejected": 0,
        "errors": 0,
        "started_at": time.time(),
        "cancelled": False,
    })

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

            mac = _random_mac() if not base_mac else _increment_mac(base_mac, n)
            uname = username_template.format(n=n)

            if auth_type == "mab":
                result = await loop.run_in_executor(
                    None, _run_mab_session_sync, cfg, mac, n + 1
                )
            elif auth_type == "pap":
                result = await loop.run_in_executor(
                    None, _run_pap_session_sync, cfg, uname, password, n + 1, mac
                )
            else:
                result = await _run_peap_session_async(cfg, uname, password, n + 1, mac)

            _session_log.appendleft(result)
            if result.result == "accept":
                _bulk_state["accepted"] += 1
            elif result.result == "reject":
                _bulk_state["rejected"] += 1
            else:
                _bulk_state["errors"] += 1

    tasks = [asyncio.create_task(_one(n)) for n in range(count)]
    await asyncio.gather(*tasks, return_exceptions=True)
    _bulk_state["running"] = False


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
    """Send a minimal Access-Request to check reachability. Uses an unlikely MAC."""
    from pyrad import packet as ppacket
    test_mac = "de:ad:be:ef:00:01"
    try:
        c = _make_pyrad_client(cfg)
        c.timeout = 5
        req = c.CreateAuthPacket(code=ppacket.AccessRequest)
        req["User-Name"] = "deadbeef0001"
        req["User-Password"] = req.PwCrypt("deadbeef0001")
        req["Service-Type"] = 10
        req["NAS-IP-Address"] = cfg.nas_ip or _local_ip()
        req["NAS-Identifier"] = cfg.nas_identifier
        req["NAS-Port"] = 0
        req["NAS-Port-Type"] = 15
        req["Calling-Station-Id"] = test_mac

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
