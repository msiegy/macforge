"""FastAPI web application for MACforge runtime control."""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from macforge.radius_nad import (
    RADIUSNADConfig,
    RADIUSSessionResult,
    cancel_bulk,
    clear_session_log,
    export_sessions_csv,
    get_bulk_state,
    get_coa_events,
    get_session_log,
    load_radius_nad_config,
    register_nad_in_ise,
    remove_nad_from_ise,
    restart_coa_listener,
    run_bulk_sessions,
    run_single_session,
    save_radius_nad_config,
    start_coa_listener,
    test_radius_connection_sync,
    _coa_event_queue,
)
from macforge.certgen import (
    generate_client_cert,
    generate_csr,
    generate_lab_ca,
    get_lab_ca_info,
    parse_cert_info,
)
from macforge.dot1x import (
    CERTS_DIR,
    DATA_DIR,
    delete_cert,
    list_certs,
    save_cert_paste,
    save_cert_upload,
)
from macforge.ise_api import (
    ISEConfig,
    load_ise_config,
    push_trusted_cert,
    save_ise_config,
    test_connection as ise_test_connection,
)
from macforge.models import (
    AuthProfile,
    CoARequest,
    DeviceCreatePayload,
    DeviceEditPayload,
    DeviceProfile,
    DeviceState,
    DeviceStatus,
    PacketLogEntry,
    PingResult,
)
from macforge.orchestrator import Orchestrator
from macforge.profiles import generate_mac, get_oui_table, get_seed_fingerprint
from macforge.dot1x import check_wpa_supplicant_version
from macforge.scep_client import (
    enroll_via_scep,
    enroll_via_step_ca,
    get_enrollment_capabilities,
)

logger = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).parent / "static"
AUTH_CONFIG_PATH = DATA_DIR / "auth_config.json"
CUSTOM_DEVICES_PATH = DATA_DIR / "custom_devices.json"

app = FastAPI(title="MACforge", version="0.2.0")

_orchestrator: Orchestrator | None = None


@app.on_event("startup")
async def _startup_checks() -> None:
    """Run pre-flight diagnostics on server start."""
    await check_wpa_supplicant_version()
    # Start CoA listener if enabled in saved config
    cfg = load_radius_nad_config()
    if cfg.coa_enabled and cfg.ise_radius_ip and cfg.shared_secret:
        asyncio.create_task(start_coa_listener(cfg))


def set_orchestrator(orch: Orchestrator) -> None:
    global _orchestrator
    _orchestrator = orch
    _load_custom_devices(orch)
    _load_auth_config(orch)


def _get_orch() -> Orchestrator:
    if _orchestrator is None:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    return _orchestrator


def _load_auth_config(orch: Orchestrator) -> None:
    """Load persisted auth configs and overlay onto device profiles."""
    if not AUTH_CONFIG_PATH.exists():
        return
    try:
        data = json.loads(AUTH_CONFIG_PATH.read_text())
        meta = data.pop("__meta__", {})
        if meta.get("data_interface"):
            orch.interface = meta["data_interface"]
            logger.info("Restored data interface: %s", orch.interface)
        for mac, auth_data in data.items():
            device = orch.devices.get(mac)
            if device:
                device.profile.auth = AuthProfile(**auth_data)
                logger.info("Loaded auth config for %s", mac)
    except Exception:
        logger.exception("Failed to load auth config from %s", AUTH_CONFIG_PATH)


def _save_auth_config(orch: Orchestrator) -> None:
    """Persist auth configs for all devices that have them."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    data: dict = {"__meta__": {"data_interface": orch.interface}}
    for mac, device in orch.devices.items():
        if device.profile.auth:
            data[mac] = device.profile.auth.model_dump()
    AUTH_CONFIG_PATH.write_text(json.dumps(data, indent=2))


def _load_custom_devices(orch: Orchestrator) -> None:
    """Load custom devices and profile overrides from persistent storage."""
    if not CUSTOM_DEVICES_PATH.exists():
        return
    try:
        data = json.loads(CUSTOM_DEVICES_PATH.read_text())
        for mac, dev_data in data.get("devices", {}).items():
            if mac not in orch.devices:
                profile = DeviceProfile(**dev_data)
                orch.add_device(profile, is_custom=True)
                logger.info("Loaded custom device: %s (%s)", profile.name, mac)
        for mac, overrides in data.get("overrides", {}).items():
            device = orch.devices.get(mac)
            if device:
                if "name" in overrides:
                    device.profile.name = overrides["name"]
                if "personality" in overrides:
                    device.profile.personality = device.profile.personality.model_copy(
                        update=overrides["personality"]
                    )
                if "dhcp" in overrides:
                    device.profile.dhcp = device.profile.dhcp.model_copy(
                        update=overrides["dhcp"]
                    )
                if "traffic_interval_sec" in overrides:
                    device.profile.traffic_interval_sec = overrides["traffic_interval_sec"]
                device.has_overrides = True
                logger.info("Applied overrides for %s", mac)
    except Exception:
        logger.exception("Failed to load custom devices from %s", CUSTOM_DEVICES_PATH)


def _save_custom_devices(orch: Orchestrator) -> None:
    """Persist custom devices and overrides for YAML-origin edits."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    devices_data = {}
    overrides_data = {}
    for mac, device in orch.devices.items():
        if device.is_custom:
            devices_data[mac] = device.profile.model_dump()
        elif device.has_overrides:
            overrides_data[mac] = {
                "name": device.profile.name,
                "personality": device.profile.personality.model_dump(),
                "dhcp": device.profile.dhcp.model_dump(),
                "traffic_interval_sec": device.profile.traffic_interval_sec,
            }
    CUSTOM_DEVICES_PATH.write_text(json.dumps(
        {"devices": devices_data, "overrides": overrides_data},
        indent=2,
    ))


# ─── Pages ───────────────────────────────────────────────────────────

@app.get("/")
async def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/touch")
async def touch_ui():
    return FileResponse(STATIC_DIR / "touch" / "index.html")


# ─── Device CRUD ─────────────────────────────────────────────────────

@app.get("/api/devices", response_model=list[DeviceStatus])
async def list_devices():
    return _get_orch().get_all_status()


@app.post("/api/devices/connect-all")
async def connect_all():
    orch = _get_orch()
    stopped = [
        m for m, d in orch.devices.items()
        if d.state.value in ("stopped", "auth_failed")
    ]
    if stopped:
        asyncio.create_task(orch.connect_all())
    return {"status": "connecting", "count": len(stopped)}


@app.post("/api/devices/disconnect-all")
async def disconnect_all():
    orch = _get_orch()
    active = [
        m for m, d in orch.devices.items()
        if d.state.value in ("online", "connecting", "authenticating", "authorized", "auth_failed")
    ]
    if active:
        asyncio.create_task(orch.disconnect_all())
    return {"status": "disconnecting", "count": len(active)}


@app.get("/api/devices/{mac}", response_model=DeviceStatus)
async def get_device(mac: str):
    mac = mac.replace("-", ":")
    status = _get_orch().get_device_status(mac)
    if not status:
        raise HTTPException(status_code=404, detail="Device not found")
    return status


@app.post("/api/devices/{mac}/connect")
async def connect_device(mac: str):
    mac = mac.replace("-", ":")
    orch = _get_orch()
    device = orch.devices.get(mac)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    # Set transitional state synchronously so the next GET /api/devices
    # (called by the JS refreshAll immediately after this POST) returns the
    # correct in-progress state rather than STOPPED.
    # The background task will overwrite this with AUTHENTICATING / CONNECTING
    # as it progresses.
    from macforge.models import DeviceState
    if device.state in (DeviceState.STOPPED, DeviceState.AUTH_FAILED):
        device.state = DeviceState.AUTHENTICATING if device.profile.auth else DeviceState.CONNECTING
        device.status_detail = "Starting…"
        device.error_message = None
    asyncio.create_task(orch.connect_device(mac))
    return {"status": "connecting", "mac": mac}


@app.post("/api/devices/{mac}/disconnect")
async def disconnect_device(mac: str):
    mac = mac.replace("-", ":")
    orch = _get_orch()
    device = orch.devices.get(mac)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    asyncio.create_task(orch.disconnect_device(mac))
    return {"status": "disconnecting", "mac": mac}


@app.post("/api/devices/{mac}/ping")
async def ping_device(mac: str, target: str | None = None, count: int = 4):
    mac = mac.replace("-", ":")
    orch = _get_orch()
    device = orch.devices.get(mac)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    # Resolve target early and set pending state synchronously so the next
    # GET /api/devices immediately shows the spinner with the correct target.
    from macforge.models import PingResult as _PingResult
    ping_target = target or device.gateway_ip or ""
    device.last_ping = _PingResult(target=ping_target, pending=True)
    asyncio.create_task(orch.ping_device(mac, target=target, count=min(count, 10)))
    return {"status": "pinging", "target": ping_target}


@app.get("/api/devices/{mac}/auth-flow")
async def get_auth_flow(mac: str):
    """Return parsed EAP auth flow events for a device (from most recent auth attempt)."""
    mac = mac.replace("-", ":")
    orch = _get_orch()
    device = orch.devices.get(mac)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    if not device.profile.auth:
        raise HTTPException(status_code=404, detail="Device has no 802.1X configuration")
    return [e.model_dump() for e in device.auth_flow_events]


@app.get("/api/devices/{mac}/dot1x-log")
async def get_dot1x_log(mac: str):
    """Return the raw wpa_supplicant log text for a device."""
    mac = mac.replace("-", ":")
    orch = _get_orch()
    device = orch.devices.get(mac)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    if not device.profile.auth:
        raise HTTPException(status_code=404, detail="Device has no 802.1X configuration")
    from macforge.dot1x import WPA_RUN_DIR, _safe_iface_name
    iface_name = _safe_iface_name(mac)
    # Try active log first, then lastfail copy
    for candidate in [
        WPA_RUN_DIR / f"{iface_name}.log",
        WPA_RUN_DIR / f"{iface_name}_lastfail.log",
    ]:
        if candidate.exists():
            return {"log": candidate.read_text(errors="replace"), "source": candidate.name}
    raise HTTPException(status_code=404, detail="No wpa_supplicant log available for this device")


@app.get("/api/devices/{mac}/ise-session")
async def get_ise_session(mac: str):
    """Fetch active RADIUS session data from ISE MnT API for a device.

    Tries MAC address lookup first. If not found and the device has a configured
    identity (username), falls back to username lookup.
    """
    mac = mac.replace("-", ":")
    orch = _get_orch()
    device = orch.devices.get(mac)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    from macforge.ise_api import load_ise_config, get_session_by_mac, get_session_by_username
    config = load_ise_config()
    if not config.hostname:
        return {"status": "error", "message": "ISE not configured — add hostname in the Certificates tab"}
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, get_session_by_mac, config, mac)
    # If MAC lookup returned not_found and device has a username identity, try that
    if result.get("status") == "not_found" and device.profile.auth and device.profile.auth.identity:
        identity = device.profile.auth.identity
        result2 = await loop.run_in_executor(None, get_session_by_username, config, identity)
        if result2.get("status") == "ok":
            return result2
    return result


@app.get("/api/devices/{mac}/ise-endpoint")
async def get_ise_endpoint(mac: str):
    """Fetch endpoint profiling record from ISE ERS API for a device."""
    mac = mac.replace("-", ":")
    orch = _get_orch()
    if mac not in orch.devices:
        raise HTTPException(status_code=404, detail="Device not found")
    from macforge.ise_api import load_ise_config, get_endpoint_by_mac
    config = load_ise_config()
    if not config.hostname:
        return {"status": "error", "message": "ISE not configured — add hostname in the Certificates tab"}
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, get_endpoint_by_mac, config, mac)


@app.get("/api/devices/{mac}/ise-history")
async def get_ise_history(mac: str, limit: int = 10):
    """Fetch recent ISE authentication history for a device."""
    mac = mac.replace("-", ":")
    orch = _get_orch()
    if mac not in orch.devices:
        raise HTTPException(status_code=404, detail="Device not found")
    from macforge.ise_api import load_ise_config, get_auth_history
    config = load_ise_config()
    if not config.hostname:
        return {"status": "error", "message": "ISE not configured — add hostname in the Certificates tab"}
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: get_auth_history(config, mac, limit))


@app.post("/api/devices/{mac}/coa")
async def send_device_coa(mac: str, payload: CoARequest):
    """Send Change of Authorization (CoA) to ISE for a device.

    Actions:
      reauth | disconnect | port_bounce — MAC-based session CoA (no session ID needed)
      anc:<policy_name>                 — apply ANC policy
      anc-clear                         — remove ANC policy
    """
    mac = mac.replace("-", ":")
    orch = _get_orch()
    if mac not in orch.devices:
        raise HTTPException(status_code=404, detail="Device not found")

    from macforge.ise_api import (
        load_ise_config, send_coa as _send_coa,
        apply_anc_policy, clear_anc_policy,
    )
    config = load_ise_config()
    if not config.hostname:
        return {"status": "error", "message": "ISE not configured — add hostname in the Certificates tab"}

    loop = asyncio.get_event_loop()

    # ANC clear
    if payload.action == "anc-clear":
        return await loop.run_in_executor(None, lambda: clear_anc_policy(config, mac))

    # ANC apply — action prefix "anc:<policy_name>"
    if payload.action.startswith("anc:"):
        policy_name = payload.action[4:].strip()
        if not policy_name:
            return {"status": "error", "message": "ANC action requires a policy name: anc:<policy_name>"}
        return await loop.run_in_executor(None, lambda: apply_anc_policy(config, mac, policy_name))

    # Session CoA: reauth / disconnect / port_bounce (MAC-based, no session ID needed)
    if payload.action not in ("reauth", "disconnect", "port_bounce"):
        raise HTTPException(
            status_code=400,
            detail="action must be: reauth, disconnect, port_bounce, anc:<policy>, anc-clear",
        )
    return await loop.run_in_executor(None, lambda: _send_coa(config, mac, payload.action))


@app.get("/api/ise/anc-policies")
async def get_ise_anc_policies():
    """Fetch available ANC policies from ISE ERS."""
    from macforge.ise_api import load_ise_config, get_anc_policies
    config = load_ise_config()
    if not config.hostname:
        return {"status": "error", "message": "ISE not configured"}
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: get_anc_policies(config))


# ── Phase 5: Packet Inspector ────────────────────────────────────────────────

@app.get("/api/devices/{mac}/packets")
async def get_device_packets(mac: str, limit: int = 200):
    """Return the per-device captured packet ring buffer (JSON, no raw bytes)."""
    mac = mac.replace("-", ":")
    orch = _get_orch()
    device = orch.devices.get(mac)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    entries = list(device.capture_log)[:limit]
    # Exclude raw_bytes from JSON response (binary, large, only used for pcap)
    return [e.model_dump(exclude={"raw_bytes"}) for e in entries]


@app.get("/api/devices/{mac}/packets/download")
async def download_device_pcap(mac: str):
    """Stream a pcap file of captured packets for opening in Wireshark."""
    import io
    mac = mac.replace("-", ":")
    orch = _get_orch()
    device = orch.devices.get(mac)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    entries = [e for e in device.capture_log if e.raw_bytes]
    if not entries:
        raise HTTPException(status_code=404, detail="No captured packets with raw data")

    try:
        from scapy.all import Ether, wrpcap
        pkts = []
        for e in reversed(entries):  # oldest first
            try:
                pkts.append(Ether(e.raw_bytes))
            except Exception:
                pass

        buf = io.BytesIO()
        wrpcap(buf, pkts)
        raw = buf.getvalue()   # read out before wrpcap closes the buffer

        safe_name = device.profile.mac.replace(":", "")
        filename = f"macforge_{safe_name}.pcap"
        return StreamingResponse(
            io.BytesIO(raw),
            media_type="application/vnd.tcpdump.pcap",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"pcap generation failed: {exc}") from exc


@app.post("/api/devices/{mac}/capture/start")
async def start_device_capture(mac: str):
    """Start per-device packet capture sniffer."""
    mac = mac.replace("-", ":")
    orch = _get_orch()
    return orch.start_capture(mac)


@app.post("/api/devices/{mac}/capture/stop")
async def stop_device_capture(mac: str):
    """Stop per-device packet capture sniffer."""
    mac = mac.replace("-", ":")
    orch = _get_orch()
    return orch.stop_capture(mac)


# ── Phase 3: NAD Probe (Cisco IOS/IOS-XE via SSH) ───────────────────────────

@app.get("/api/nad/config")
async def get_nad_config():
    """Return the saved NAD SSH connection settings."""
    from macforge.nad_probe import load_nad_config
    return load_nad_config()


@app.put("/api/nad/config")
async def set_nad_config(payload: dict):
    """Persist NAD SSH connection settings to nad_config.json."""
    from macforge.nad_probe import save_nad_config
    # Only accept the expected fields
    allowed = {"host", "port", "username", "password", "enable_password", "device_type"}
    clean = {k: v for k, v in payload.items() if k in allowed}
    save_nad_config(clean)
    return {"status": "ok"}


@app.post("/api/devices/{mac}/nad-probe")
async def nad_probe_device(mac: str):
    """SSH into the configured NAD and query port state for the given device."""
    mac = mac.replace("-", ":")
    orch = _get_orch()
    if mac not in orch.devices:
        raise HTTPException(status_code=404, detail="Device not found")
    from macforge.nad_probe import probe_nad
    return await probe_nad(mac)


@app.post("/api/devices", response_model=DeviceStatus)
async def create_device(payload: DeviceCreatePayload):
    orch = _get_orch()
    mac = payload.mac.strip()
    if not mac:
        mac = generate_mac(
            set(orch.devices.keys()),
            category=payload.personality.category,
            oui_hint=payload.oui_hint.strip(),
            seed=orch.seed,
        )
    mac = mac.upper().replace("-", ":")
    if mac in orch.devices:
        raise HTTPException(status_code=409, detail=f"MAC {mac} already exists")
    profile = DeviceProfile(
        name=payload.name,
        mac=mac,
        personality=payload.personality,
        dhcp=payload.dhcp,
        auth=payload.auth,
        traffic_interval_sec=payload.traffic_interval_sec,
    )
    device = orch.add_device(profile, is_custom=True)
    _save_custom_devices(orch)
    _save_auth_config(orch)
    return device.to_status()


@app.put("/api/devices/{mac}", response_model=DeviceStatus)
async def edit_device(mac: str, payload: DeviceEditPayload):
    mac = mac.replace("-", ":")
    orch = _get_orch()
    device = orch.devices.get(mac)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    if device.state not in (DeviceState.STOPPED, DeviceState.AUTH_FAILED):
        raise HTTPException(status_code=409, detail="Device must be stopped to edit")
    if payload.name is not None:
        device.profile.name = payload.name
    if payload.personality is not None:
        device.profile.personality = payload.personality
    if payload.dhcp is not None:
        device.profile.dhcp = payload.dhcp
    if payload.traffic_interval_sec is not None:
        device.profile.traffic_interval_sec = payload.traffic_interval_sec
    if not device.is_custom:
        device.has_overrides = True
    _save_custom_devices(orch)
    logger.info("Edited device %s: name=%s", mac, device.profile.name)
    return device.to_status()


@app.post("/api/devices/{mac}/clone", response_model=DeviceStatus)
async def clone_device(mac: str):
    mac = mac.replace("-", ":")
    orch = _get_orch()
    source = orch.devices.get(mac)
    if not source:
        raise HTTPException(status_code=404, detail="Device not found")
    source_oui = ":".join(source.profile.mac.split(":")[:3])
    new_mac = generate_mac(set(orch.devices.keys()), oui_hint=source_oui,
                           seed=orch.seed)
    clone_data = source.profile.model_dump()
    clone_data["mac"] = new_mac
    clone_data["name"] = source.profile.name + " (Copy)"
    profile = DeviceProfile(**clone_data)
    device = orch.add_device(profile, is_custom=True)
    _save_custom_devices(orch)
    _save_auth_config(orch)
    return device.to_status()


@app.delete("/api/devices/{mac}")
async def delete_device(mac: str):
    mac = mac.replace("-", ":")
    orch = _get_orch()
    device = orch.devices.get(mac)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    if not device.is_custom:
        raise HTTPException(status_code=403, detail="Cannot delete YAML-loaded devices")
    if device.state not in (DeviceState.STOPPED, DeviceState.AUTH_FAILED):
        raise HTTPException(status_code=409, detail="Device must be stopped to delete")
    orch.remove_device(mac)
    _save_custom_devices(orch)
    _save_auth_config(orch)
    return {"status": "deleted", "mac": mac}


# ─── Auth Config ─────────────────────────────────────────────────────

@app.get("/api/devices/{mac}/auth")
async def get_device_auth(mac: str):
    mac = mac.replace("-", ":")
    orch = _get_orch()
    device = orch.devices.get(mac)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    if not device.profile.auth:
        return None
    return device.profile.auth.model_dump()


@app.put("/api/devices/{mac}/auth")
async def update_device_auth(mac: str, auth: AuthProfile):
    mac = mac.replace("-", ":")
    orch = _get_orch()
    device = orch.devices.get(mac)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    if device.state not in (DeviceState.STOPPED, DeviceState.AUTH_FAILED):
        raise HTTPException(
            status_code=409,
            detail="Device must be stopped to change auth config",
        )
    device.profile.auth = auth
    _save_auth_config(orch)
    logger.info("Updated auth config for %s: method=%s", mac, auth.method)
    return device.profile.auth.model_dump()


@app.delete("/api/devices/{mac}/auth")
async def delete_device_auth(mac: str):
    mac = mac.replace("-", ":")
    orch = _get_orch()
    device = orch.devices.get(mac)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    if device.state not in (DeviceState.STOPPED, DeviceState.AUTH_FAILED):
        raise HTTPException(
            status_code=409,
            detail="Device must be stopped to change auth config",
        )
    device.profile.auth = None
    _save_auth_config(orch)
    logger.info("Removed auth config for %s (reverted to MAB)", mac)
    return {"status": "removed", "mac": mac}


# ─── Certificate Management ─────────────────────────────────────────

@app.get("/api/certs")
async def get_certs():
    return list_certs()


@app.post("/api/certs/upload")
async def upload_cert(file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")
    content = await file.read()
    if len(content) > 100_000:
        raise HTTPException(status_code=413, detail="File too large (max 100KB)")
    saved = save_cert_upload(file.filename, content)
    return {"filename": saved, "size": len(content)}


class CertPastePayload(BaseModel):
    filename: str
    content: str


@app.post("/api/certs/paste")
async def paste_cert(payload: CertPastePayload):
    if not payload.filename:
        raise HTTPException(status_code=400, detail="Filename required")
    if len(payload.content) > 100_000:
        raise HTTPException(status_code=413, detail="Content too large (max 100KB)")
    saved = save_cert_paste(payload.filename, payload.content)
    return {"filename": saved, "size": len(payload.content)}


@app.delete("/api/certs/{filename}")
async def remove_cert(filename: str):
    if delete_cert(filename):
        return {"status": "deleted", "filename": filename}
    raise HTTPException(status_code=404, detail="Certificate not found")


@app.get("/api/certs/{filename}/download")
async def download_cert(filename: str):
    safe = Path(filename).name
    path = CERTS_DIR / safe
    if not path.exists() or not path.is_file():
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(
        path,
        filename=safe,
        media_type="application/octet-stream",
    )


@app.get("/api/certs/{filename}/info")
async def cert_info(filename: str):
    try:
        return parse_cert_info(filename)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="File not found")


# ─── PKI / Lab CA ────────────────────────────────────────────────────


class GenerateCAPayload(BaseModel):
    cn: str = "MACforge Lab CA"
    org: str = "MACforge Lab"
    days: int = 3650
    key_size: int = 2048


class GenerateClientPayload(BaseModel):
    cn: str
    san: Optional[str] = None
    ca_cert: str = "lab-ca.pem"
    ca_key: str = "lab-ca.key"
    days: int = 3650
    key_size: int = 2048


class GenerateCSRPayload(BaseModel):
    cn: str
    san: Optional[str] = None
    key_size: int = 2048


@app.get("/api/pki/lab-ca")
async def get_lab_ca():
    info = get_lab_ca_info()
    return {"exists": info is not None, "info": info}


@app.post("/api/pki/generate-ca")
async def api_generate_ca(payload: GenerateCAPayload):
    try:
        result = generate_lab_ca(
            cn=payload.cn, org=payload.org,
            days=payload.days, key_size=payload.key_size,
        )
        return result
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/api/pki/generate-client")
async def api_generate_client(payload: GenerateClientPayload):
    san_list = [s.strip() for s in payload.san.split(",") if s.strip()] if payload.san else None
    try:
        result = generate_client_cert(
            cn=payload.cn, san_list=san_list,
            ca_cert_file=payload.ca_cert, ca_key_file=payload.ca_key,
            days=payload.days, key_size=payload.key_size,
        )
        return result
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/api/pki/generate-csr")
async def api_generate_csr(payload: GenerateCSRPayload):
    san_list = [s.strip() for s in payload.san.split(",") if s.strip()] if payload.san else None
    try:
        result = generate_csr(cn=payload.cn, san_list=san_list, key_size=payload.key_size)
        return result
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ─── ISE Integration ─────────────────────────────────────────────────


class ISEConfigPayload(BaseModel):
    hostname: str = ""
    username: str = ""
    password: str = ""
    verify_tls: bool = False


@app.get("/api/ise/config")
async def get_ise_config():
    cfg = load_ise_config()
    return {
        "hostname": cfg.hostname,
        "username": cfg.username,
        "password": "••••••••" if cfg.password else "",
        "verify_tls": cfg.verify_tls,
        "configured": bool(cfg.hostname and cfg.username),
    }


@app.put("/api/ise/config")
async def update_ise_config(payload: ISEConfigPayload):
    cfg = ISEConfig(
        hostname=payload.hostname,
        username=payload.username,
        password=payload.password,
        verify_tls=payload.verify_tls,
    )
    save_ise_config(cfg)
    return {"status": "saved", "hostname": cfg.hostname}


@app.post("/api/ise/test")
async def api_ise_test():
    cfg = load_ise_config()
    return ise_test_connection(cfg)


class ISEPushCAPayload(BaseModel):
    cert_filename: str = "lab-ca.pem"
    description: str = "MACforge Lab CA"


@app.post("/api/ise/push-ca")
async def api_ise_push_ca(payload: ISEPushCAPayload):
    cfg = load_ise_config()
    return push_trusted_cert(cfg, payload.cert_filename, payload.description)


# ─── Enterprise PKI (SCEP / step-ca) ─────────────────────────────────


@app.get("/api/pki/enrollment-capabilities")
async def api_enrollment_caps():
    return get_enrollment_capabilities()

class TestNDESPayload(BaseModel):
    ndes_url: str


@app.post("/api/pki/test-ndes")
async def api_test_ndes(payload: TestNDESPayload):
    """Probe the NDES endpoint to verify it is reachable and responding.

    Sends a HTTP GET to the NDES GetCACaps operation which requires no auth
    and returns CA capabilities.  A 200 response confirms NDES is up.
    """
    import urllib.request
    import urllib.error

    caps_url = payload.ndes_url.rstrip("/") + "?operation=GetCACaps"
    try:
        req = urllib.request.Request(caps_url, headers={"User-Agent": "MACforge/1.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            body = resp.read(128).decode(errors="replace")
            return {"status": "ok", "message": f"NDES responded (HTTP {resp.status}): {body[:60]}"}
    except urllib.error.HTTPError as exc:
        # NDES sometimes returns 400/403 on GetCACaps but is still reachable
        if exc.code in (400, 403, 404):
            return {"status": "ok", "message": f"NDES reachable (HTTP {exc.code}) — verify URL path"}
        raise HTTPException(status_code=400, detail=f"NDES returned HTTP {exc.code}")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Could not reach NDES: {exc}")

class StepCAEnrollPayload(BaseModel):
    ca_url: str
    cn: str
    provisioner: str = "macforge"
    token: Optional[str] = None
    ca_fingerprint: Optional[str] = None


@app.post("/api/pki/enroll-step-ca")
async def api_enroll_step_ca(payload: StepCAEnrollPayload):
    result = await enroll_via_step_ca(
        ca_url=payload.ca_url,
        cn=payload.cn,
        provisioner=payload.provisioner,
        token=payload.token,
        ca_fingerprint=payload.ca_fingerprint,
    )
    if result["status"] == "error":
        raise HTTPException(status_code=400, detail=result["message"])
    return result


class SCEPEnrollPayload(BaseModel):
    ndes_url: str
    challenge: str
    cn: str
    san: Optional[str] = None


@app.post("/api/pki/enroll-scep")
async def api_enroll_scep(payload: SCEPEnrollPayload):
    result = await enroll_via_scep(
        ndes_url=payload.ndes_url,
        challenge=payload.challenge,
        cn=payload.cn,
        san=payload.san,
    )
    if result["status"] == "error":
        raise HTTPException(status_code=400, detail=result["message"])
    return result


# ─── 802.1X Readiness ───────────────────────────────────────────────

@app.get("/api/dot1x/readiness")
async def dot1x_readiness():
    """System readiness checks for 802.1X and MAB operation.

    Runs fast, explicit binary-level checks — no network traffic generated.
    Results cached for 60s. Categories:
      - binaries:  required tools present and correct version
      - eap:       EAP methods compiled into wpa_supplicant (probe-based)
      - system:    kernel capabilities (macvlan, iptables)
    """
    import shutil, tempfile, time, subprocess

    cache = getattr(dot1x_readiness, "_cache", None)
    if cache and time.time() - cache["ts"] < 60:
        return cache["data"]

    from macforge.dot1x import WPA_SUPPLICANT_BIN, WPA_SUPPLICANT_TEAP_BIN

    # ── Helper: run a command, return (ok, detail) ──────────────────
    async def run_check(args: list, timeout: float = 3.0) -> tuple[bool, str]:
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                try: proc.kill()
                except ProcessLookupError: pass
                return True, "timeout (ok — process started)"
            combined = (out + err).decode()
            return proc.returncode == 0, combined[:200].strip()
        except FileNotFoundError:
            return False, "binary not found"
        except Exception as exc:
            return False, str(exc)

    # ── Helper: probe one EAP method ────────────────────────────────
    # Writes a minimal config, runs wpa_supplicant for up to 2s.
    # If it exits immediately with "unknown EAP method" → not compiled in.
    # If it runs for 2s (waiting for a switch that isn't there) → method ok.
    async def probe_eap(eap: str, phase2: str = "", binary: str = WPA_SUPPLICANT_BIN) -> dict:
        conf = (
            "ctrl_interface=DIR=/tmp\nap_scan=0\nnetwork={\n"
            "  key_mgmt=IEEE8021X\n"
            f"  eap={eap}\n"
            '  identity="probe"\n'
            '  password="probe"\n'
        )
        if phase2:
            conf += f'  phase2="auth={phase2}"\n'
        conf += "}\n"
        tmp = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".conf", delete=False, prefix="/tmp/mf_probe_"
            ) as f:
                f.write(conf)
                tmp = f.name
            ok, detail = await run_check(
                [binary, "-c", tmp, "-i", "lo", "-D", "wired"],
                timeout=2.0,
            )
            # A timeout means it started fine (method recognised, waiting for switch)
            if "timeout" in detail:
                return {"ok": True, "detail": "compiled in"}
            # Catch all known failure patterns:
            #   "unknown EAP method"          — TEAP/FAST/etc not compiled
            #   "unknown network field"        — machine_cert etc
            #   "failed to parse"              — config parse error
            #   "Unsupported Phase2 EAP method" — MSCHAPV2 not compiled (PEAP/TTLS inner)
            #   "Failed to initialize EAP method" — method not registered
            _fail_patterns = (
                "unknown EAP method",
                "unknown network field",
                "failed to parse",
                "Unsupported Phase2",
                "Failed to initialize EAP method",
            )
            if any(p in detail for p in _fail_patterns):
                bad = next(
                    (l.strip() for l in detail.splitlines()
                     if any(p in l for p in _fail_patterns)),
                    detail[:160]
                )
                return {"ok": False, "detail": bad}
            # Any other clean exit (e.g. no carrier) is fine
            return {"ok": True, "detail": "compiled in"}
        except Exception as exc:
            return {"ok": False, "detail": str(exc)}
        finally:
            if tmp:
                Path(tmp).unlink(missing_ok=True)

    # ── Binary checks ────────────────────────────────────────────────
    wpa_ok, wpa_out       = await run_check([WPA_SUPPLICANT_BIN, "-v"])
    wpa_teap_ok, teap_out = await run_check([WPA_SUPPLICANT_TEAP_BIN, "-v"])
    sscep_ok, _      = await run_check(["sscep", "help"])
    # sscep exits non-zero on "help" but we just need to know it's present
    sscep_ok = shutil.which("sscep") is not None

    import re as _re
    ver_match = _re.search(r"v(\d+\.\d+)", wpa_out)
    wpa_version = ver_match.group(1) if ver_match else "unknown"
    wpa_version_ok = False
    if ver_match:
        parts = wpa_version.split(".")
        wpa_version_ok = (int(parts[0]) > 2) or (int(parts[0]) == 2 and int(parts[1]) >= 10)

    teap_ver_match = _re.search(r"v(\d+\.\d+)", teap_out)
    teap_version = teap_ver_match.group(1) if teap_ver_match else "unknown"

    binaries = {
        "wpa_supplicant": {
            "ok": wpa_ok,
            "detail": f"v{wpa_version} (apt — PEAP/EAP-TLS/FAST/TTLS)" if wpa_ok else wpa_out[:120],
        },
        "wpa_supplicant_version": {
            "ok": wpa_version_ok,
            "detail": f"v{wpa_version} ({'≥2.10 ✓' if wpa_version_ok else '<2.10 — TEAP requires ≥2.10'})",
        },
        "wpa_supplicant_teap": {
            "ok": wpa_teap_ok,
            "detail": f"v{teap_version} (source-built — TEAP only)" if wpa_teap_ok else "not found — TEAP will fail",
        },
        "sscep": {
            "ok": sscep_ok,
            "detail": "present" if sscep_ok else "not found — SCEP/NDES enrollment unavailable",
        },
    }

    # ── EAP method probes ────────────────────────────────────────────
    # All non-TEAP methods use the apt binary. TEAP requires source-built.
    eap = {
        "PEAP_MSCHAPv2": await probe_eap("PEAP", "MSCHAPV2", WPA_SUPPLICANT_BIN),
        "EAP_TLS":       await probe_eap("TLS",  "",         WPA_SUPPLICANT_BIN),
        "EAP_FAST":      await probe_eap("FAST", "MSCHAPV2", WPA_SUPPLICANT_BIN),
        "EAP_TTLS":      await probe_eap("TTLS", "MSCHAPV2", WPA_SUPPLICANT_BIN),
        "TEAP":          await probe_eap("TEAP", "MSCHAPV2", WPA_SUPPLICANT_TEAP_BIN),
    }

    # ── System capability checks ─────────────────────────────────────
    ip_ok, _       = await run_check(["ip", "link", "show"])
    ipt_ok, _      = await run_check(["iptables", "-L", "-n"])
    system = {
        "iproute2": {
            "ok": ip_ok,
            "detail": "ip link functional" if ip_ok else "iproute2 not working — macvlan creation will fail",
        },
        "iptables": {
            "ok": ipt_ok,
            "detail": "iptables functional" if ipt_ok else "iptables not working — stealth mode unavailable",
        },
    }

    all_ok = (
        all(v["ok"] for v in binaries.values()) and
        all(v["ok"] for v in eap.values()) and
        all(v["ok"] for v in system.values())
    )

    data = {
        "all_ok": all_ok,
        "wpa_supplicant_version": wpa_version,
        "binaries": binaries,
        "eap": eap,
        "system": system,
    }
    dot1x_readiness._cache = {"ts": time.time(), "data": data}
    return data


# ─── Logs & Settings ────────────────────────────────────────────────

@app.get("/api/logs", response_model=list[PacketLogEntry])
async def get_logs(limit: int = 50):
    return _get_orch().get_recent_logs(limit)


class SettingsPayload(BaseModel):
    snmp_enabled: bool


@app.get("/api/settings")
async def get_settings():
    orch = _get_orch()
    return {"snmp_enabled": orch.snmp_enabled}


@app.post("/api/settings")
async def update_settings(payload: SettingsPayload):
    orch = _get_orch()
    orch.set_snmp_enabled(payload.snmp_enabled)
    return {"snmp_enabled": orch.snmp_enabled}


def _iface_info(iface: str) -> dict:
    """Return MAC, IP, and operstate for a network interface."""
    import fcntl, socket, struct as _struct
    result: dict = {"name": iface, "mac": None, "ip": None, "operstate": "unknown"}
    try:
        with open(f"/sys/class/net/{iface}/operstate") as f:
            result["operstate"] = f.read().strip()
    except OSError:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927, _struct.pack("256s", iface[:15].encode()))
        result["mac"] = ":".join(f"{b:02x}" for b in info[18:24])
        s.close()
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8915, _struct.pack("256s", iface[:15].encode()))
        result["ip"] = socket.inet_ntoa(info[20:24])
        s.close()
    except Exception:
        pass
    return result


@app.get("/api/interface")
async def get_interface():
    """Return the active data interface and management interface with their details."""
    orch = _get_orch()
    data_info = _iface_info(orch.interface)
    mgmt_info = _iface_info(orch.mgmt_interface)
    same = orch.interface == orch.mgmt_interface
    return {
        "data_interface": orch.interface,
        "mgmt_interface": orch.mgmt_interface,
        "same": same,
        # Legacy field — kept for backwards compat; equals data_interface
        "interface": orch.interface,
        "mac": data_info["mac"],
        "ip": data_info["ip"],
        "seed_fingerprint": get_seed_fingerprint(),
        "data": data_info,
        "mgmt": mgmt_info if not same else data_info,
    }


@app.get("/api/interfaces")
async def list_interfaces():
    """Return all non-loopback network interfaces with their details and roles."""
    orch = _get_orch()
    import os as _os
    ifaces = []
    try:
        names = sorted(_os.listdir("/sys/class/net"))
    except OSError:
        names = [orch.interface, orch.mgmt_interface]
    for name in names:
        # Skip loopback, MACforge's own macvlan children (mf prefix), and
        # Docker virtual interfaces (docker*, br-*, veth*) — none are valid
        # upstream NIC choices.
        if name == "lo":
            continue
        if name.startswith(("mf", "docker", "br-", "veth")):
            continue
        info = _iface_info(name)
        if name == orch.interface and name == orch.mgmt_interface:
            info["role"] = "data+mgmt"
        elif name == orch.interface:
            info["role"] = "data"
        elif name == orch.mgmt_interface:
            info["role"] = "mgmt"
        else:
            info["role"] = "other"
        ifaces.append(info)
    return {"interfaces": ifaces, "data_interface": orch.interface, "mgmt_interface": orch.mgmt_interface}


class SetDataInterfacePayload(BaseModel):
    interface: str


@app.put("/api/interface/data")
async def set_data_interface(payload: SetDataInterfacePayload):
    """Switch the active data/NAD interface at runtime.

    All currently connected devices must be disconnected first — their macvlans
    are parented to the old interface and cannot be re-parented without a reconnect.
    """
    orch = _get_orch()
    # Reject if any device is currently connected
    connected = [
        d.profile.name for d in orch.devices.values()
        if d.state.value not in ("stopped", "error", "auth_failed")
    ]
    if connected:
        raise HTTPException(
            status_code=409,
            detail=f"Disconnect all devices before changing the data interface. "
                   f"Still connected: {', '.join(connected)}",
        )
    old = orch.interface
    orch.interface = payload.interface
    _save_auth_config(orch)
    logger.info("Data interface changed: %s → %s", old, payload.interface)

    # Bring the interface up immediately so it is ready when devices connect.
    # `ip link set up` is a no-op if already up, so this is always safe.
    try:
        up_proc = await asyncio.create_subprocess_exec(
            "ip", "link", "set", payload.interface, "up",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, up_err = await up_proc.communicate()
        if up_proc.returncode != 0:
            logger.warning("Could not bring up %s: %s", payload.interface, up_err.decode().strip())
        else:
            logger.info("Brought up data interface %s", payload.interface)
    except Exception:
        logger.exception("Exception while bringing up %s", payload.interface)

    return {"status": "ok", "data_interface": orch.interface, "mgmt_interface": orch.mgmt_interface}


@app.get("/api/vendor-ouis")
async def vendor_ouis():
    return get_oui_table()


# ─── RADIUS NAD Emulator ─────────────────────────────────────────────


class RADIUSNADConfigPayload(BaseModel):
    ise_radius_ip: str = ""
    radius_port: int = 1812
    acct_port: int = 1813
    shared_secret: str = ""
    nas_ip: str = ""
    nas_identifier: str = "macforge-nad"
    coa_port: int = 3799
    coa_enabled: bool = False


@app.get("/api/radius/config")
async def get_radius_config():
    cfg = load_radius_nad_config()
    return {
        "ise_radius_ip": cfg.ise_radius_ip,
        "radius_port": cfg.radius_port,
        "acct_port": cfg.acct_port,
        "shared_secret": "••••••••" if cfg.shared_secret else "",
        "nas_ip": cfg.nas_ip,
        "nas_identifier": cfg.nas_identifier,
        "coa_port": cfg.coa_port,
        "coa_enabled": cfg.coa_enabled,
        "configured": bool(cfg.ise_radius_ip and cfg.shared_secret and cfg.nas_ip),
    }


@app.put("/api/radius/config")
async def update_radius_config(payload: RADIUSNADConfigPayload):
    cfg = RADIUSNADConfig(**payload.model_dump())
    save_radius_nad_config(cfg)
    # Restart CoA listener with new settings
    restart_coa_listener(cfg)
    return {"status": "saved"}


@app.get("/api/radius/local-ip")
async def get_radius_local_ip():
    """Return the host IP that ISE will see as the UDP source of RADIUS packets."""
    from macforge.radius_nad import _local_ip
    return {"ip": _local_ip()}


@app.post("/api/radius/test")
async def test_radius_connection():
    cfg = load_radius_nad_config()
    if not cfg.ise_radius_ip or not cfg.shared_secret:
        return {"status": "error", "message": "RADIUS NAD not configured — set ISE IP, shared secret, and NAS-IP first"}
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, test_radius_connection_sync, cfg)


class RunSessionPayload(BaseModel):
    auth_type: str = "mab"
    mac: str = ""
    username: str = ""
    password: str = ""
    nas_port: int = 1


@app.post("/api/radius/run-session")
async def api_run_session(payload: RunSessionPayload):
    cfg = load_radius_nad_config()
    if not cfg.ise_radius_ip or not cfg.shared_secret:
        raise HTTPException(status_code=400, detail="RADIUS NAD not configured")
    if payload.auth_type not in ("mab", "pap", "peap"):
        raise HTTPException(status_code=400, detail="auth_type must be: mab, pap, peap")

    result = await run_single_session(
        cfg=cfg,
        auth_type=payload.auth_type,   # type: ignore[arg-type]
        mac=payload.mac,
        username=payload.username,
        password=payload.password,
        nas_port=payload.nas_port,
    )
    return result.model_dump()


@app.get("/api/radius/sessions")
async def get_radius_sessions(limit: int = 200):
    sessions = get_session_log()
    return [s.model_dump() for s in sessions[:limit]]


@app.delete("/api/radius/sessions")
async def delete_radius_sessions():
    clear_session_log()
    return {"status": "cleared"}


@app.get("/api/radius/sessions/export")
async def export_radius_sessions():
    csv_data = export_sessions_csv()
    return StreamingResponse(
        iter([csv_data]),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="radius_sessions.csv"'},
    )


class BulkRunPayload(BaseModel):
    auth_type: str = "mab"
    count: int = 10
    concurrency: int = 5
    delay_ms: int = 0
    base_mac: str = ""
    username_template: str = "user{n}@lab.local"
    password: str = ""


@app.post("/api/radius/bulk/start")
async def start_bulk_run(payload: BulkRunPayload):
    cfg = load_radius_nad_config()
    if not cfg.ise_radius_ip or not cfg.shared_secret:
        raise HTTPException(status_code=400, detail="RADIUS NAD not configured")
    bulk = get_bulk_state()
    if bulk["running"]:
        raise HTTPException(status_code=409, detail="A bulk run is already in progress")
    if payload.count < 1 or payload.count > 10000:
        raise HTTPException(status_code=400, detail="count must be 1–10000")
    if payload.concurrency < 1 or payload.concurrency > 200:
        raise HTTPException(status_code=400, detail="concurrency must be 1–200")

    asyncio.create_task(run_bulk_sessions(
        cfg=cfg,
        auth_type=payload.auth_type,    # type: ignore[arg-type]
        count=payload.count,
        concurrency=payload.concurrency,
        delay_ms=payload.delay_ms,
        base_mac=payload.base_mac,
        username_template=payload.username_template,
        password=payload.password,
    ))
    return {"status": "started", "total": payload.count}


@app.get("/api/radius/bulk/status")
async def get_bulk_status():
    return get_bulk_state()


@app.post("/api/radius/bulk/cancel")
async def cancel_bulk_run():
    cancel_bulk()
    return {"status": "cancelling"}


@app.get("/api/radius/coa-events")
async def stream_coa_events():
    """Server-Sent Events stream for live CoA events from ISE."""
    async def _event_generator():
        # Send any buffered events first
        for event in reversed(list(get_coa_events())[:20]):
            yield f"data: {event.model_dump_json()}\n\n"

        while True:
            try:
                event = await asyncio.wait_for(_coa_event_queue.get(), timeout=30)
                yield f"data: {event.model_dump_json()}\n\n"
            except asyncio.TimeoutError:
                yield "data: {\"ping\":true}\n\n"

    return StreamingResponse(
        _event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/api/radius/bulk/progress")
async def stream_bulk_progress():
    """SSE stream for bulk run progress updates."""
    async def _progress_generator():
        while True:
            state = get_bulk_state()
            import json as _json
            yield f"data: {_json.dumps(state)}\n\n"
            if not state["running"]:
                break
            await asyncio.sleep(0.5)

    return StreamingResponse(
        _progress_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/api/radius/ise/register-nad")
async def api_register_nad():
    from macforge.ise_api import load_ise_config as _load_ise
    ise_cfg = _load_ise()
    radius_cfg = load_radius_nad_config()
    if not ise_cfg.hostname or not ise_cfg.username:
        raise HTTPException(status_code=400, detail="ISE REST not configured — add hostname in the Certificates tab")
    if not radius_cfg.nas_ip or not radius_cfg.shared_secret:
        raise HTTPException(status_code=400, detail="RADIUS NAD not configured — set NAS-IP and shared secret first")
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, register_nad_in_ise, ise_cfg, radius_cfg)


@app.delete("/api/radius/ise/register-nad")
async def api_remove_nad():
    from macforge.ise_api import load_ise_config as _load_ise
    ise_cfg = _load_ise()
    radius_cfg = load_radius_nad_config()
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, remove_nad_from_ise, ise_cfg, radius_cfg)


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
