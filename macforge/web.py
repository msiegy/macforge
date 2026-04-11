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
    CustomAttr,
    RADIUSNADConfig,
    RADIUSSessionResult,
    cancel_bulk,
    clear_coa_events,
    clear_completed_jobs,
    clear_session_log,
    delete_job,
    delete_attr_set,
    export_sessions_csv,
    get_attr_catalog,
    get_attr_sets,
    get_bulk_state,
    get_coa_events,
    get_jobs,
    get_live_sessions,
    get_session_log,
    load_radius_nad_config,
    register_nad_in_ise,
    remove_nad_from_ise,
    restart_coa_listener,
    run_bulk_sessions,
    run_single_session,
    save_attr_set,
    save_radius_nad_config,
    start_coa_listener,
    terminate_all_live_sessions,
    terminate_live_session,
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
    NDESConfig,
    load_ndes_config,
    save_ndes_config,
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
from macforge.radius_dicts import (
    add_credential,
    add_mac,
    clear_credentials,
    clear_macs,
    delete_credential,
    delete_mac,
    import_credentials_csv,
    import_macs_csv,
    load_credentials,
    load_macs,
)
from macforge.orchestrator import Orchestrator
from macforge.profiles import generate_mac, get_oui_table, get_seed_fingerprint
from macforge.dot1x import check_wpa_supplicant_version
from macforge.scep_client import (
    enroll_via_scep,
    enroll_via_step_ca,
    fetch_ndes_otp,
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


# ─── NDES / SCEP global configuration ────────────────────────────────

@app.get("/api/pki/ndes-config")
async def get_ndes_config():
    cfg = load_ndes_config()
    return {
        "ndes_url": cfg.ndes_url,
        "otp_mode": cfg.otp_mode,
        "challenge_saved": bool(cfg.challenge),
        "ntlm_user": cfg.ntlm_user,
        "ntlm_password_saved": bool(cfg.ntlm_password),
        "ca_fingerprint": cfg.ca_fingerprint,
    }


class NDESConfigPayload(BaseModel):
    ndes_url: str = ""
    otp_mode: str = "static"
    challenge: str = ""
    ntlm_user: str = ""
    ntlm_password: str = ""
    ca_fingerprint: str = ""


@app.put("/api/pki/ndes-config")
async def update_ndes_config(payload: NDESConfigPayload):
    existing = load_ndes_config()
    # Preserve stored secrets when the client sends blank (field was left empty)
    challenge = payload.challenge if payload.challenge else existing.challenge
    ntlm_password = payload.ntlm_password if payload.ntlm_password else existing.ntlm_password
    cfg = NDESConfig(
        ndes_url=payload.ndes_url.strip(),
        otp_mode=payload.otp_mode,
        challenge=challenge,
        ntlm_user=payload.ntlm_user.strip(),
        ntlm_password=ntlm_password,
        ca_fingerprint=payload.ca_fingerprint.strip(),
    )
    save_ndes_config(cfg)
    return {"status": "saved", "ndes_url": cfg.ndes_url, "otp_mode": cfg.otp_mode}


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

class TestNTLMOTPPayload(BaseModel):
    ndes_url: str
    ntlm_user: str = ""
    ntlm_password: str = ""  # if blank, use saved credentials


@app.post("/api/pki/test-ndes-otp")
async def api_test_ndes_otp(payload: TestNTLMOTPPayload):
    """Attempt NTLM auth against the NDES admin page and confirm OTP retrieval.

    Returns success with OTP length (not the OTP itself) so the caller can
    confirm Dynamic OTP mode is working before committing an enrollment.
    """
    saved = load_ndes_config()
    ntlm_user = payload.ntlm_user or saved.ntlm_user
    ntlm_password = payload.ntlm_password or saved.ntlm_password
    if not ntlm_user or not ntlm_password:
        raise HTTPException(status_code=400, detail="NTLM username and password are required.")
    try:
        loop = asyncio.get_event_loop()
        otp = await loop.run_in_executor(
            None, fetch_ndes_otp, payload.ndes_url, ntlm_user, ntlm_password
        )
        return {
            "status": "ok",
            "message": f"NTLM authentication succeeded — OTP retrieved ({len(otp)} chars).",
        }
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


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
    challenge: str = ""
    cn: str
    san: Optional[str] = None


@app.post("/api/pki/enroll-scep")
async def api_enroll_scep(payload: SCEPEnrollPayload):
    saved = load_ndes_config()
    # Use saved challenge as fallback when field is blank
    challenge = payload.challenge or saved.challenge
    result = await enroll_via_scep(
        ndes_url=payload.ndes_url,
        challenge=challenge,
        cn=payload.cn,
        san=payload.san,
        otp_mode=saved.otp_mode,
        ntlm_user=saved.ntlm_user,
        ntlm_password=saved.ntlm_password,
        ca_fingerprint=saved.ca_fingerprint,
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
    coa_port: int = 1700
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


@app.get("/api/radius/profiles")
async def get_radius_profiles():
    """Return device profiles (name, mac, oui, category, device_type) for the NAD emulator."""
    from macforge.profiles import load_profiles
    profiles = load_profiles()
    result = []
    for p in profiles:
        oui = ":".join(p.mac.upper().split(":")[:3])
        result.append({
            "name": p.name,
            "mac": p.mac,
            "oui": oui,
            "category": p.personality.category,
            "device_type": p.personality.device_type,
            "os": p.personality.os,
            "dhcp_hostname": p.dhcp.hostname,
            "dhcp_vendor_class": p.dhcp.vendor_class,
            "auth_method": p.auth.method if p.auth else None,
        })
    return result


class IssueCertPayload(BaseModel):
    cn: str
    san_emails: list[str] = []
    ca_cert_file: str = "lab-ca.pem"
    ca_key_file: str = "lab-ca.key"
    days: int = 3650


@app.get("/api/radius/certs")
async def list_radius_certs():
    """List PEM files in the certs directory with metadata."""
    from macforge.radius_nad import list_available_certs
    return list_available_certs()


@app.post("/api/radius/certs/issue")
async def issue_radius_cert(payload: IssueCertPayload):
    """Issue a new client certificate signed by the lab CA for EAP-TLS."""
    from macforge.certgen import generate_client_cert
    loop = asyncio.get_event_loop()
    try:
        info = await loop.run_in_executor(
            None,
            lambda: generate_client_cert(
                cn=payload.cn,
                san_list=payload.san_emails or None,
                ca_cert_file=payload.ca_cert_file,
                ca_key_file=payload.ca_key_file,
                days=payload.days,
            ),
        )
        return {"status": "ok", **info}
    except FileNotFoundError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


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
    oui_prefix: str = ""        # when MAC blank, randomise within this OUI (e.g. "64:4E:D7")
    username: str = ""
    password: str = ""
    nas_port: int = 1
    # Session lifetime:
    #   -1 = immediate (Acct-Start + Stop back-to-back, for bulk/report-only)
    #    0 = live until manually terminated (default for single sessions — CoA testing)
    #   >0 = live for N seconds then auto-terminate
    session_lifetime_secs: int = 0
    # EAP-TLS
    cert_file: str = ""
    key_file: str = ""
    validate_server_cert: bool = False
    ise_ca_cert_file: str = ""
    # MAB profiling: name of the device profile whose DHCP/vendor attributes to
    # send as subscriber: Cisco-AVPairs in Accounting-Start to assist ISE profiling.
    profile_name: str = ""
    # Termination cause for live sessions ("auto" = best-fit per trigger)
    # Accepted: "auto", "User-Request", "Lost-Carrier", "Session-Timeout",
    #           "Admin-Reset", "Lost-Power"
    terminate_cause: str = "auto"
    # User-defined custom RADIUS attributes to inject into session packets
    custom_attrs: list[CustomAttr] = []


@app.post("/api/radius/run-session")
async def api_run_session(payload: RunSessionPayload):
    from macforge.profiles import load_profiles
    cfg = load_radius_nad_config()
    if not cfg.ise_radius_ip or not cfg.shared_secret:
        raise HTTPException(status_code=400, detail="RADIUS NAD not configured")
    if payload.auth_type not in ("mab", "pap", "peap", "eap-tls"):
        raise HTTPException(status_code=400, detail="auth_type must be: mab, pap, peap, eap-tls")

    # Resolve profiling attributes from the selected profile
    profile_attrs: dict | None = None
    if payload.profile_name and payload.auth_type == "mab":
        profiles = load_profiles()
        matched = next((p for p in profiles if p.name == payload.profile_name), None)
        if matched:
            profile_attrs = {
                "vendor_class": matched.dhcp.vendor_class if matched.dhcp else "",
                "hostname": matched.dhcp.hostname if matched.dhcp else "",
                "param_request_list": (
                    matched.dhcp.param_request_list if matched.dhcp else []
                ),
                "profile_name": matched.name,
            }

    result = await run_single_session(
        cfg=cfg,
        auth_type=payload.auth_type,   # type: ignore[arg-type]
        mac=payload.mac,
        oui_prefix=payload.oui_prefix,
        username=payload.username,
        password=payload.password,
        nas_port=payload.nas_port,
        session_lifetime_secs=payload.session_lifetime_secs,
        cert_file=payload.cert_file,
        key_file=payload.key_file,
        validate_server_cert=payload.validate_server_cert,
        ise_ca_cert_file=payload.ise_ca_cert_file,
        profile_attrs=profile_attrs,
        terminate_cause=payload.terminate_cause,
        custom_attrs=payload.custom_attrs or [],
    )

    # Log to Activity Log so NAD emulator sessions appear alongside device events.
    import time as _time
    identity = result.username or result.mac
    detail_str = result.detail or result.acct_session_id or ""
    _get_orch().packet_log.appendleft(PacketLogEntry(
        timestamp=_time.time(),
        device_name="NAD Emulator",
        mac=result.mac,
        packet_type=f"RADIUS {result.auth_type.upper()}",
        detail=f"{result.result.upper()} — {identity} — {detail_str}".rstrip(" —"),
    ))

    return result.model_dump()


@app.get("/api/radius/sessions")
async def get_radius_sessions(limit: int = 200):
    sessions = get_session_log()
    return [s.model_dump() for s in sessions[:limit]]


@app.delete("/api/radius/sessions")
async def delete_radius_sessions():
    clear_session_log()
    return {"status": "cleared"}


@app.get("/api/radius/live-sessions")
async def api_get_live_sessions():
    """Return currently live sessions (Acct-Start sent, Acct-Stop not yet sent)."""
    return get_live_sessions()


@app.delete("/api/radius/live-sessions/{session_id}")
async def api_terminate_live_session(session_id: str):
    """Send Acct-Stop for a specific live session and remove it."""
    terminated = await terminate_live_session(session_id, "User-Request")
    if not terminated:
        raise HTTPException(status_code=404, detail="Live session not found")
    return {"status": "terminated", "acct_session_id": session_id}


@app.delete("/api/radius/live-sessions")
async def api_terminate_all_live_sessions():
    """Send Acct-Stop for all live sessions."""
    count = await terminate_all_live_sessions("User-Request")
    return {"status": "terminated", "count": count}


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
    # bulk_source controls how MACs (and profiling hints) are generated:
    #   "random"   – random OUI DE:AD:BE (legacy default)
    #   "category" – random OUI from a specific device category (uses device_category)
    #   "profiles" – randomly selects from all YAML device profiles per session
    bulk_source: str = "random"
    device_category: str = ""       # used when bulk_source == "category"
    username_template: str = "user{n}@lab.local"
    password: str = ""
    session_lifetime_secs: int = -1  # default: immediate close (don't flood live-sessions)
    # EAP-TLS bulk (same cert for all sessions; machine/device cert scenario)
    cert_file: str = ""
    key_file: str = ""
    validate_server_cert: bool = False
    ise_ca_cert_file: str = ""
    # Termination cause for live sessions ("auto" = best-fit per trigger)
    terminate_cause: str = "auto"
    # User-defined custom RADIUS attributes applied to every session in the bulk run
    custom_attrs: list[CustomAttr] = []
    # Dictionary integration — when True, cycles through stored dictionaries
    # instead of using username_template/password or random MACs
    credential_dict: bool = False
    mac_dict: bool = False


@app.post("/api/radius/bulk/start")
async def start_bulk_run(payload: BulkRunPayload):
    from macforge.profiles import VENDOR_OUIS, load_profiles
    import random as _rnd
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
    if payload.auth_type == "eap-tls" and (not payload.cert_file or not payload.key_file):
        raise HTTPException(status_code=400, detail="cert_file and key_file are required for EAP-TLS bulk runs")

    oui_prefix = ""
    profile_pool: list[dict] | None = None
    username_template = payload.username_template
    password = payload.password
    base_mac = payload.base_mac

    # Credential dictionary overrides username_template + password
    if payload.credential_dict and payload.auth_type in ("pap", "peap", "eap-tls"):
        creds = load_credentials()
        if not creds:
            raise HTTPException(
                status_code=400,
                detail="Credential dictionary is empty — add entries in the Dictionaries panel first"
            )
        # Build a template-like cycle using Python format string substitution by index
        # We pass creds as a profile_pool-like mechanism via the MAC dict approach below.
        # For simplicity, expand the list into a pool list here and pass via username_template.
        # Since run_bulk_sessions doesn't natively support credential cycling, we encode
        # the N-th credential into username_template and password via a lookup table stored
        # in the job params — the bulk runner uses {n} which we can post-process.
        # A cleaner approach: pre-build a list and pass inline. For now, we pass the creds
        # list and let bulk runner pick by index via username_template = "DICT:{n}".
        # We'll handle this by expanding the count to the dict length if count > len(creds),
        # then pass a pool param. Simplest implementation: export creds as pool.
        pass  # Dict cycling is handled in the bulk runner via credential_pool below

    # MAC dictionary overrides oui_prefix for MAB
    mac_pool: list[str] | None = None
    if payload.mac_dict and payload.auth_type == "mab":
        macs = load_macs()
        if not macs:
            raise HTTPException(
                status_code=400,
                detail="MAC dictionary is empty — add entries in the Dictionaries panel first"
            )
        mac_pool = [m["mac"] for m in macs]

    if payload.bulk_source == "profiles" and payload.auth_type == "mab" and not mac_pool:
        # Build a pool from all YAML device profiles — each session randomly picks one
        all_profiles = load_profiles()
        pool = []
        for p in all_profiles:
            mac_clean = p.mac.lower().replace(":", "").replace("-", "")
            # Use first 6 hex chars as OUI (AA:BB:CC format)
            oui = ":".join(mac_clean[i:i+2].upper() for i in range(0, 6, 2)) if len(mac_clean) >= 6 else "DE:AD:BE"
            pool.append({
                "oui": oui,
                "vendor_class": p.dhcp.vendor_class if p.dhcp else "",
                "hostname": p.dhcp.hostname if p.dhcp else "",
                "param_request_list": p.dhcp.param_request_list if p.dhcp else [],
                "profile_name": p.name,
            })
        if pool:
            profile_pool = pool
    elif payload.bulk_source == "category" and payload.device_category and not mac_pool:
        if payload.device_category in VENDOR_OUIS:
            entries = VENDOR_OUIS[payload.device_category]
            oui_prefix = _rnd.choice(entries)["oui"]

    # Build credential pool for cycling (PAP/PEAP with credential_dict)
    cred_pool: list[dict] | None = None
    if payload.credential_dict and payload.auth_type in ("pap", "peap", "eap-tls"):
        creds = load_credentials()
        if creds:
            cred_pool = creds

    import time as _time
    import uuid as _uuid
    job_id = str(_uuid.uuid4())[:8].upper()

    async def _bulk_task() -> None:
        orch = _get_orch()
        orch.packet_log.appendleft(PacketLogEntry(
            timestamp=_time.time(),
            device_name="NAD Emulator",
            mac="—",
            packet_type=f"RADIUS Bulk {payload.auth_type.upper()}",
            detail=f"Started — {payload.count} sessions · concurrency {payload.concurrency}",
        ))
        await run_bulk_sessions(
            cfg=cfg,
            auth_type=payload.auth_type,    # type: ignore[arg-type]
            count=payload.count,
            concurrency=payload.concurrency,
            delay_ms=payload.delay_ms,
            base_mac=base_mac,
            oui_prefix=oui_prefix,
            username_template=username_template,
            password=password,
            cert_file=payload.cert_file,
            key_file=payload.key_file,
            validate_server_cert=payload.validate_server_cert,
            ise_ca_cert_file=payload.ise_ca_cert_file,
            profile_pool=profile_pool,
            session_lifetime_secs=payload.session_lifetime_secs,
            terminate_cause=payload.terminate_cause,
            job_id=job_id,
            job_params=payload.model_dump(),
            mac_pool=mac_pool,
            cred_pool=cred_pool,
            custom_attrs=payload.custom_attrs or [],
        )
        # Log completion summary using the finished job record.
        jobs = get_jobs()
        job = next((j for j in jobs if j.get("job_id") == job_id), None)
        if job:
            orch.packet_log.appendleft(PacketLogEntry(
                timestamp=_time.time(),
                device_name="NAD Emulator",
                mac="—",
                packet_type=f"RADIUS Bulk {payload.auth_type.upper()}",
                detail=(
                    f"{job.get('status', '').upper()} — "
                    f"{job.get('accepted', 0)} accept · "
                    f"{job.get('rejected', 0)} reject · "
                    f"{job.get('errors', 0)} error"
                ),
            ))

    asyncio.create_task(_bulk_task())
    return {"status": "started", "total": payload.count, "job_id": job_id}


@app.get("/api/radius/bulk/status")
async def get_bulk_status():
    return get_bulk_state()


@app.post("/api/radius/bulk/cancel")
async def cancel_bulk_run():
    cancel_bulk()
    return {"status": "cancelling"}


@app.get("/api/radius/jobs")
async def api_get_jobs():
    """Return all bulk job history records, newest first."""
    return get_jobs()


@app.delete("/api/radius/jobs")
async def api_clear_completed_jobs():
    """Remove all completed/cancelled/failed jobs from history."""
    removed = clear_completed_jobs()
    return {"status": "cleared", "removed": removed}


@app.delete("/api/radius/jobs/{job_id}")
async def api_delete_job(job_id: str):
    """Remove a specific job from history."""
    deleted = delete_job(job_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Job not found")
    return {"status": "deleted", "job_id": job_id}


@app.post("/api/radius/jobs/{job_id}/repeat")
async def api_repeat_job(job_id: str):
    """Re-run a previous bulk job with the same parameters."""
    jobs = get_jobs()
    job = next((j for j in jobs if j["job_id"] == job_id), None)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    params = job.get("params", {})
    if not params:
        raise HTTPException(status_code=400, detail="Job has no saved parameters")
    # Re-submit via the same bulk start logic
    payload = BulkRunPayload(**params)
    return await start_bulk_run(payload)


# ─── Dictionary API ──────────────────────────────────────────────────

class CredentialEntry(BaseModel):
    username: str
    password: str


class MacEntry(BaseModel):
    mac: str


class ImportCsvPayload(BaseModel):
    csv_text: str


@app.get("/api/radius/dicts/credentials")
async def api_get_credentials():
    return load_credentials()


@app.post("/api/radius/dicts/credentials")
async def api_add_credential(entry: CredentialEntry):
    return add_credential(entry.username, entry.password)


@app.delete("/api/radius/dicts/credentials")
async def api_clear_credentials():
    count = clear_credentials()
    return {"status": "cleared", "count": count}


@app.delete("/api/radius/dicts/credentials/{entry_id}")
async def api_delete_credential(entry_id: str):
    deleted = delete_credential(entry_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Credential entry not found")
    return {"status": "deleted"}


@app.post("/api/radius/dicts/credentials/import")
async def api_import_credentials(payload: ImportCsvPayload):
    added = import_credentials_csv(payload.csv_text)
    return {"status": "imported", "added": added}


@app.get("/api/radius/dicts/macs")
async def api_get_macs():
    return load_macs()


@app.post("/api/radius/dicts/macs")
async def api_add_mac(entry: MacEntry):
    return add_mac(entry.mac)


@app.delete("/api/radius/dicts/macs")
async def api_clear_macs():
    count = clear_macs()
    return {"status": "cleared", "count": count}


@app.delete("/api/radius/dicts/macs/{entry_id}")
async def api_delete_mac(entry_id: str):
    deleted = delete_mac(entry_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="MAC entry not found")
    return {"status": "deleted"}


@app.post("/api/radius/dicts/macs/import")
async def api_import_macs(payload: ImportCsvPayload):
    added = import_macs_csv(payload.csv_text)
    return {"status": "imported", "added": added}


# ─── Attribute Customization API ─────────────────────────────────────

@app.get("/api/radius/attrs/catalog")
async def api_get_attr_catalog():
    """Return all RADIUS attribute definitions from the embedded dictionary."""
    return get_attr_catalog()


class AttrSetPayload(BaseModel):
    name: str
    attrs: list[CustomAttr]


@app.get("/api/radius/attrs/sets")
async def api_get_attr_sets():
    return get_attr_sets()


@app.post("/api/radius/attrs/sets")
async def api_save_attr_set(payload: AttrSetPayload):
    save_attr_set(payload.name, [a.model_dump() for a in payload.attrs])
    return {"status": "saved", "name": payload.name}


@app.delete("/api/radius/attrs/sets/{name}")
async def api_delete_attr_set(name: str):
    deleted = delete_attr_set(name)
    if not deleted:
        raise HTTPException(status_code=404, detail="Attribute set not found")
    return {"status": "deleted", "name": name}


@app.delete("/api/radius/coa-events")
async def api_clear_coa_events():
    """Clear all buffered CoA events."""
    clear_coa_events()
    return {"status": "cleared"}


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
