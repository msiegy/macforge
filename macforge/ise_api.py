"""Cisco ISE API integration for certificate and endpoint management.

Provides connectivity testing and trusted certificate import via
ISE's OpenAPI (v1) endpoints on port 443.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import urllib.request
import urllib.error
import urllib.parse
import ssl
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

from pydantic import BaseModel

from macforge.crypto_store import decrypt_secret, encrypt_secret

logger = logging.getLogger(__name__)

DATA_DIR = Path(os.environ.get("MACFORGE_DATA_DIR", "/app/data"))
CERTS_DIR = DATA_DIR / "certs"
ISE_CONFIG_PATH = DATA_DIR / "ise_config.json"
NDES_CONFIG_PATH = DATA_DIR / "ndes_config.json"


class ISEConfig(BaseModel):
    hostname: str = ""
    username: str = ""
    password: str = ""
    verify_tls: bool = False


def load_ise_config() -> ISEConfig:
    if ISE_CONFIG_PATH.exists():
        try:
            data = json.loads(ISE_CONFIG_PATH.read_text())
            return ISEConfig(**data)
        except Exception:
            logger.exception("Failed to load ISE config")
    return ISEConfig()


def save_ise_config(config: ISEConfig) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    ISE_CONFIG_PATH.write_text(config.model_dump_json(indent=2))
    logger.info("Saved ISE config for %s", config.hostname)


class NDESConfig(BaseModel):
    ndes_url: str = ""
    otp_mode: str = "static"       # "static" | "dynamic"
    challenge: str = ""            # plaintext in memory; encrypted on disk
    ntlm_user: str = ""
    ntlm_password: str = ""        # plaintext in memory; encrypted on disk
    ca_fingerprint: str = ""       # optional SHA-256 hex of NDES root CA


def load_ndes_config() -> NDESConfig:
    """Load and decrypt NDES config from disk."""
    if NDES_CONFIG_PATH.exists():
        try:
            data = json.loads(NDES_CONFIG_PATH.read_text())
            cfg = NDESConfig(**data)
            # Decrypt secrets — handles legacy plaintext transparently
            cfg.challenge = decrypt_secret(cfg.challenge)
            cfg.ntlm_password = decrypt_secret(cfg.ntlm_password)
            return cfg
        except Exception:
            logger.exception("Failed to load NDES config")
    return NDESConfig()


def save_ndes_config(config: NDESConfig) -> None:
    """Encrypt secrets and write NDES config to disk."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    on_disk = config.model_copy()
    on_disk.challenge = encrypt_secret(config.challenge)
    on_disk.ntlm_password = encrypt_secret(config.ntlm_password)
    NDES_CONFIG_PATH.write_text(on_disk.model_dump_json(indent=2))
    logger.info("Saved NDES config for %s (mode=%s)", config.ndes_url, config.otp_mode)


def _make_ssl_context(verify: bool) -> ssl.SSLContext:
    if verify:
        return ssl.create_default_context()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _auth_header(username: str, password: str) -> str:
    creds = base64.b64encode(f"{username}:{password}".encode()).decode()
    return f"Basic {creds}"


def test_connection(config: ISEConfig) -> dict:
    """Test connectivity to ISE by listing trusted certificates.

    Returns a dict with status and message.
    """
    if not config.hostname or not config.username:
        return {"status": "error", "message": "ISE hostname and username required"}

    url = f"https://{config.hostname}/api/v1/certs/trusted-certificate?size=1&page=1"
    ctx = _make_ssl_context(config.verify_tls)

    req = urllib.request.Request(
        url,
        headers={
            "Authorization": _auth_header(config.username, config.password),
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            data = json.loads(resp.read())
            total = data.get("response", [{}])
            return {
                "status": "ok",
                "message": f"Connected to ISE at {config.hostname}",
                "ise_version": data.get("version", "unknown"),
            }
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode()[:500]
        except Exception:
            pass
        return {
            "status": "error",
            "message": f"HTTP {exc.code}: {exc.reason}",
            "detail": body,
        }
    except urllib.error.URLError as exc:
        return {
            "status": "error",
            "message": f"Connection failed: {exc.reason}",
        }
    except Exception as exc:
        return {"status": "error", "message": str(exc)}


def _extract_cert_cn(cert_pem: str) -> Optional[str]:
    """Return the CN from a PEM certificate string, or None on failure."""
    try:
        from cryptography import x509 as _x509
        from cryptography.x509.oid import NameOID as _NameOID
        cert_obj = _x509.load_pem_x509_certificate(cert_pem.encode())
        attrs = cert_obj.subject.get_attributes_for_oid(_NameOID.COMMON_NAME)
        return attrs[0].value if attrs else None
    except Exception:
        return None


def push_trusted_cert(
    config: ISEConfig,
    cert_filename: str,
    description: str = "MACforge Lab CA",
) -> dict:
    """Push a CA certificate to ISE's trusted certificate store.

    Uses POST /api/v1/certs/trusted-certificate/import

    The ISE ``name`` field (must be unique per ISE node) is derived from
    the certificate's own CN so that multiple MACforge deployments with
    different Lab CAs don't collide on the same name.  The caller-supplied
    ``description`` is used only for the human-readable description field.
    """
    if not config.hostname or not config.username:
        return {"status": "error", "message": "ISE not configured"}

    cert_path = CERTS_DIR / cert_filename
    if not cert_path.exists():
        return {"status": "error", "message": f"Certificate not found: {cert_filename}"}

    cert_pem = cert_path.read_text()

    # Use the cert's CN as the ISE trust-store name so each unique Lab CA gets
    # its own entry and re-using the same CN across instances doesn't 409.
    cert_cn = _extract_cert_cn(cert_pem)
    ise_name = cert_cn or description

    payload = json.dumps({
        "data": cert_pem,
        "description": description,
        "name": ise_name,
        "trustForIseAuth": True,
        "trustForClientAuth": True,
        "trustForCertificateBasedAdminAuth": False,
        "trustForCiscoServicesAuth": False,
        "allowBasicConstraintCAFalse": False,
        "allowOutOfDateCert": False,
        "allowSHA1Certificates": False,
    }).encode()

    url = f"https://{config.hostname}/api/v1/certs/trusted-certificate/import"
    ctx = _make_ssl_context(config.verify_tls)

    req = urllib.request.Request(
        url,
        data=payload,
        method="POST",
        headers={
            "Authorization": _auth_header(config.username, config.password),
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            data = json.loads(resp.read())
            logger.info("Pushed %s to ISE %s", cert_filename, config.hostname)
            return {
                "status": "ok",
                "message": f"Certificate imported into ISE trust store",
                "ise_response": data,
            }
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode()[:1000]
        except Exception:
            pass
        logger.warning("ISE cert push failed: HTTP %d: %s", exc.code, body)
        if exc.code == 409:
            return {
                "status": "error",
                "message": (
                    f"ISE already has a trusted certificate named '{ise_name}'. "
                    "Delete it in ISE (Administration → System → Certificates → "
                    "Trusted Certificates) or regenerate the Lab CA with a unique CN."
                ),
                "detail": body,
            }
        return {
            "status": "error",
            "message": f"HTTP {exc.code}: {exc.reason}",
            "detail": body,
        }
    except Exception as exc:
        return {"status": "error", "message": str(exc)}


def _xml_elem_to_dict(element) -> dict:
    """Recursively convert an XML element tree to a flat/nested dict.
    Strips XML namespaces. When multiple sibling elements share a tag,
    collapses them into a list.
    """
    result: dict = {}
    for child in element:
        tag = child.tag
        if "}" in tag:
            tag = tag.split("}", 1)[1]  # strip namespace
        if list(child):
            val: object = _xml_elem_to_dict(child)
        else:
            text = child.text
            val = text.strip() if text and text.strip() else ""
        if tag in result:
            existing = result[tag]
            if isinstance(existing, list):
                existing.append(val)
            else:
                result[tag] = [existing, val]
        else:
            result[tag] = val
    return result


def _flatten_mnt_session(d: dict) -> dict:
    """Flatten MnT session dict: merge any nested-dict values (e.g. <activeSession>)
    into the parent so callers see a single flat key-value map.
    Scalar values from the parent always win over nested values on key collision.
    """
    flat: dict = {}
    nested: dict = {}
    for k, v in d.items():
        if isinstance(v, dict):
            nested.update(v)
        elif v != "":
            flat[k] = v
    # Nested values fill in keys not already present in the parent
    for k, v in nested.items():
        if k not in flat and v != "":
            flat[k] = v
    return flat


def _mnt_session_request(config: ISEConfig, url: str) -> dict:
    """Shared helper for ISE MnT Session API calls (returns XML)."""
    ctx = _make_ssl_context(config.verify_tls)
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": _auth_header(config.username, config.password),
            "Accept": "application/xml",
        },
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
            raw = resp.read()
        root = ET.fromstring(raw)
        session = _xml_elem_to_dict(root)
        # Flatten nested wrapper elements (e.g. <activeSession>) into a single dict
        session = _flatten_mnt_session(session)
        return {"status": "ok", "session": session}
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode()[:500]
        except Exception:
            pass
        if exc.code == 404:
            return {"status": "not_found", "message": "No active session found in ISE"}
        return {"status": "error", "message": f"HTTP {exc.code}: {exc.reason}", "detail": body}
    except urllib.error.URLError as exc:
        return {"status": "error", "message": f"Connection failed: {exc.reason}"}
    except Exception as exc:
        return {"status": "error", "message": str(exc)}


def get_session_by_mac(config: ISEConfig, mac: str) -> dict:
    """Fetch active RADIUS session data from ISE MnT API by MAC address.

    Uses GET /admin/API/mnt/Session/MACAddress/{mac} (MnT REST API).
    Returns {"status": "ok", "session": {...}} or error dict.
    """
    if not config.hostname or not config.username:
        return {"status": "error", "message": "ISE not configured"}

    # MnT expects colon-separated uppercase with dashes replaced: AA:BB:CC:DD:EE:FF
    mac_fmt = mac.replace("-", ":").upper()
    url = f"https://{config.hostname}/admin/API/mnt/Session/MACAddress/{urllib.parse.quote(mac_fmt)}"
    return _mnt_session_request(config, url)


def get_session_by_username(config: ISEConfig, username: str) -> dict:
    """Fetch active RADIUS session data from ISE MnT API by username.

    Uses GET /admin/API/mnt/Session/UserName/{username} (MnT REST API).
    Returns {"status": "ok", "session": {...}} or error dict.
    """
    if not config.hostname or not config.username:
        return {"status": "error", "message": "ISE not configured"}

    url = f"https://{config.hostname}/admin/API/mnt/Session/UserName/{urllib.parse.quote(username)}"
    return _mnt_session_request(config, url)


def get_endpoint_by_mac(config: ISEConfig, mac: str) -> dict:
    """Fetch endpoint profiling record from ISE OpenAPI v1 by MAC address.

    Uses GET /api/v1/endpoint/{mac} (ISE 3.x OpenAPI).
    Returns {"status": "ok", "endpoint": {...}} or error dict.
    """
    if not config.hostname or not config.username:
        return {"status": "error", "message": "ISE not configured"}

    mac_fmt = mac.replace("-", ":").upper()
    url = f"https://{config.hostname}/api/v1/endpoint/{urllib.parse.quote(mac_fmt)}"
    ctx = _make_ssl_context(config.verify_tls)
    headers = {
        "Authorization": _auth_header(config.username, config.password),
        "Accept": "application/json",
    }

    try:
        with urllib.request.urlopen(
            urllib.request.Request(url, headers=headers), context=ctx, timeout=15
        ) as resp:
            data = json.loads(resp.read())
            return {"status": "ok", "endpoint": data}
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode()[:500]
        except Exception:
            pass
        if exc.code == 404:
            return {"status": "not_found", "message": "Endpoint not found in ISE"}
        return {"status": "error", "message": f"HTTP {exc.code}: {exc.reason}", "detail": body}
    except urllib.error.URLError as exc:
        return {"status": "error", "message": f"Connection failed: {exc.reason}"}
    except Exception as exc:
        return {"status": "error", "message": str(exc)}


def get_auth_history(config: ISEConfig, mac: str, limit: int = 10) -> dict:
    """Fetch recent authentication history from ISE MnT API by MAC address.

    Uses GET /admin/API/mnt/AuthStatus/MACAddress/{mac}/0/{limit}/All (XML).
    Returns {"status": "ok", "history": [...]} or error dict.
    """
    if not config.hostname or not config.username:
        return {"status": "error", "message": "ISE not configured"}

    mac_fmt = mac.replace("-", ":").upper()
    # 0 minutes = no time filter; limit = max records; All = passed + failed
    url = (
        f"https://{config.hostname}/admin/API/mnt/AuthStatus/MACAddress"
        f"/{urllib.parse.quote(mac_fmt)}/0/{limit}/All"
    )
    ctx = _make_ssl_context(config.verify_tls)
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": _auth_header(config.username, config.password),
            "Accept": "application/xml",
        },
    )

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
            raw = resp.read()
        root = ET.fromstring(raw)
        # Structure: <authStatusOutputList><authStatusList><authStatusElements>...</authStatusElements>...</authStatusList></authStatusOutputList>
        # Collect all <authStatusElements> regardless of nesting depth
        ns_strip = lambda tag: tag.split("}", 1)[1] if "}" in tag else tag
        elements = [
            child for child in root.iter()
            if ns_strip(child.tag) == "authStatusElements"
        ]
        records = []
        for el in elements:
            rec = _xml_elem_to_dict(el)
            rec = {k: v for k, v in rec.items() if v != ""}
            records.append(rec)
        return {"status": "ok", "history": records}
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode()[:500]
        except Exception:
            pass
        if exc.code == 404:
            return {"status": "ok", "history": []}
        return {"status": "error", "message": f"HTTP {exc.code}: {exc.reason}", "detail": body}
    except urllib.error.URLError as exc:
        return {"status": "error", "message": f"Connection failed: {exc.reason}"}
    except Exception as exc:
        return {"status": "error", "message": str(exc)}


def apply_anc_policy(config: ISEConfig, mac: str, policy_name: str) -> dict:
    """Apply an ANC policy to an endpoint by MAC address (no session ID needed).

    Uses POST /ers/config/ancendpoint/apply (ISE ERS ANC API).
    Common policy names: Quarantine, Shutdown, ReAuthenticate (ISE-configured).
    Returns {"status": "ok", "message": "..."} or error dict.
    """
    if not config.hostname or not config.username:
        return {"status": "error", "message": "ISE not configured"}

    mac_fmt = mac.replace("-", ":").upper()
    payload = json.dumps({
        "OperationAdditionalData": {
            "additionalData": [
                {"name": "macAddress", "value": mac_fmt},
                {"name": "policyName", "value": policy_name},
            ]
        }
    }).encode()

    url = f"https://{config.hostname}/ers/config/ancendpoint/apply"
    ctx = _make_ssl_context(config.verify_tls)
    req = urllib.request.Request(
        url,
        data=payload,
        method="PUT",
        headers={
            "Authorization": _auth_header(config.username, config.password),
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
            body = resp.read()
            try:
                result = json.loads(body)
            except Exception:
                result = {}
            return {"status": "ok", "message": f"ANC policy '{policy_name}' applied to {mac_fmt}", "response": result}
    except urllib.error.HTTPError as exc:
        body = b""
        try:
            body = exc.read()
        except Exception:
            pass
        body_str = body.decode(errors="replace")[:500] if body else ""
        return {"status": "error", "message": f"HTTP {exc.code}: {exc.reason}", "detail": body_str}
    except urllib.error.URLError as exc:
        return {"status": "error", "message": f"Connection failed: {exc.reason}"}
    except Exception as exc:
        return {"status": "error", "message": str(exc)}


def _get_session_by_mac(config: ISEConfig, mac_hyphen: str) -> dict:
    """Look up an active ISE session using the targeted MnT MAC endpoint.

    GET /admin/API/mnt/Session/MACAddress/{MAC}

    This is a direct single-session lookup — far more reliable than parsing
    the full ActiveList.  Returns dict with ise_name, nas_ip, endpoint_ip on
    success, or {"status": "error", "message": ...} on failure.

    ISE XML field names searched (tries both hyphen and underscore variants
    since ISE versions are inconsistent):
      ise-name / ise_name
      nas-ip-address / nas_ip_address
      framed-ip-address / framed_ip_address / calling-station-ip
    """
    url = f"https://{config.hostname}/admin/API/mnt/Session/MACAddress/{mac_hyphen}"
    logger.info("Session lookup → GET %s", url)

    ctx = _make_ssl_context(config.verify_tls)
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": _auth_header(config.username, config.password),
            "Accept": "application/xml",
        },
    )

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
            body = resp.read()

        logger.debug("Session XML for %s:\n%s", mac_hyphen, body.decode(errors="replace")[:2000])
        root = ET.fromstring(body)

        def _find(*tags: str) -> str:
            """Search the whole tree for any of the given tag names; return first hit."""
            for tag in tags:
                for el in root.iter(tag):
                    val = (el.text or "").strip()
                    if val:
                        return val
            return ""

        # ISE 3.x MnT returns underscore-named tags; PSN node is <acs_server>
        ise_name    = _find("acs_server", "ise_name", "ise-name", "server")
        nas_ip      = _find("nas_ip_address", "nas-ip-address", "device_ip_address",
                            "network-device-ip-address")
        endpoint_ip = _find("framed_ip_address", "framed-ip-address",
                            "calling_station_ip", "calling-station-ip")

        if not ise_name:
            logger.warning("Session XML has no ISE node name for %s — dumping tags: %s",
                           mac_hyphen, [el.tag for el in root.iter()])
            return {"status": "error",
                    "message": "ISE session found but PSN node name is missing in response"}

        logger.info("Session: mac=%s  psn=%s  nad=%s  ep=%s",
                    mac_hyphen, ise_name, nas_ip, endpoint_ip)
        return {
            "status":      "ok",
            "ise_name":    ise_name,
            "nas_ip":      nas_ip,
            "endpoint_ip": endpoint_ip,
        }

    except urllib.error.HTTPError as exc:
        err_body = ""
        try:
            err_body = exc.read().decode()[:300]
        except Exception:
            pass
        if exc.code == 404:
            logger.warning("Session lookup 404 for %s — not in MnT (device may not be authenticated)", mac_hyphen)
            return {"status": "error",
                    "message": f"No active ISE session for {mac_hyphen} — device may not be authenticated yet"}
        logger.error("Session lookup HTTP %s for %s: %s", exc.code, mac_hyphen, err_body)
        return {"status": "error", "message": f"HTTP {exc.code}: {exc.reason}", "detail": err_body}
    except urllib.error.URLError as exc:
        logger.error("Session lookup connection failed: %s", exc.reason)
        return {"status": "error", "message": f"Connection failed: {exc.reason}"}
    except Exception as exc:
        logger.exception("Session lookup unexpected error for %s", mac_hyphen)
        return {"status": "error", "message": str(exc)}


def send_coa(config: ISEConfig, mac: str, action: str) -> dict:
    """Send CoA via ISE MnT REST API.

    Resolves the PSN name, NAS IP, and endpoint IP from the MnT session
    lookup (Session/MACAddress), then calls the appropriate MnT CoA endpoint:

      Reauth     GET /admin/API/mnt/CoA/Reauth/{psn}/{mac}/0
      Disconnect GET /admin/API/mnt/CoA/Disconnect/{psn}/{mac}/0/{nad_ip}/{ep_ip}
      Port Bounce GET /admin/API/mnt/CoA/Disconnect/{psn}/{mac}/1/{nad_ip}/{ep_ip}

    DISCONNECT_TYPE: 0=Disconnect, 1=Port Bounce, 2=Shutdown
    REAUTH_TYPE:     0=Default, 1=Last, 2=Rerun
    """
    if not config.hostname or not config.username:
        return {"status": "error", "message": "ISE not configured"}

    action_lower = action.lower()
    if action_lower not in ("reauth", "disconnect", "port_bounce"):
        return {"status": "error",
                "message": f"Unknown action '{action}'. Valid: reauth, disconnect, port_bounce"}

    # MnT URLs use uppercase hyphen-separated MAC: XX-XX-XX-XX-XX-XX
    clean = mac.replace(":", "").replace("-", "").upper()
    mac_hyphen = "-".join(clean[i:i+2] for i in range(0, 12, 2))

    # Resolve session info from ISE MnT
    session = _get_session_by_mac(config, mac_hyphen)
    if session.get("status") == "error":
        return session

    psn     = urllib.parse.quote(session["ise_name"],    safe="")
    mac_q   = urllib.parse.quote(mac_hyphen,             safe="")
    nad_q   = urllib.parse.quote(session["nas_ip"],      safe="")
    ep_q    = urllib.parse.quote(session["endpoint_ip"], safe="")
    base    = f"https://{config.hostname}/admin/API/mnt/CoA"

    if action_lower == "reauth":
        url   = f"{base}/Reauth/{psn}/{mac_q}/0"
        label = "Re-auth"
    elif action_lower == "disconnect":
        url   = f"{base}/Disconnect/{psn}/{mac_q}/0/{nad_q}/{ep_q}"
        label = "Disconnect"
    else:  # port_bounce
        url   = f"{base}/Disconnect/{psn}/{mac_q}/1/{nad_q}/{ep_q}"
        label = "Port Bounce"

    logger.info("CoA %s → GET %s", action, url)

    ctx = _make_ssl_context(config.verify_tls)
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": _auth_header(config.username, config.password),
            "Accept": "application/xml",
        },
    )

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
            resp.read()
            logger.info("CoA %s success for %s", action, mac_hyphen)
            return {"status": "ok", "message": f"{label} sent for {mac_hyphen}"}
    except urllib.error.HTTPError as exc:
        err_body = ""
        try:
            err_body = exc.read().decode()[:500]
        except Exception:
            pass
        logger.error("CoA %s failed for %s: HTTP %s — %s", action, mac_hyphen, exc.code, err_body)
        return {"status": "error", "message": f"HTTP {exc.code}: {exc.reason}", "detail": err_body}
    except urllib.error.URLError as exc:
        logger.error("CoA %s connection failed: %s", action, exc.reason)
        return {"status": "error", "message": f"Connection failed: {exc.reason}"}
    except Exception as exc:
        logger.exception("CoA %s unexpected error for %s", action, mac_hyphen)
        return {"status": "error", "message": str(exc)}


def clear_anc_policy(config: ISEConfig, mac: str) -> dict:
    """Clear any ANC policy assigned to an endpoint by MAC address.

    Uses PUT /ers/config/ancendpoint/clear (ISE ERS ANC API).
    Returns {"status": "ok", "message": "..."} or error dict.
    """
    if not config.hostname or not config.username:
        return {"status": "error", "message": "ISE not configured"}

    mac_fmt = mac.replace("-", ":").upper()
    payload = json.dumps({
        "OperationAdditionalData": {
            "additionalData": [
                {"name": "macAddress", "value": mac_fmt},
            ]
        }
    }).encode()

    url = f"https://{config.hostname}/ers/config/ancendpoint/clear"
    ctx = _make_ssl_context(config.verify_tls)
    req = urllib.request.Request(
        url,
        data=payload,
        method="PUT",
        headers={
            "Authorization": _auth_header(config.username, config.password),
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
            body = resp.read()
            try:
                result = json.loads(body) if body else {}
            except Exception:
                result = {}
            return {"status": "ok", "message": f"ANC policy cleared for {mac_fmt}", "response": result}
    except urllib.error.HTTPError as exc:
        body = b""
        try:
            body = exc.read()
        except Exception:
            pass
        body_str = body.decode(errors="replace")[:500] if body else ""
        return {"status": "error", "message": f"HTTP {exc.code}: {exc.reason}", "detail": body_str}
    except urllib.error.URLError as exc:
        return {"status": "error", "message": f"Connection failed: {exc.reason}"}
    except Exception as exc:
        return {"status": "error", "message": str(exc)}


def get_anc_policies(config: ISEConfig) -> dict:
    """Fetch list of available ANC policies from ISE ERS.

    Uses GET /ers/config/ancpolicy (ISE ERS ANC API).
    Returns {"status": "ok", "policies": ["Quarantine", "Shutdown", ...]} or error dict.
    """
    if not config.hostname or not config.username:
        return {"status": "error", "message": "ISE not configured"}

    url = f"https://{config.hostname}/ers/config/ancpolicy?size=100&page=1"
    ctx = _make_ssl_context(config.verify_tls)
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": _auth_header(config.username, config.password),
            "Accept": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
            data = json.loads(resp.read())
        resources = data.get("SearchResult", {}).get("resources", [])
        names = [r["name"] for r in resources if "name" in r]
        return {"status": "ok", "policies": names}
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode()[:500]
        except Exception:
            pass
        return {"status": "error", "message": f"HTTP {exc.code}: {exc.reason}", "detail": body}
    except urllib.error.URLError as exc:
        return {"status": "error", "message": f"Connection failed: {exc.reason}"}
    except Exception as exc:
        return {"status": "error", "message": str(exc)}
