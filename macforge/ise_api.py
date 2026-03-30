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

logger = logging.getLogger(__name__)

DATA_DIR = Path(os.environ.get("MACFORGE_DATA_DIR", "/app/data"))
CERTS_DIR = DATA_DIR / "certs"
ISE_CONFIG_PATH = DATA_DIR / "ise_config.json"


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


def send_coa(config: ISEConfig, mac: str, action: str) -> dict:
    """Send Change of Authorization (CoA) via ISE ERS session MAC endpoints.

    action: 'reauth' | 'disconnect' | 'port_bounce'
    Uses PUT /ers/config/session/{MAC}/reAuth or /disconnect.
    No RADIUS session ID needed — MAC is used directly.
    Returns {"status": "ok", "message": "..."} or error dict.
    """
    if not config.hostname or not config.username:
        return {"status": "error", "message": "ISE not configured"}

    # ISE session endpoints use uppercase colon-separated MAC
    mac_fmt = mac.replace("-", ":").upper()

    action_map = {
        "reauth": "reAuth",
        "disconnect": "disconnect",
        "port_bounce": "disconnect",  # closest ISE session action
    }
    url_suffix = action_map.get(action.lower())
    if not url_suffix:
        return {
            "status": "error",
            "message": f"Unknown CoA action '{action}'. Valid: reauth, disconnect, port_bounce",
        }

    url = f"https://{config.hostname}/ers/config/session/{urllib.parse.quote(mac_fmt)}/{url_suffix}"
    ctx = _make_ssl_context(config.verify_tls)
    req = urllib.request.Request(
        url,
        data=b"",           # PUT with empty body
        method="PUT",
        headers={
            "Authorization": _auth_header(config.username, config.password),
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Content-Length": "0",
        },
    )

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
            body = resp.read()
            try:
                result = json.loads(body) if body else {}
            except Exception:
                result = {}
            return {"status": "ok", "message": f"CoA {url_suffix} sent to {mac_fmt}", "response": result}
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
