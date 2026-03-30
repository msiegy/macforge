"""802.1X supplicant management via wpa_supplicant and macvlan interfaces."""

from __future__ import annotations

import asyncio
import logging
import os
import re
import time
from pathlib import Path
from typing import Optional

from macforge.models import AuthFlowEvent, AuthProfile

logger = logging.getLogger(__name__)

DATA_DIR = Path(os.environ.get("MACFORGE_DATA_DIR", "/app/data"))
CERTS_DIR = DATA_DIR / "certs"
WPA_RUN_DIR = Path("/tmp/macforge_wpa")

# apt wpasupplicant — used for PEAP, EAP-TLS, EAP-FAST, EAP-TTLS (has working MSCHAPv2)
WPA_SUPPLICANT_BIN = "/usr/sbin/wpa_supplicant"
# source-built binary — required ONLY for TEAP (apt package lacks CONFIG_EAP_TEAP=y)
WPA_SUPPLICANT_TEAP_BIN = "/usr/local/sbin/wpa_supplicant_teap"
WPA_CLI_BIN = "wpa_cli"


def _wpa_bin_for_method(method: str) -> str:
    """Return the correct wpa_supplicant binary for the given EAP method.

    The source-built binary (wpa_supplicant_teap) is required ONLY for TEAP.
    The Debian Bookworm apt package deliberately omits CONFIG_EAP_TEAP=y — there
    is no runtime workaround; TEAP support must be compiled in.

    All other methods (PEAP, EAP-TLS, EAP-FAST, EAP-TTLS) use the apt binary.
    EAP-TLS on the apt binary was confirmed working against Cisco ISE in session 13
    (EAP SUCCESS in ~2s; the prior routing to source-built was caused by a ca_cert
    bug, not a binary capability gap).
    """
    if method == "teap":
        return WPA_SUPPLICANT_TEAP_BIN
    return WPA_SUPPLICANT_BIN

_IFACE_SAFE = re.compile(r"^[a-zA-Z0-9_-]+$")


def _safe_iface_name(mac: str) -> str:
    """Generate a unique macvlan interface name from the full MAC address.

    Uses all 12 hex chars (= 14-char name with 'mf' prefix), which is
    within Linux's IFNAMSIZ-1 (15 char) limit and guarantees no collisions
    between devices whose MACs only differ in the first 3 bytes.
    """
    return "mf" + mac.replace(":", "")


def _resolve_cert_path(filename: Optional[str]) -> str:
    """Resolve a certificate filename to its absolute path."""
    if not filename:
        return ""
    p = CERTS_DIR / filename
    return str(p)


def generate_wpa_conf(auth: AuthProfile, mac: str) -> str:
    """Generate wpa_supplicant.conf content for a given AuthProfile."""
    method = auth.method.lower()
    lines = [
        "ctrl_interface=DIR=/var/run/wpa_supplicant",
        f"eapol_version={auth.eapol_version}",
        "ap_scan=0",
        # Re-authentication period on wired 802.1X is driven by the switch
        # (dot1x timers) and ISE Session-Timeout RADIUS attribute — not by
        # the supplicant. wpa_supplicant has no eap_reauth_period config field;
        # fast_reauth (TLS session resumption) defaults to 1 (enabled) globally.
        "",
        "network={",
        "  key_mgmt=IEEE8021X",
        f'  identity="{auth.identity}"',
        # Note: TLS session resumption (fast_reauth) is a wpa_supplicant global
        # option that defaults to 1 — no explicit config line needed.
    ]

    if auth.anonymous_identity:
        lines.append(f'  anonymous_identity="{auth.anonymous_identity}"')

    if method in ("peap-mschapv2", "peap"):
        lines.append("  eap=PEAP")
        if auth.password is not None:
            lines.append(f'  password="{auth.password}"')
        phase2 = auth.phase2 or "MSCHAPV2"
        lines.append(f'  phase2="auth={phase2}"')
        lines.append(f'  phase1="peapver={auth.peap_version}"')

    elif method == "eap-tls":
        lines.append("  eap=TLS")
        if auth.client_cert:
            cert_path = _resolve_cert_path(auth.client_cert)
            if not Path(cert_path).exists():
                raise FileNotFoundError(
                    f"EAP-TLS client cert not found: {cert_path}. "
                    "Upload it on the Certificates page first."
                )
            lines.append(f'  client_cert="{cert_path}"')
        else:
            raise ValueError(
                "EAP-TLS requires a client certificate. "
                "Select one in the 802.1X configuration drawer."
            )
        if auth.private_key:
            key_path = _resolve_cert_path(auth.private_key)
            if not Path(key_path).exists():
                raise FileNotFoundError(
                    f"EAP-TLS private key not found: {key_path}. "
                    "Upload it on the Certificates page first."
                )
            lines.append(f'  private_key="{key_path}"')
        else:
            raise ValueError(
                "EAP-TLS requires a private key. "
                "Select one in the 802.1X configuration drawer."
            )
        if auth.private_key_password:
            lines.append(f'  private_key_passwd="{auth.private_key_password}"')

    elif method in ("eap-fast", "fast"):
        lines.append("  eap=FAST")
        if auth.password is not None:
            lines.append(f'  password="{auth.password}"')
        phase2 = auth.phase2 or "MSCHAPV2"
        lines.append(f'  phase2="auth={phase2}"')
        if auth.pac_provisioning:
            lines.append('  phase1="fast_provisioning=1"')
        if auth.pac_file:
            lines.append(f'  pac_file="{_resolve_cert_path(auth.pac_file)}"')

    elif method in ("eap-ttls", "ttls"):
        lines.append("  eap=TTLS")
        if auth.password is not None:
            lines.append(f'  password="{auth.password}"')
        phase2 = auth.phase2 or "MSCHAPV2"
        lines.append(f'  phase2="auth={phase2}"')

    elif method == "teap":
        # TEAP (RFC 7170) — requires wpa_supplicant >= 2.10
        # Uses a TLS outer tunnel carrying TLV objects for inner auth data.
        # TLVs enable chained user+machine auth, cert renewal (PKCS#10 TLV),
        # and password change TLVs — all handled transparently by wpa_supplicant.
        # Cisco ISE defaults to PAC-less TEAP (full TLS handshake, no .pac file).
        # ca_cert is handled by the shared trailing block below.
        # Do NOT write ca_cert="" here — empty string causes
        # SSL_CTX_load_verify_locations("", NULL) → "EAP-TEAP: Failed to initialize SSL".
        # Omitting ca_cert entirely passes NULL → SSL_VERIFY_NONE (same as other methods).
        lines.append("  eap=TEAP")
        # wpa_supplicant's TEAP implementation reuses EAP-FAST infrastructure
        # and requires pac_file to be set even for PAC-less TEAP (ISE default).
        # The file does not need to exist — wpa_supplicant uses the path as a
        # cache location. Without this line: "EAP-TEAP: No PAC file configured".
        mac_clean = mac.replace(":", "")
        lines.append(f'  pac_file="/tmp/macforge_wpa/teap_{mac_clean}.pac"')
        inner = (auth.teap_inner_method or "MSCHAPV2").upper()

        if inner == "MSCHAPV2":
            # Straightforward: user password inside TEAP TLS tunnel.
            # TEAP inner methods are EAP-wrapped, so wpa_supplicant needs
            # autheap= (not auth=). phase2="auth=MSCHAPV2" is PEAP/TTLS syntax
            # and causes wpa_supplicant to immediately NAK TEAP (step 12851).
            lines.append('  phase2="autheap=MSCHAPV2"')
            if auth.password is not None:
                lines.append(f'  password="{auth.password}"')

        elif inner == "EAP-TLS":
            # NOTE: wpa_supplicant does NOT support EAP-TLS as a TEAP inner method.
            # phase2="autheap=TLS" is written but the TEAP code path ignores it.
            # When ISE proposes MSCHAPv2 for the inner method, wpa_supplicant
            # does not NAK it — it falls through and attempts MSCHAPv2 with no
            # password → "EAP-MSCHAPV2: Password not configured" → EAP-FAILURE.
            #
            # What actually happens when ISE has "Accept client cert during tunnel
            # establishment" ENABLED (ISE default): the cert is presented in the
            # OUTER TLS handshake (step 12811), inner method is skipped (step 11563),
            # and ISE authenticates via the outer cert. This produces ISE protocol
            # "TEAP (EAP-TLS)" and may succeed depending on your AuthZ policy.
            #
            # When that ISE setting is DISABLED: wpa_supplicant receives an
            # MSCHAPv2 inner-method challenge, has no password → EAP-FAILURE → reject.
            #
            # The cert fields are still written so the outer TLS mutual auth works.
            # autheap=TLS is written as a best-effort; actual inner EAP-TLS is
            # not achievable with wpa_supplicant's current TEAP implementation.
            lines.append('  phase2="autheap=TLS"')
            if auth.client_cert:
                lines.append(f'  client_cert="{_resolve_cert_path(auth.client_cert)}"')
            if auth.private_key:
                lines.append(f'  private_key="{_resolve_cert_path(auth.private_key)}"')
            if auth.private_key_password:
                lines.append(f'  private_key_passwd="{auth.private_key_password}"')

        elif inner == "CHAINED":
            # EAP chaining: machine TLS cert (outer) + user MSCHAPv2 (inner).
            # wpa_supplicant 2.10+ supports machine_cert / machine_key fields for
            # the outer TLS handshake (machine auth), with identity/password for
            # inner MSCHAPv2 (user auth).
            #
            # NOTE on observed behavior (session 14 testing):
            # When ISE has "Accept client cert during tunnel establishment" ENABLED,
            # ISE uses the outer cert for BOTH user and machine via EAP chaining
            # (ISE steps 11627, 11557). ISE reports both as "TEAP (EAP-TLS)" and
            # EapChainingResult "User succeeded and machine succeeded". This is
            # NOT true RFC 7170 chaining — it is ISE consuming the outer cert
            # twice. The machine_cert/machine_identity/password inner-MSCHAPv2
            # path (true chaining) has not been confirmed tested.
            #
            # ISE policy Compound Condition for true chaining:
            #   Network Access:EapChainingResult EQUALS
            #   "User and Machine both Succeeded"
            #
            # wpa_supplicant mapping for true chaining:
            #   - outer TLS identity = machine_identity (e.g. host/WIN11-LAB$)
            #   - outer TLS client cert = machine_cert / machine_key
            #   - inner EAP-MSCHAPv2 = identity / password (user)
            #   autheap= required; auth= is PEAP/TTLS non-EAP syntax.
            lines.append('  phase2="autheap=MSCHAPV2"')
            # Machine identity for outer TLS (Windows: DOMAIN\HOSTNAME$  or  host/HOSTNAME$)
            if auth.machine_identity:
                lines.append(f'  machine_identity="{auth.machine_identity}"')
            if auth.password is not None:
                lines.append(f'  password="{auth.password}"')
            if auth.machine_cert:
                lines.append(f'  client_cert="{_resolve_cert_path(auth.machine_cert)}"')
            if auth.machine_key:
                lines.append(f'  private_key="{_resolve_cert_path(auth.machine_key)}"')
            if auth.machine_key_password:
                lines.append(f'  private_key_passwd="{auth.machine_key_password}"')
        else:
            # Fallback for unknown inner method (TEAP always uses autheap=)
            lines.append(f'  phase2="autheap={inner}"')
            if auth.password is not None:
                lines.append(f'  password="{auth.password}"')

    if auth.validate_server_cert and auth.ca_cert:
        resolved_ca = _resolve_cert_path(auth.ca_cert)
        if Path(resolved_ca).exists():
            # validate_server_cert=True + ca_cert set + file present → verify ISE cert
            lines.append(f'  ca_cert="{resolved_ca}"')
        else:
            logger.warning(
                "validate_server_cert=True but CA cert '%s' not found at %s — "
                "server cert verification disabled. Upload the CA cert on the "
                "Certificates page.",
                auth.ca_cert, resolved_ca,
            )
            # Fall through — no ca_cert line written (see below)

    # When validate_server_cert=False (or ca_cert missing/not found), do NOT
    # write ca_cert at all.  wpa_supplicant docs: "If ca_cert and ca_path are
    # not included, server certificate will not be verified."  This is the only
    # correct way to disable verification:
    #   ca_cert=""  → wpa_supplicant passes "" to tls_connection_ca_cert()
    #                 → SSL_CTX_load_verify_locations("", NULL) → ENOENT
    #   ca_cert omitted → NULL pointer path → SSL_VERIFY_NONE, no file I/O
    # Note: The ca_cert="" workaround was previously used for TEAP (prevents a
    # double-NAK on the outer TLS handshake); TEAP is handled separately.

    if auth.fragment_size != 1398:
        lines.append(f"  fragment_size={auth.fragment_size}")

    lines.append("}")
    lines.append("")
    return "\n".join(lines)


async def check_wpa_supplicant_version() -> tuple[str, bool]:
    """Return (version_string, teap_supported) for the installed wpa_supplicant.

    TEAP requires wpa_supplicant >= 2.10 AND must be compiled with
    CONFIG_EAP_TEAP=y. Both conditions are checked here.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            WPA_SUPPLICANT_BIN, "-v",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        output = (stdout or stderr).decode()
        # wpa_supplicant -v outputs: "wpa_supplicant v2.10"
        match = re.search(r"v(\d+)\.(\d+)", output)
        if match:
            major, minor = int(match.group(1)), int(match.group(2))
            version_str = f"{major}.{minor}"
            version_ok = (major > 2) or (major == 2 and minor >= 10)
            if not version_ok:
                logger.warning(
                    "wpa_supplicant %s detected — TEAP requires >= 2.10. "
                    "TEAP authentication will fail on this version.",
                    version_str,
                )
                return version_str, False
            # Version is OK; check if TEAP EAP method is compiled in
            teap_supported = await _probe_teap_support()
            if teap_supported:
                logger.info("wpa_supplicant %s — TEAP supported.", version_str)
            else:
                logger.warning(
                    "wpa_supplicant %s found but TEAP is not compiled in "
                    "(CONFIG_EAP_TEAP=y missing). "
                    "Rebuild the Docker image: docker build --no-cache -t macforge .",
                    version_str,
                )
            return version_str, teap_supported
    except FileNotFoundError:
        logger.error("wpa_supplicant not found. 802.1X authentication unavailable.")
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not determine wpa_supplicant version: %s", exc)
    return "unknown", False


async def _probe_teap_support() -> bool:
    """Return True if wpa_supplicant has TEAP compiled in.

    Writes a minimal TEAP config to a temp file and checks whether
    wpa_supplicant rejects 'TEAP' as an unknown EAP method.
    """
    import tempfile
    test_conf = (
        "ctrl_interface=DIR=/tmp/mf_teap_probe\n"
        "ap_scan=0\n"
        "network={\n"
        "  key_mgmt=IEEE8021X\n"
        "  identity=\"probe\"\n"
        "  eap=TEAP\n"
        "  phase2=\"auth=MSCHAPV2\"\n"
        "  password=\"probe\"\n"
        "}\n"
    )
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".conf", delete=False, prefix="/tmp/mf_teap_probe_"
        ) as f:
            f.write(test_conf)
            tmp = f.name

        proc = await asyncio.create_subprocess_exec(
            WPA_SUPPLICANT_TEAP_BIN,
            "-c", tmp,
            "-i", "lo",     # interface won't be used before we kill it
            "-D", "wired",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=2.0)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            # Timed out = started without a parse error = TEAP is present
            return True

        output = (stdout + stderr).decode()
        return "unknown EAP method 'TEAP'" not in output and "unknown EAP method \"TEAP\"" not in output

    except Exception as exc:
        logger.debug("TEAP probe failed (assuming unsupported): %s", exc)
        return False
    finally:
        if tmp:
            Path(tmp).unlink(missing_ok=True)


async def _destroy_any_iface_with_mac(mac: str) -> None:
    """Delete every network interface currently holding the given MAC address.

    Handles stale interfaces from previous naming schemes (e.g. old 6-char
    suffix names left behind after an upgrade to the 12-char scheme).
    """
    mac_lower = mac.lower()
    proc = await asyncio.create_subprocess_exec(
        "ip", "-o", "link", "show",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate()
    for line in stdout.decode().splitlines():
        if mac_lower not in line.lower():
            continue
        # Line format: "44: mfEDEC90@eth0: <...> link/ether 3c:d9:2b:ed:ec:90 ..."
        parts = line.split(":")
        if len(parts) < 2:
            continue
        iface = parts[1].strip().split("@")[0]
        logger.warning("Removing stale interface %s holding MAC %s", iface, mac)
        del_proc = await asyncio.create_subprocess_exec(
            "ip", "link", "del", iface,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await del_proc.communicate()


async def create_macvlan(parent_iface: str, mac: str) -> str:
    """Create a macvlan interface with the given MAC on the parent interface.

    Returns the name of the created interface.
    """
    iface_name = _safe_iface_name(mac)
    if not _IFACE_SAFE.match(iface_name):
        raise ValueError(f"Invalid interface name: {iface_name}")

    # Remove any interface already holding this MAC — including stale ones
    # from old naming schemes left behind after a container rebuild/upgrade.
    await _destroy_any_iface_with_mac(mac)

    # Bring the parent interface UP unconditionally before macvlan creation.
    # Always issuing `ip link set <iface> up` is safe — it is a no-op when the
    # interface is already up.  Skipping on operstate=="unknown" was unreliable:
    # some Linux drivers (e.g. virtio-net, vmxnet3) report "unknown" for a NIC
    # that is administratively down or has no carrier, causing MACforge to skip
    # the command and leave the interface down, requiring manual intervention.
    # After bringing it up, wait up to 3 s for carrier so Ethernet autoneg
    # completes before the macvlan is created on top.
    operstate_path = Path(f"/sys/class/net/{parent_iface}/operstate")
    try:
        operstate = operstate_path.read_text().strip()
    except OSError:
        operstate = "unknown"

    logger.info(
        "Ensuring parent interface %s is up (current operstate: %s)",
        parent_iface, operstate,
    )
    up_proc = await asyncio.create_subprocess_exec(
        "ip", "link", "set", parent_iface, "up",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, up_err = await up_proc.communicate()
    if up_proc.returncode != 0:
        logger.warning(
            "Could not bring up %s: %s",
            parent_iface, up_err.decode().strip(),
        )
    else:
        # Poll operstate briefly so we don't create macvlans on a down parent.
        # Ethernet autoneg typically completes within 1–2 s.
        for _ in range(15):
            try:
                new_state = operstate_path.read_text().strip()
            except OSError:
                break
            if new_state in ("up", "unknown"):
                break
            await asyncio.sleep(0.2)
        logger.info("Parent interface %s ready (operstate: %s)", parent_iface,
                    operstate_path.read_text().strip() if operstate_path.exists() else "?")

    cmds = [
        ["ip", "link", "add", iface_name, "link", parent_iface,
         "type", "macvlan", "mode", "bridge"],
        ["ip", "link", "set", iface_name, "address", mac],
        ["ip", "link", "set", iface_name, "up"],
    ]

    for cmd in cmds:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate()
        if proc.returncode != 0:
            err = stderr.decode().strip()
            raise RuntimeError(
                f"Failed to run {' '.join(cmd)}: {err}"
            )

    logger.info("Created macvlan %s (MAC %s) on %s", iface_name, mac, parent_iface)
    return iface_name


async def destroy_macvlan(mac: str) -> None:
    """Remove the macvlan interface for the given MAC."""
    iface_name = _safe_iface_name(mac)
    proc = await asyncio.create_subprocess_exec(
        "ip", "link", "del", iface_name,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await proc.communicate()
    if proc.returncode != 0:
        err = stderr.decode().strip()
        if "Cannot find device" not in err:
            logger.warning("Failed to destroy macvlan %s: %s", iface_name, err)
    else:
        logger.info("Destroyed macvlan %s", iface_name)


async def _kill_existing_wpa(iface_name: str) -> None:
    """Kill any wpa_supplicant already running on this interface."""
    pid_path = WPA_RUN_DIR / f"{iface_name}.pid"
    if pid_path.exists():
        try:
            pid = int(pid_path.read_text().strip())
            os.kill(pid, 15)
            logger.info("Killed stale wpa_supplicant pid %d on %s", pid, iface_name)
            await asyncio.sleep(0.3)
        except (ValueError, ProcessLookupError, OSError):
            pass
        finally:
            pid_path.unlink(missing_ok=True)

    proc = await asyncio.create_subprocess_exec(
        "pkill", "-f", f"wpa_supplicant.*{iface_name}",
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    await proc.communicate()

    ctrl_sock = Path(f"/var/run/wpa_supplicant/{iface_name}")
    if ctrl_sock.exists():
        ctrl_sock.unlink(missing_ok=True)


# RFC 3748 + IANA EAP Method Types
_EAP_METHOD_NAMES: dict[str, str] = {
    "1":  "Identity",
    "4":  "MD5",
    "6":  "OTP",
    "13": "EAP-TLS",
    "17": "LEAP",
    "21": "EAP-TTLS",
    "25": "PEAP",
    "43": "EAP-FAST",
    "55": "TEAP",
    "254": "EAP-EXPANDED",
}


def _parse_eap_event(line: str, step: int, ts: float) -> Optional[AuthFlowEvent]:
    """Parse a wpa_supplicant log line into an AuthFlowEvent.

    Returns None if the line is not a meaningful auth event.

    Actor attribution notes:
    - "authenticator": the switch/NAD initiated the event (e.g. EAP-Request sent
      to the supplicant). Inferred from wpa_supplicant perspective — the supplicant
      received it, so the switch must have sent it.
    - "radius": ISE/RADIUS server proposed or decided the outcome.
    - "supplicant": wpa_supplicant responded or completed an action locally.
    """
    line = line.strip()
    if not line:
        return None

    # Mapping of (substring_match, actor, event_type, detail_template)
    PATTERNS = [
        ("CTRL-EVENT-EAP-STARTED",        "authenticator", "identity",       "Switch sent EAP-Request/Identity — supplicant detected auth start"),
        ("CTRL-EVENT-EAP-PROPOSED-METHOD", "radius",        "method_propose", "ISE proposed EAP method"),
        ("CTRL-EVENT-EAP-METHOD",          "supplicant",    "method_accept",  "Supplicant selected"),
        ("EAP-PEAP: Start",                "supplicant",    "tls_start",      "PEAP outer TLS tunnel starting"),
        ("EAP-TEAP: Start",                "supplicant",    "tls_start",      "TEAP outer TLS tunnel starting"),
        ("EAP-TLS: Start",                 "supplicant",    "tls_start",      "EAP-TLS mutual TLS handshake starting"),
        ("TLS: Phase 1 done",              "supplicant",    "tls_done",       "Outer TLS tunnel established"),
        ("CTRL-EVENT-EAP-PEER-CERT",       "supplicant",    "cert_received",  "Server certificate received"),
        ("CTRL-EVENT-EAP-PEER-ALT",        "supplicant",    "cert_san",       "Server cert SAN"),
        ("EAP-MSCHAPV2: Authentication succeeded", "supplicant", "inner_auth", "MSCHAPv2 inner authentication passed"),
        ("EAP-MSCHAPV2: Authentication failed",    "supplicant", "failure",    "MSCHAPv2 inner authentication failed"),
        ("CTRL-EVENT-EAP-SUCCESS",         "radius",        "success",        "EAP-Success received — corresponds to RADIUS Access-Accept from ISE"),
        ("CTRL-EVENT-EAP-FAILURE",         "radius",        "failure",        "EAP-Failure received — corresponds to RADIUS Access-Reject from ISE"),
        ("CTRL-EVENT-CONNECTED",           "authenticator", "connected",      "802.1X port authorized by switch — RADIUS AV pairs (VLAN/SGT/dACL) in ISE Policy tab"),
        ("CTRL-EVENT-DISCONNECTED",        "authenticator", "failure",        "Port disconnected"),
        ("EAP-TEAP",                       "supplicant",    "info",           "TEAP negotiation event"),
        ("TLV type=",                      "supplicant",    "teap_tlv",       "TEAP TLV exchange"),
        ("method=55",                      "supplicant",    "method_accept",  "TEAP method (55) negotiated"),
        ("unknown EAP method 'TEAP'",      "supplicant",    "failure",        "TEAP not compiled into wpa_supplicant binary"),
        ("TLS: Handshake failed",          "supplicant",    "failure",        "TLS handshake failed — check cert/CA configuration"),
        # TLS certificate verification failure — fired before SSL Alert
        ("CTRL-EVENT-EAP-TLS-CERT-ERROR", "supplicant",    "cert_error",     "TLS certificate verification failed"),
        # SSL fatal alert sent by supplicant toward ISE
        ("SSL3 alert: write",              "supplicant",    "ssl_alert",      "SSL fatal alert sent to ISE"),
    ]

    for substr, actor, event_type, detail in PATTERNS:
        if substr not in line:
            continue

        # cert_error: extract reason and cert CN
        if event_type == "cert_error":
            try:
                # CTRL-EVENT-EAP-TLS-CERT-ERROR reason=N depth=D subject='...'
                # Also check the preceding log line pattern:
                # TLS: Certificate verification failed, error N (reason text)
                reason_str = ""
                cn_str = ""
                if "reason=" in line:
                    reason_str = line.split("reason=", 1)[1].split()[0]
                if "err=" in line:
                    err_part = line.split("err=", 1)[1].strip("'\"").split("'")[0].split('"')[0]
                    reason_str = err_part or reason_str
                if "subject=" in line:
                    cn_part = line.split("subject=", 1)[1].strip("'\" ")
                    # extract CN= value
                    if "CN=" in cn_part:
                        cn_str = cn_part.split("CN=", 1)[1].split("/")[0].split("'")[0].strip()
                    else:
                        cn_str = cn_part.split("'")[0].split('"')[0].strip()
                detail = "Server cert rejected"
                if cn_str:
                    detail += f": {cn_str}"
                if reason_str:
                    detail += f" ({reason_str})"
            except Exception:
                pass

        # ssl_alert: extract alert description
        elif event_type == "ssl_alert":
            try:
                # SSL: SSL3 alert: write (local SSL3 detected an error):fatal:unknown CA
                if "fatal:" in line:
                    alert = line.split("fatal:", 1)[1].strip()
                    detail = f"SSL fatal alert → ISE: {alert}"
            except Exception:
                pass

        # Method number → name enrichment
        elif event_type in ("method_propose", "method_accept"):
            try:
                # Two log formats:
                #   CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=13      (method=N)
                #   CTRL-EVENT-EAP-METHOD EAP vendor 0 method 25 (PEAP) selected  (method N)
                m_match = re.search(r'\bmethod[= ](\d+)', line)
                num = m_match.group(1) if m_match else ""
                # Try to get a human name: first from parentheses in the line
                # e.g. "EAP vendor 0 method 25 (PEAP) selected", then from our lookup table
                name = None
                if "(" in line and ")" in line:
                    bracketed = line.split("(", 1)[1].split(")", 1)[0].strip()
                    if bracketed and not bracketed.isdigit():
                        name = bracketed
                if not name:
                    name = _EAP_METHOD_NAMES.get(num)
                if event_type == "method_accept":
                    # Build "Supplicant selected PEAP (method 25)"
                    detail = f"Supplicant selected {name or ('method ' + num)} (method {num})" if num else detail
                else:
                    # method_propose: "ISE proposed EAP method — EAP-TLS (method 13)"
                    if name:
                        detail = detail + f" — {name} (method {num})"
                    elif num:
                        detail = detail + f" — method {num}"
            except Exception:
                pass

        # Server cert: extract CN only; show hash truncated
        elif event_type == "cert_received" and "depth=" in line:
            try:
                depth = line.split("depth=", 1)[1].split()[0]
                cn = None
                if "CN=" in line:
                    cn = line.split("CN=", 1)[1].split("/")[0].split("'")[0].strip()
                elif "subject=" in line:
                    cn = line.split("subject=", 1)[1].split(" hash=")[0].strip(" '")
                hash_val = ""
                if " hash=" in line:
                    h = line.split(" hash=", 1)[1].strip()
                    hash_val = f" [{h[:16]}…]" if len(h) > 16 else f" [{h}]"
                depth_label = "" if depth == "0" else f" (chain depth {depth})"
                detail = f"Server cert: {cn or 'unknown CN'}{depth_label}{hash_val}"
            except Exception:
                pass

        # SAN: extract DNS / email
        elif event_type == "cert_san":
            try:
                san_part = line.split("depth=", 1)[1]
                san_val = " ".join(san_part.split()[1:])
                detail = f"Server cert SAN: {san_val}"
            except Exception:
                pass

        return AuthFlowEvent(
            timestamp=ts,
            step=step,
            actor=actor,
            event_type=event_type,
            detail=detail,
            raw_log_line=line,
        )
    return None


def _dump_wpa_log(iface_name: str, log_path: "Path", trigger: str) -> None:
    """Emit the last 50 lines of a wpa_supplicant log to the app logger at ERROR level.

    Called on EAP FAILURE / auth rejection so the full exchange is visible in
    docker logs without needing to exec into the container.
    Also writes a copy to _lastfail.log in WPA_RUN_DIR for post-mortem inspection.
    """
    if not log_path.exists():
        logger.error("wpa auth failed (%s) on %s — no log file found", trigger, iface_name)
        return

    content = log_path.read_text(errors="replace")
    # Preserve a copy immediately in case cleanup races
    lastfail = WPA_RUN_DIR / f"{iface_name}_lastfail.log"
    try:
        lastfail.write_text(content)
    except OSError:
        pass

    lines = content.splitlines()
    tail = "\n".join(lines[-50:]) if len(lines) > 50 else content
    logger.error(
        "wpa_supplicant log for %s (trigger=%s) — last 50 lines:\n%s",
        iface_name, trigger, tail,
    )
    # Also print directly to stderr so it's always visible in docker logs
    # even if the app logger level or handler swallows it.
    import sys
    print(
        f"[WPA-FAIL] {iface_name} trigger={trigger}\n{tail}",
        file=sys.stderr, flush=True,
    )


def _raise_wpa_error(err: str, method: str) -> None:
    """Parse a wpa_supplicant error string and raise with an actionable message."""
    # TEAP not compiled into the binary
    if "unknown EAP method 'TEAP'" in err or 'unknown EAP method "TEAP"' in err:
        raise RuntimeError(
            "TEAP is not compiled into the wpa_supplicant binary in this container "
            "(CONFIG_EAP_TEAP=y missing from the build). "
            "Rebuild the Docker image: docker build --no-cache -t macforge ."
        )
    # machine_cert/machine_key unknown — these fields don't exist in wpa_supplicant 2.10;
    # Chained mode uses client_cert/private_key for the machine cert instead.
    if "unknown network field 'machine_cert'" in err or "unknown network field 'machine_key'" in err:
        raise RuntimeError(
            "wpa_supplicant 2.10 does not have machine_cert / machine_key fields. "
            "Update MACforge and push the fix into the container: "
            "git pull && "
            "docker cp ~/macforge/macforge/dot1x.py macforge:/app/macforge/dot1x.py && "
            "docker restart macforge"
        )
    # Config parse failure — surface the specific unknown field(s) clearly
    if "failed to parse network block" in err or "unknown network field" in err:
        bad_lines = [l.strip() for l in err.splitlines() if "unknown network field" in l]
        detail = "; ".join(bad_lines) if bad_lines else err[:400]
        raise RuntimeError(
            f"wpa_supplicant rejected the config — {detail}. "
            "Check that MACforge is up to date (git pull + docker cp or rebuild)."
        )
    # Truncate raw error to a readable length for the UI
    short_err = err[:800] if len(err) > 800 else err
    raise RuntimeError(f"wpa_supplicant failed to start: {short_err}")


async def start_wpa_supplicant(
    mac: str,
    auth: AuthProfile,
    parent_iface: str,
) -> tuple[str, asyncio.subprocess.Process]:
    """Start a wpa_supplicant instance for the given device.

    Returns (macvlan_iface_name, process).
    """
    WPA_RUN_DIR.mkdir(parents=True, exist_ok=True)
    CERTS_DIR.mkdir(parents=True, exist_ok=True)
    Path("/var/run/wpa_supplicant").mkdir(parents=True, exist_ok=True)

    iface_name = await create_macvlan(parent_iface, mac)

    await _kill_existing_wpa(iface_name)

    conf_path = WPA_RUN_DIR / f"{iface_name}.conf"
    pid_path = WPA_RUN_DIR / f"{iface_name}.pid"
    log_path = WPA_RUN_DIR / f"{iface_name}.log"

    log_path.unlink(missing_ok=True)

    conf_content = generate_wpa_conf(auth, mac)
    conf_path.write_text(conf_content)

    # Log config at DEBUG level with passwords masked — useful for diagnosing
    # wpa_supplicant config parse errors without leaking credentials.
    masked = re.sub(r'(password|passwd)="[^"]*"', r'\1="***"', conf_content)
    logger.debug("wpa_supplicant config for %s:\n%s", mac, masked)

    wpa_bin = _wpa_bin_for_method(auth.method)
    # Fallback: if the preferred binary doesn't exist (container not yet rebuilt),
    # use the apt binary. Log a warning so it's visible in docker logs.
    if not Path(wpa_bin).exists():
        logger.warning(
            "Preferred binary %s not found for method=%s — falling back to %s. "
            "Rebuild the Docker image for full support.",
            wpa_bin, auth.method, WPA_SUPPLICANT_BIN,
        )
        wpa_bin = WPA_SUPPLICANT_BIN
    logger.debug("Using wpa_supplicant binary: %s (method=%s)", wpa_bin, auth.method)
    cmd = [
        wpa_bin,
        "-i", iface_name,
        "-c", str(conf_path),
        "-D", "wired",
        "-P", str(pid_path),
        "-f", str(log_path),
        "-B",
    ]

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await proc.communicate()
    if proc.returncode != 0:
        err = stderr.decode().strip()
        if not err and log_path.exists():
            # Read full log — TEAP parse errors appear at the START, not the end
            err = log_path.read_text().strip()
        logger.debug("wpa_supplicant raw error for %s (method=%s):\n%s", mac, auth.method, err)
        # Clean up the macvlan we just created so next connect starts fresh
        await destroy_macvlan(mac)
        _raise_wpa_error(err, auth.method)

    logger.info(
        "wpa_supplicant started on %s for %s (method=%s)",
        iface_name, mac, auth.method,
    )
    return iface_name, proc


async def monitor_wpa_auth(
    iface_name: str, timeout: float = 30.0
) -> tuple[str, list[AuthFlowEvent]]:
    """Monitor wpa_supplicant for authentication result.

    Returns a tuple of:
      - result string: "authorized" | "auth_failed" | "timeout"
      - list of AuthFlowEvent parsed from the wpa_supplicant log
    """
    log_path = WPA_RUN_DIR / f"{iface_name}.log"
    deadline = time.monotonic() + timeout
    last_size = 0
    events: list[AuthFlowEvent] = []
    step = 0

    while time.monotonic() < deadline:
        await asyncio.sleep(0.5)

        if not log_path.exists():
            continue

        content = log_path.read_text()
        if len(content) <= last_size:
            continue
        new_content = content[last_size:]
        last_size = len(content)
        ts = time.time()

        # Parse new lines into AuthFlowEvents; stop at first terminal event
        # so that reauthentications starting in the same read window are not
        # captured — we only want the initial auth exchange.
        try:
            for line in new_content.splitlines():
                evt = _parse_eap_event(line, step, ts)
                if evt is not None:
                    events.append(evt)
                    step += 1
                    if evt.event_type in ("success", "connected", "failure"):
                        break  # stop capturing; terminal event found
        except Exception:
            pass  # never let parse errors interrupt auth monitoring

        if "CTRL-EVENT-EAP-SUCCESS" in new_content:
            logger.info("EAP SUCCESS on %s", iface_name)
            return "authorized", events
        if "CTRL-EVENT-CONNECTED" in new_content:
            logger.info("802.1X CONNECTED on %s", iface_name)
            return "authorized", events
        if "CTRL-EVENT-EAP-FAILURE" in new_content:
            logger.info("EAP FAILURE on %s", iface_name)
            _dump_wpa_log(iface_name, log_path, "EAP-FAILURE")
            return "auth_failed", events
        if "CTRL-EVENT-DISCONNECTED" in new_content and "reason=23" in new_content:
            logger.info("802.1X auth rejected on %s", iface_name)
            _dump_wpa_log(iface_name, log_path, "DISCONNECTED reason=23")
            return "auth_failed", events
        # TEAP not compiled in — catch early and surface cleanly
        if "unknown EAP method 'TEAP'" in new_content or "unknown network field 'machine_cert'" in new_content:
            logger.error("TEAP not compiled into wpa_supplicant on %s — aborting", iface_name)
            return "auth_failed", events
        # TEAP-specific diagnostic events (wpa_supplicant 2.10+)
        if "EAP-TEAP" in new_content or "method=55" in new_content:
            logger.info("TEAP negotiation in progress on %s", iface_name)
        if "TLV type=" in new_content:
            # Log TLV exchanges (cert renewal type=33, crypto-binding type=59, etc.)
            for line in new_content.splitlines():
                if "TLV type=" in line:
                    logger.info("TEAP TLV exchange on %s: %s", iface_name, line.strip())

    logger.warning("Auth monitoring timed out on %s", iface_name)
    _dump_wpa_log(iface_name, log_path, "TIMEOUT")
    # Append a synthetic timeout event
    events.append(AuthFlowEvent(
        timestamp=time.time(),
        step=step,
        actor="supplicant",
        event_type="timeout",
        detail="Authentication monitoring timed out — no response from switch/ISE",
        raw_log_line="[monitor timeout]",
    ))
    return "timeout", events


async def stop_wpa_supplicant(mac: str) -> None:
    """Stop the wpa_supplicant instance and clean up for a device."""
    iface_name = _safe_iface_name(mac)
    pid_path = WPA_RUN_DIR / f"{iface_name}.pid"

    if pid_path.exists():
        try:
            pid = int(pid_path.read_text().strip())
            os.kill(pid, 15)
            logger.info("Sent SIGTERM to wpa_supplicant pid %d", pid)
            await asyncio.sleep(0.5)
        except (ValueError, ProcessLookupError, OSError):
            pass
        finally:
            pid_path.unlink(missing_ok=True)
    else:
        proc = await asyncio.create_subprocess_exec(
            "pkill", "-f", f"wpa_supplicant.*{iface_name}",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.communicate()

    for suffix in (".conf",):
        (WPA_RUN_DIR / f"{iface_name}{suffix}").unlink(missing_ok=True)
    # Preserve log as _lastfail.log — overwrite so there's always one copy per MAC
    log_path = WPA_RUN_DIR / f"{iface_name}.log"
    lastfail_path = WPA_RUN_DIR / f"{iface_name}_lastfail.log"
    if log_path.exists():
        try:
            import shutil
            shutil.copy2(log_path, lastfail_path)
        except OSError:
            pass
        log_path.unlink(missing_ok=True)

    await destroy_macvlan(mac)
    logger.info("Cleaned up wpa_supplicant for %s", mac)


def list_certs() -> list[dict]:
    """List certificate/key files in the data certs directory."""
    CERTS_DIR.mkdir(parents=True, exist_ok=True)
    results = []
    for f in sorted(CERTS_DIR.iterdir()):
        if f.is_file():
            results.append({
                "filename": f.name,
                "size": f.stat().st_size,
                "type": _guess_cert_type(f.name),
            })
    return results


def _guess_cert_type(filename: str) -> str:
    lower = filename.lower()
    if lower.endswith((".pem", ".crt", ".cer")):
        return "certificate"
    if lower.endswith((".key",)):
        return "private_key"
    if lower.endswith((".p12", ".pfx")):
        return "pkcs12"
    if lower.endswith((".pac",)):
        return "pac"
    return "unknown"


def save_cert_upload(filename: str, content: bytes) -> str:
    """Save uploaded certificate content, return sanitized filename."""
    CERTS_DIR.mkdir(parents=True, exist_ok=True)
    safe_name = Path(filename).name
    safe_name = re.sub(r"[^\w.\-]", "_", safe_name)
    dest = CERTS_DIR / safe_name
    dest.write_bytes(content)
    logger.info("Saved cert file: %s (%d bytes)", safe_name, len(content))
    return safe_name


def save_cert_paste(filename: str, pem_content: str) -> str:
    """Save pasted PEM content as a file, return sanitized filename."""
    CERTS_DIR.mkdir(parents=True, exist_ok=True)
    safe_name = Path(filename).name
    safe_name = re.sub(r"[^\w.\-]", "_", safe_name)
    dest = CERTS_DIR / safe_name
    dest.write_text(pem_content)
    logger.info("Saved pasted cert: %s (%d bytes)", safe_name, len(pem_content))
    return safe_name


def delete_cert(filename: str) -> bool:
    """Delete a certificate file. Returns True if deleted."""
    safe_name = Path(filename).name
    target = CERTS_DIR / safe_name
    if target.exists() and target.is_file():
        target.unlink()
        logger.info("Deleted cert file: %s", safe_name)
        return True
    return False
