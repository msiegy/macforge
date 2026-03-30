"""NAD Probe — SSH into a Cisco IOS/IOS-XE switch to query port state.

Runs seven IOS commands in a single SSH shell session after auto-discovering
the switch port from the MAC address table:
  1. show mac address-table address <mac>          → discover port (e.g. Gi1/0/12)
  2. show authentication sessions interface <port> detail
  3. show dot1x interface <port> detail
  4. show spanning-tree interface <port>
  5. show device-sensor cache mac <mac>
  6. show device-tracking database mac <mac> details
  7. show running-config interface <port>

Requires asyncssh (pip install asyncssh).  If asyncssh is absent a graceful
error dict is returned so the rest of the app still runs.
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

DATA_DIR = Path(os.environ.get("MACFORGE_DATA_DIR", "/app/data"))
NAD_CONFIG_FILE = DATA_DIR / "nad_config.json"


# ── Config persistence ──────────────────────────────────────────────────────

def load_nad_config() -> dict:
    """Load NAD SSH config from nad_config.json (returns defaults if absent)."""
    try:
        if NAD_CONFIG_FILE.exists():
            return json.loads(NAD_CONFIG_FILE.read_text())
    except Exception as exc:
        logger.warning("Failed to load NAD config: %s", exc)
    return {"host": "", "port": 22, "username": "", "password": "",
            "enable_password": "", "device_type": "cisco_ios"}


def save_nad_config(config: dict) -> None:
    """Persist NAD SSH config to nad_config.json."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    NAD_CONFIG_FILE.write_text(json.dumps(config, indent=2))
    logger.info("NAD config saved to %s", NAD_CONFIG_FILE)


# ── SSH helpers ─────────────────────────────────────────────────────────────

def _probe_sync(host: str, port: int, username: str, password: str,
                mac: str, enable_password: str = "",
                device_type: str = "cisco_ios") -> dict:
    """Run the full NAD probe sequence in a single Netmiko SSH session.

    All commands (MAC table lookup + all port-detail commands) share one
    ConnectHandler context so there is only one authentication round-trip
    and no session boundary that EEM applets can trigger on.

    *device_type* is passed directly to Netmiko's ConnectHandler.  Supported
    values: 'cisco_ios' (IOS / IOS-XE / IOSv — default), 'cisco_xe',
    'cisco_nxos', 'cisco_s300', 'autodetect'.  When 'autodetect' is chosen
    Netmiko's SSHDetect is used to identify the platform before connecting.

    If *enable_password* is provided, ``enable`` is issued after login so all
    commands run at privilege level 15.  Required when the SSH user logs in
    at priv < 15 (prompt ends with ``>`` instead of ``#``).

    Session transcript is written to /tmp/netmiko_nad_<host>.log.
    To inspect from the host:
        docker exec <container_name> cat /tmp/netmiko_nad_<ip>.log
    """
    try:
        from netmiko import ConnectHandler, SSHDetect  # noqa: PLC0415
        from netmiko.exceptions import (
            NetmikoTimeoutException, NetmikoAuthenticationException,
        )
        # Paramiko has its own SSH stack and is NOT affected by OpenSSH's
        # deprecation of SHA-1 kex and ssh-rsa host keys (openssh 8.8+).
        # However, newer Paramiko builds may exclude legacy algorithms from
        # their default preferred lists.  Append any missing ones at the END
        # so modern algorithms are tried first; the fallback is only used
        # when nothing else matches (common on IOS 15 / IOSv devices).
        import paramiko as _pm
        _legacy_kex = (
            "diffie-hellman-group14-sha1",
            "diffie-hellman-group-exchange-sha1",
            "diffie-hellman-group1-sha1",
        )
        _missing_kex = tuple(k for k in _legacy_kex
                             if k not in _pm.Transport._preferred_kex)
        if _missing_kex:
            _pm.Transport._preferred_kex = _pm.Transport._preferred_kex + _missing_kex
            logger.info("NAD: extended paramiko kex with legacy algorithms: %s", _missing_kex)

        # Same issue applies to host key types: old IOS only offers ssh-rsa.
        # OpenSSH 8.8+ deprecated it but Paramiko still supports it — we just
        # need to ensure it's in the preferred keys list.
        _legacy_keys = ("ssh-rsa",)
        _missing_keys = tuple(k for k in _legacy_keys
                              if k not in _pm.Transport._preferred_keys)
        if _missing_keys:
            _pm.Transport._preferred_keys = _pm.Transport._preferred_keys + _missing_keys
            logger.info("NAD: extended paramiko host key types with legacy: %s", _missing_keys)
    except ImportError:
        return {"status": "error", "message": "netmiko not installed — rebuild the Docker image"}

    cisco_mac = _mac_to_cisco(mac)
    log_path  = f"/tmp/netmiko_nad_{host.replace('.', '_')}.log"

    # Pre-initialise result so the except handler can always reference it
    result: dict = {"status": "error", "message": "Unknown error"}

    # ── Resolve device_type ───────────────────────────────────────────────────
    resolved_type = device_type or "cisco_ios"
    if resolved_type == "autodetect":
        try:
            detect_kwargs = dict(
                device_type="autodetect", host=host, port=port,
                username=username, password=password, conn_timeout=10,
            )
            guesser = SSHDetect(**detect_kwargs)
            resolved_type = guesser.autodetect() or "cisco_ios"
            logger.info("NAD autodetect: resolved device_type=%r", resolved_type)
        except Exception as det_exc:
            logger.warning("NAD autodetect failed (%s), falling back to cisco_ios", det_exc)
            resolved_type = "cisco_ios"

    logger.info("NAD probe start: host=%s  mac=%s  device_type=%s  session_log=%s",
                host, cisco_mac, resolved_type, log_path)

    def _cmd(net, command: str) -> str:
        """Send one show command; return raw output or '[error: ...]' string."""
        try:
            out = net.send_command(command, read_timeout=30)
            logger.info("NAD  %-70s  %d B", command[:70], len(out))
            return out
        except Exception as exc:
            logger.warning("NAD  %-70s  FAILED: %s", command[:70], exc)
            return f"[error: {exc}]"

    try:
        with ConnectHandler(
            device_type=resolved_type,
            host=host,
            port=port,
            username=username,
            password=password,
            secret=enable_password or password,
            timeout=20,
            session_timeout=120,
            conn_timeout=10,
            fast_cli=False,
            session_log=log_path,
        ) as net:
            if enable_password:
                try:
                    net.enable()
                    logger.info("NAD enable: privilege level elevated")
                except Exception as en_exc:
                    # Some platforms / privilege levels don't accept 'enable'
                    # (already at priv 15, or not supported).  Log and continue.
                    logger.warning("NAD enable() failed (continuing anyway): %s", en_exc)
            # ─ Step 1: discover port ──────────────────────────────────────────
            discover_raw = _cmd(net, f"show mac address-table address {cisco_mac}")
            port_name    = _parse_port_from_mac_table(discover_raw, mac)

            result: dict = {
                "status": "ok",
                "switch": host,
                "mac":    mac,
                "port":   port_name,
                "mac_table": discover_raw.strip(),
            }

            if not port_name:
                result["warning"] = (
                    "MAC not found in address table — device may not be connected "
                    "or the switch is still learning"
                )
                return result

            # ─ Step 2: all port-specific commands in the same session ────────
            auth_mac_raw = _cmd(net, f"show authentication sessions mac {cisco_mac} detail")
            auth_raw     = _cmd(net, f"show authentication sessions interface {port_name} detail")
            dot1x_raw    = _cmd(net, f"show dot1x interface {port_name} detail")
            stp_raw      = _cmd(net, f"show spanning-tree interface {port_name}")
            sensor_raw   = _cmd(net, f"show device-sensor cache mac {cisco_mac}")
            tracking_raw = _cmd(net, f"show device-tracking database mac {cisco_mac} details")
            runint_raw   = _cmd(net, f"show running-config interface {port_name}")

            # Populate result inside the with-block so that an exception during
            # Netmiko disconnect (e.g. EEM applet closing the session after the
            # last command) does not discard successfully collected data.
            result.update({
                "auth_mac_sessions":    _parse_auth_sessions_multi(auth_mac_raw),
                "auth_mac_raw":         auth_mac_raw.strip(),
                "auth_sessions":        _parse_auth_sessions_multi(auth_raw),
                "auth_sessions_raw":    auth_raw.strip(),
                "dot1x":                _parse_colon_kv(dot1x_raw),
                "dot1x_raw":            dot1x_raw.strip(),
                "spanning_tree":        _parse_spanning_tree(stp_raw),
                "spanning_tree_raw":    stp_raw.strip(),
                "device_sensor":        _parse_device_sensor(sensor_raw),
                "device_sensor_raw":    sensor_raw.strip(),
                "device_tracking":      _parse_device_tracking(tracking_raw),
                "device_tracking_raw":  tracking_raw.strip(),
                "run_interface":        _clean_run_config(runint_raw),
                "run_interface_raw":    runint_raw.strip(),
            })

    except (NetmikoTimeoutException, NetmikoAuthenticationException) as exc:
        return {"status": "error", "message": f"SSH error: {exc}"}
    except Exception as exc:
        # If all data was already collected (result has auth_sessions key), log
        # the disconnect error as a warning but still return the data.
        if "auth_sessions" in result:
            logger.warning("NAD probe disconnect error (data already collected): %s", exc)
        else:
            logger.exception("NAD probe unexpected error")
            return {"status": "error", "message": f"SSH error: {exc}"}

    return result



# ── IOS output parsers ───────────────────────────────────────────────────────

def _mac_to_cisco(mac: str) -> str:
    """Convert AA:BB:CC:DD:EE:FF → aabb.ccdd.eeff (Cisco dot-notation)."""
    clean = mac.lower().replace(":", "").replace("-", "")
    return f"{clean[0:4]}.{clean[4:8]}.{clean[8:12]}"


def _parse_port_from_mac_table(output: str, mac: str) -> Optional[str]:
    """Extract the interface name from 'show mac address-table' output.

    Supports both colon-notation (aa:bb:cc:dd:ee:ff) and Cisco dot-notation
    (aabb.ccdd.eeff).  Returns the last token on a matching line (the port).
    """
    cisco_mac = _mac_to_cisco(mac)
    colon_mac = mac.lower().replace(":", "")

    for line in output.splitlines():
        line_lower = line.lower()
        if cisco_mac in line_lower or colon_mac in line_lower:
            parts = line.split()
            if len(parts) >= 4:
                return parts[-1]
    return None


def _parse_colon_kv(output: str) -> dict[str, str]:
    """Generic key: value parser for IOS detail outputs.

    Lines with a colon are split into key/value pairs.  Lines that start
    with dashes or are pure separators are skipped.
    """
    fields: dict[str, str] = {}
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("-") or stripped.startswith("="):
            continue
        if ":" in stripped:
            key, _, value = stripped.partition(":")
            key = key.strip()
            value = value.strip()
            if key and value:
                # Avoid overwriting earlier fields with empty continuations
                fields[key] = value
    return fields


def _parse_auth_sessions_multi(output: str) -> list[dict]:
    """Parse multi-session 'show authentication sessions ... detail' output.

    Multiple sessions on the same port are separated by lines of ≥10 dashes.
    Returns a list of dicts, one per session block.  Each dict has the
    colon-separated key/value fields from the block plus a special key
    ``_method_states`` containing a list of {method, state} dicts extracted
    from the "Method status list" table at the bottom of each block.
    """
    blocks = re.split(r"-{10,}", output)
    sessions: list[dict] = []
    for block in blocks:
        if not block.strip():
            continue
        fields: dict = {}
        method_states: list[dict[str, str]] = []
        in_method_list = False
        for line in block.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            # "Method status list:" header — switch to table-parsing mode
            if re.match(r"Method\s+status\s+list", stripped, re.IGNORECASE):
                in_method_list = True
                continue
            # Skip the column-header line "Method  State" inside the table
            if in_method_list and re.match(r"Method\s+State", stripped, re.IGNORECASE):
                continue
            if in_method_list:
                parts = stripped.split(None, 1)
                if len(parts) == 2:
                    method_states.append({"method": parts[0], "state": parts[1]})
                continue
            # Generic key: value line
            if ":" in stripped:
                key, _, value = stripped.partition(":")
                key = key.strip()
                value = value.strip()
                if key and value:
                    fields[key] = value
        if fields:
            if method_states:
                fields["_method_states"] = method_states
            sessions.append(fields)
    return sessions


def _parse_device_sensor(output: str) -> list[dict[str, str]]:
    """Parse 'show device-sensor cache mac <mac>' tabular output.

    Typical format::

        Device: aabb.ccdd.eeff on port GigabitEthernet1/0/11
        ---------------------------------------------------------
        Proto  Type:Name                 Len  Data
        ---------------------------------------------------------
        DHCP   12:hostname               13   my-laptop
        DHCP   55:param-req-list          6   01 1c 02 03 0f 06
        CDP    22:platform-type          10   Cisco IP Phone 8821

    Returns a list of {proto, type_name, data} dicts.
    """
    entries: list[dict[str, str]] = []
    in_table = False
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or re.match(r"-{5,}", stripped):
            continue
        if re.match(r"Proto\s+Type", stripped, re.IGNORECASE):
            in_table = True
            continue
        if stripped.lower().startswith("device:"):
            continue
        if in_table:
            # Columns: Proto  Type:Name  Len  Data (Len is not interesting)
            parts = stripped.split(None, 3)
            if len(parts) >= 2:
                entries.append({
                    "proto": parts[0],
                    "type_name": parts[1],
                    "data": parts[3].strip() if len(parts) > 3 else "",
                })
    return entries


def _parse_device_tracking(output: str) -> list[dict[str, str]]:
    """Parse 'show device-tracking database mac <mac> details' output.

    Each data line starts with a type code (ARP, DH4, DH6, ND, etc.) followed
    by IP address, MAC, interface, vlan, prlvl, age, state, and time-left.
    Skips header/separator lines and the 'Codes:' legend block.
    """
    TYPE_CODE = re.compile(r'^(ARP|DH4|DH6|ND|L|S|PKT|API)\s', re.IGNORECASE)
    entries: list[dict[str, str]] = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or re.match(r'-{5,}', stripped):
            continue
        if not TYPE_CODE.match(stripped):
            continue
        parts = stripped.split()
        # cols: 0=type 1=address 2=link_layer 3=interface 4=vlan 5=prlvl 6=age 7=state 8+=time
        if len(parts) < 3:
            continue
        entries.append({
            "type":       parts[0],
            "address":    parts[1] if len(parts) > 1 else "",
            "link_layer": parts[2] if len(parts) > 2 else "",
            "interface":  parts[3] if len(parts) > 3 else "",
            "vlan":       parts[4] if len(parts) > 4 else "",
            "age":        parts[6] if len(parts) > 6 else "",
            "state":      parts[7] if len(parts) > 7 else "",
        })
    return entries


def _clean_run_config(output: str) -> str:
    """Strip the 'Building configuration...' preamble from show run output."""
    lines = output.splitlines()
    while lines and lines[0].strip().lower().startswith("building"):
        lines.pop(0)
    while lines and not lines[0].strip():
        lines.pop(0)
    return "\n".join(lines).strip()


def _parse_spanning_tree(output: str) -> dict[str, str]:
    """Parse 'show spanning-tree interface <port>' tabular output.

    Typical line: VLAN0010   Desg FWD 4     128.12  P2p
    Returns stp_vlan, stp_role, stp_state, and any key:value pairs found.
    """
    fields = _parse_colon_kv(output)
    for line in output.splitlines():
        parts = line.split()
        # VLAN-prefixed lines: VLAN0001  Root FWD ...
        if parts and re.match(r"VLAN\d+", parts[0], re.IGNORECASE):
            fields["stp_vlan"] = parts[0]
            if len(parts) > 1:
                fields["stp_role"] = parts[1]
            if len(parts) > 2:
                fields["stp_state"] = parts[2]
            break
    return fields


# ── Main probe entry point ───────────────────────────────────────────────────

async def probe_nad(mac: str) -> dict:
    """Async entry point — delegates to _probe_sync in a thread executor.

    _probe_sync opens exactly one Netmiko SSH session and runs all commands
    (MAC table lookup + 6 port-detail commands) within that session.  The
    full session transcript is written to /tmp/netmiko_nad_<host>.log.
    To inspect:
        docker exec <container_name> cat /tmp/netmiko_nad_<ip>.log
    """
    import asyncio

    config = load_nad_config()
    if not config.get("host"):
        return {
            "status": "error",
            "message": "NAD not configured — add the switch hostname/IP in the NAD Probe settings",
        }

    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None,
        _probe_sync,
        config["host"],
        int(config.get("port") or 22),
        config.get("username", ""),
        config.get("password", ""),
        mac,
        config.get("enable_password", ""),
        config.get("device_type", "cisco_ios"),
    )
