"""Device orchestrator -- manages lifecycle of emulated devices.

Handles connect/disconnect sequences, ARP keepalives, ARP responder for
incoming ARP requests, DHCP sniffing for offers/ACKs, and ICMP ping tests.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from typing import Optional

from scapy.all import ARP, ICMP, AsyncSniffer, BOOTP, DHCP, Ether, IP, UDP
from scapy.layers.eap import EAPOL, EAP
from scapy.layers.snmp import SNMP

from macforge.dot1x import (
    monitor_wpa_auth,
    start_wpa_supplicant,
    stop_wpa_supplicant,
)
from macforge.engine import (
    build_arp_reply,
    build_dhcp_discover,
    build_dhcp_release,
    build_dhcp_request,
    build_dns_query,
    build_gratuitous_arp,
    build_icmp_echo,
    build_icmp_reply,
    build_keepalive_udp,
    build_mdns_announcement,
    build_snmp_response,
    build_ssdp_alive,
    build_tcp_syn,
    async_send_packet,
    send_packet,
)
from macforge.models import (
    AuthFlowEvent,
    DeviceProfile,
    DeviceState,
    DeviceStatus,
    PacketEvent,
    PacketLogEntry,
    PingResult,
)

logger = logging.getLogger(__name__)

MAX_LOG_ENTRIES = 500
DHCP_TIMEOUT = 6.0       # per-attempt wait for a DHCP Offer/ACK
DHCP_MAX_RETRIES = 3     # standard fast-path retries (MAB with no dot1x delay)
DHCP_MAX_RETRIES_MAB = 12  # extended retries for MAB — covers dot1x tx-period fallthrough
                            # Cisco default: tx-period=30s, max-reauth-req=2 → ~90s to MAB
                            # 12 × (6s wait + backoff) ≈ 90–100s total window
DHCP_BACKOFF_BASE = 2.0    # seconds before first retry
DHCP_BACKOFF_MAX = 10.0    # cap per-retry backoff
PING_TIMEOUT = 4.0


class DeviceInstance:
    """Runtime state for a single emulated device."""

    def __init__(self, profile: DeviceProfile, is_custom: bool = False):
        self.profile = profile
        self.is_custom = is_custom
        self.has_overrides = False
        self.state = DeviceState.STOPPED
        self.status_detail: str = ""
        self.connected_at: Optional[float] = None
        self.packets_sent = 0
        self.assigned_ip: Optional[str] = None
        self.server_ip: Optional[str] = None
        self.gateway_ip: Optional[str] = None
        self.gateway_mac: Optional[str] = None
        self.xid: int = 0
        self.last_ping: Optional[PingResult] = None
        self._keepalive_task: Optional[asyncio.Task] = None
        self._macvlan_iface: Optional[str] = None
        self.dot1x_failed_open: bool = False
        self.error_message: Optional[str] = None  # last auth/connect error
        # Auth timestamps
        self.auth_started_at: Optional[float] = None
        self.auth_completed_at: Optional[float] = None
        # Auth flow events (parsed from wpa_supplicant log)
        self.auth_flow_events: list[AuthFlowEvent] = []
        # Extended DHCP fields (parsed from ACK)
        self.dhcp_subnet: Optional[str] = None
        self.dhcp_dns: list[str] = []
        self.dhcp_lease_time: Optional[int] = None
        # Phase 5: per-device packet capture ring buffer
        self.capture_log: deque = deque(maxlen=200)
        self._capture_sniffer: Optional[AsyncSniffer] = None
        self._capture_active: bool = False

    @property
    def uptime(self) -> float:
        if self.connected_at is None:
            return 0.0
        return time.time() - self.connected_at

    def to_status(self) -> DeviceStatus:
        auth_method = None
        auth_state = None
        if self.profile.auth:
            auth_method = self.profile.auth.method
            if self.dot1x_failed_open and self.state == DeviceState.ONLINE:
                auth_state = "dot1x_failed_open"
            elif self.state == DeviceState.AUTHENTICATING:
                auth_state = "authenticating"
            elif self.state == DeviceState.AUTHORIZED:
                auth_state = "authorized"
            elif self.state == DeviceState.AUTH_FAILED:
                auth_state = "auth_failed"
            elif self.state == DeviceState.ONLINE:
                auth_state = "authorized"
        return DeviceStatus(
            name=self.profile.name,
            mac=self.profile.mac,
            state=self.state,
            status_detail=self.status_detail,
            error_message=self.error_message,
            personality=self.profile.personality,
            dhcp=self.profile.dhcp,
            auth_method=auth_method,
            auth_state=auth_state,
            auth_identity=self.profile.auth.identity if self.profile.auth else None,
            uptime_sec=round(self.uptime, 1),
            packets_sent=self.packets_sent,
            assigned_ip=self.assigned_ip,
            gateway_ip=self.gateway_ip,
            dhcp_server_ip=self.server_ip,
            dhcp_subnet=self.dhcp_subnet,
            dhcp_dns=list(self.dhcp_dns),
            dhcp_lease_time=self.dhcp_lease_time,
            connected_at=self.connected_at,
            auth_started_at=self.auth_started_at,
            auth_completed_at=self.auth_completed_at,
            last_ping=self.last_ping,
            is_custom=self.is_custom,
        )


class Orchestrator:
    """Manages all emulated devices on a single network interface."""

    def __init__(self, profiles: list[DeviceProfile], interface: str,
                 seed: Optional[bytes] = None, mgmt_interface: Optional[str] = None):
        self.interface = interface           # data/NAD interface — EAP, MAB, DHCP
        self.mgmt_interface = mgmt_interface or interface  # web UI / management interface
        self.seed = seed
        self.devices: dict[str, DeviceInstance] = {}
        self.packet_log: deque[PacketLogEntry] = deque(maxlen=MAX_LOG_ENTRIES)
        self._arp_responder: Optional[AsyncSniffer] = None
        self._icmp_responder: Optional[AsyncSniffer] = None
        self._snmp_responder: Optional[AsyncSniffer] = None
        self.snmp_enabled: bool = False
        self._ip_to_device: dict[str, DeviceInstance] = {}

        for p in profiles:
            self.devices[p.mac] = DeviceInstance(p)

    def _log_packet(self, device: DeviceInstance, pkt_type: str, detail: str = "") -> None:
        entry = PacketLogEntry(
            timestamp=time.time(),
            device_name=device.profile.name,
            mac=device.profile.mac,
            packet_type=pkt_type,
            detail=detail,
        )
        self.packet_log.appendleft(entry)
        device.packets_sent += 1
        # Per-device capture log (Phase 5) — record sent packets when capture is active
        if device._capture_active:
            device.capture_log.appendleft(PacketEvent(
                timestamp=entry.timestamp,
                direction="sent",
                protocol=pkt_type,
                summary=detail,
                size_bytes=0,
            ))

    def get_all_status(self) -> list[DeviceStatus]:
        return [d.to_status() for d in self.devices.values()]

    def get_device_status(self, mac: str) -> Optional[DeviceStatus]:
        device = self.devices.get(mac)
        return device.to_status() if device else None

    def get_recent_logs(self, limit: int = 50) -> list[PacketLogEntry]:
        return list(self.packet_log)[:limit]

    def add_device(self, profile: DeviceProfile, is_custom: bool = True) -> DeviceInstance:
        """Register a new device at runtime."""
        device = DeviceInstance(profile, is_custom=is_custom)
        self.devices[profile.mac] = device
        logger.info("Added device: %s (%s) custom=%s", profile.name, profile.mac, is_custom)
        return device

    def remove_device(self, mac: str) -> bool:
        """Remove a stopped custom device."""
        device = self.devices.get(mac)
        if not device:
            return False
        if device.state != DeviceState.STOPPED:
            return False
        del self.devices[mac]
        self._update_ip_index(device)
        logger.info("Removed device: %s (%s)", device.profile.name, mac)
        return True

    def _start_arp_responder(self) -> None:
        """Start background ARP responder that answers ARP who-has for our emulated IPs."""
        if self._arp_responder is not None:
            return

        def _handle_arp(pkt):
            if not pkt.haslayer(ARP):
                return
            arp = pkt[ARP]
            if arp.op != 1:
                return
            target_ip = arp.pdst
            device = self._ip_to_device.get(target_ip)
            if device is None or device.state != DeviceState.ONLINE:
                return
            reply = build_arp_reply(
                src_mac=device.profile.mac,
                src_ip=target_ip,
                dst_mac=arp.hwsrc,
                dst_ip=arp.psrc,
            )
            send_packet(reply, self.interface)

        self._arp_responder = AsyncSniffer(
            iface=self.interface,
            filter="arp",
            prn=_handle_arp,
            store=False,
        )
        self._arp_responder.start()
        logger.info("ARP responder started on %s", self.interface)

    def _start_icmp_responder(self) -> None:
        """Reply to incoming ICMP echo requests destined to emulated device IPs."""
        if self._icmp_responder is not None:
            return

        def _handle_icmp(pkt):
            if not pkt.haslayer(ICMP) or not pkt.haslayer(IP) or not pkt.haslayer(Ether):
                return
            if pkt[ICMP].type != 8:
                return
            dst_ip = pkt[IP].dst
            device = self._ip_to_device.get(dst_ip)
            if device is None or device.state != DeviceState.ONLINE:
                return
            payload = bytes(pkt[ICMP].payload) if pkt[ICMP].payload else b""
            reply = build_icmp_reply(
                src_mac=device.profile.mac,
                src_ip=dst_ip,
                dst_mac=pkt[Ether].src,
                dst_ip=pkt[IP].src,
                icmp_id=pkt[ICMP].id,
                icmp_seq=pkt[ICMP].seq,
                payload=payload,
            )
            send_packet(reply, self.interface)

        self._icmp_responder = AsyncSniffer(
            iface=self.interface,
            filter="icmp[icmptype] == 8",
            prn=_handle_icmp,
            store=False,
        )
        self._icmp_responder.start()
        logger.info("ICMP responder started on %s", self.interface)

    def _start_snmp_responder(self) -> None:
        """Respond to SNMP GET/GETNEXT queries for emulated devices that have profiles."""
        if self._snmp_responder is not None:
            return

        def _handle_snmp(pkt):
            if not pkt.haslayer(UDP) or not pkt.haslayer(IP) or not pkt.haslayer(Ether):
                return
            if pkt[UDP].dport != 161:
                return
            dst_ip = pkt[IP].dst
            device = self._ip_to_device.get(dst_ip)
            if device is None or device.state != DeviceState.ONLINE:
                return
            if device.profile.snmp is None:
                return
            try:
                snmp_pkt = SNMP(bytes(pkt[UDP].payload))
            except Exception:
                return
            uptime_ticks = int(device.uptime * 100)
            reply = build_snmp_response(
                src_mac=device.profile.mac,
                src_ip=dst_ip,
                dst_mac=pkt[Ether].src,
                dst_ip=pkt[IP].src,
                dst_port=pkt[UDP].sport,
                snmp_pkt=snmp_pkt,
                snmp_profile=device.profile.snmp,
                uptime_ticks=uptime_ticks,
            )
            if reply:
                send_packet(reply, self.interface)

        self._snmp_responder = AsyncSniffer(
            iface=self.interface,
            filter="udp and dst port 161",
            prn=_handle_snmp,
            store=False,
        )
        self._snmp_responder.start()
        logger.info("SNMP responder started on %s", self.interface)

    def _stop_snmp_responder(self) -> None:
        if self._snmp_responder is not None:
            if self._snmp_responder.running:
                self._snmp_responder.stop()
            self._snmp_responder = None
            logger.info("SNMP responder stopped")

    # ── Phase 5: Per-device packet capture ──────────────────────────────────

    def start_capture(self, mac: str) -> dict:
        """Start per-device packet capture sniffer (Phase 5 — Packet Inspector)."""
        device = self.devices.get(mac)
        if not device:
            return {"status": "error", "message": "Device not found"}
        if device._capture_active:
            return {"status": "ok", "message": "Capture already running"}

        device.capture_log.clear()
        device._capture_active = True

        # Use per-device macvlan if available, else the shared interface
        iface = device._macvlan_iface or self.interface
        mac_filter = device.profile.mac.lower()
        # Only capture inbound (TX side is already covered by _log_packet augmentation)
        bpf = f"not ether src {mac_filter}"

        def _handle_capture(pkt: Ether) -> None:
            if not pkt.haslayer(Ether):
                return
            proto: Optional[str] = None
            summary = ""
            size = len(bytes(pkt))
            pkt_detail: dict = {}

            # EAPOL (ethertype 0x888e) — decode EAP type/code/method
            if pkt.type == 0x888e:
                proto = "EAPOL"
                eapol_types = {0: "EAP-Packet", 1: "EAPOL-Start", 2: "EAPOL-Logoff",
                               3: "EAPOL-Key", 4: "EAPOL-Encapsulated-ASF-Alert"}
                eap_codes    = {1: "Request", 2: "Response", 3: "Success", 4: "Failure"}
                eap_types    = {
                    1: "Identity", 2: "Notification", 3: "NAK",
                    4: "MD5-Challenge", 13: "EAP-TLS", 17: "LEAP",
                    18: "EAP-SIM", 21: "TTLS", 25: "PEAP",
                    29: "MS-CHAPv2", 43: "EAP-FAST", 55: "TEAP",
                }
                try:
                    eapol_layer = pkt.getlayer(EAPOL)
                    eapol_type = eapol_types.get(getattr(eapol_layer, "type", -1), "Unknown")
                    pkt_detail["eapol_type"] = eapol_type

                    if eapol_layer and eapol_layer.type == 0:  # EAP-Packet
                        eap_layer = eapol_layer.payload
                        if eap_layer and hasattr(eap_layer, "code"):
                            code_name = eap_codes.get(eap_layer.code, f"code={eap_layer.code}")
                            pkt_detail["eap_code"] = code_name
                            pkt_detail["eap_id"] = getattr(eap_layer, "id", "?")
                            if eap_layer.code in (1, 2) and hasattr(eap_layer, "type"):
                                type_name = eap_types.get(eap_layer.type, f"type={eap_layer.type}")
                                pkt_detail["eap_type"] = type_name
                                if eap_layer.code == 1:
                                    summary = f"EAP Request [{type_name}] id={pkt_detail['eap_id']}"
                                else:
                                    summary = f"EAP Response [{type_name}] id={pkt_detail['eap_id']}"
                            elif eap_layer.code == 3:
                                summary = "EAP Success"
                                pkt_detail["eap_type"] = "Success"
                            elif eap_layer.code == 4:
                                summary = "EAP Failure"
                                pkt_detail["eap_type"] = "Failure"
                            else:
                                summary = f"EAP {code_name} id={pkt_detail['eap_id']}"
                        else:
                            summary = f"EAPOL {eapol_type}"
                    else:
                        summary = f"EAPOL {eapol_type}"

                    pkt_detail["src_mac"] = pkt[Ether].src
                    pkt_detail["dst_mac"] = pkt[Ether].dst
                except Exception:
                    summary = "EAPOL frame"
            # DHCP — UDP with BOOTP/DHCP layers
            elif pkt.haslayer(UDP) and pkt.haslayer(BOOTP) and pkt.haslayer(DHCP):
                proto = "DHCP"
                dhcp_opts = {
                    o[0]: o[1] for o in pkt[DHCP].options if isinstance(o, tuple)
                }
                mt = dhcp_opts.get("message-type", 0)
                names = {
                    1: "Discover", 2: "Offer", 3: "Request", 4: "Decline",
                    5: "ACK", 6: "NAK", 7: "Release", 8: "Inform",
                }
                summary = f"DHCP {names.get(mt, str(mt))}"
                pkt_detail["msg_type"] = names.get(mt, str(mt))
                if dhcp_opts.get("server_id"):
                    pkt_detail["server_id"] = dhcp_opts["server_id"]
                if dhcp_opts.get("router"):
                    pkt_detail["router"] = dhcp_opts["router"]
                offered = pkt[BOOTP].yiaddr
                if offered and offered != "0.0.0.0":
                    pkt_detail["offered_ip"] = offered
                    summary += f" ({offered})"
            # ARP
            elif pkt.haslayer(ARP):
                arp = pkt[ARP]
                op_name = "Who-Has" if arp.op == 1 else "Is-At"
                summary = f"ARP {op_name} {arp.pdst} from {arp.psrc}"
                proto = "ARP"
                pkt_detail["op"] = op_name
                pkt_detail["src_ip"] = arp.psrc
                pkt_detail["dst_ip"] = arp.pdst
                pkt_detail["src_mac"] = arp.hwsrc
            # ICMP
            elif pkt.haslayer(IP) and pkt.haslayer(ICMP):
                icmp = pkt[ICMP]
                type_names = {
                    0: "Echo Reply", 3: "Unreachable",
                    8: "Echo Request", 11: "TTL Exceeded",
                }
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                summary = f"{type_names.get(icmp.type, f'type={icmp.type}')} {src_ip}→{dst_ip}"
                proto = "ICMP"
                pkt_detail["icmp_type"] = type_names.get(icmp.type, str(icmp.type))
                pkt_detail["src_ip"] = src_ip
                pkt_detail["dst_ip"] = dst_ip

            if proto is None:
                return

            raw = bytes(pkt)
            device.capture_log.appendleft(PacketEvent(
                timestamp=time.time(),
                direction="recv",
                protocol=proto,
                summary=summary,
                size_bytes=size,
                detail=pkt_detail,
                raw_bytes=raw,
            ))

        device._capture_sniffer = AsyncSniffer(
            iface=iface,
            filter=bpf,
            prn=_handle_capture,
            store=False,
        )
        try:
            device._capture_sniffer.start()
            logger.info("Packet capture started for %s on %s", mac, iface)
        except Exception as exc:
            device._capture_active = False
            device._capture_sniffer = None
            logger.error("Failed to start capture for %s: %s", mac, exc)
            return {"status": "error", "message": str(exc)}
        return {"status": "ok"}

    def stop_capture(self, mac: str) -> dict:
        """Stop per-device packet capture (Phase 5)."""
        device = self.devices.get(mac)
        if not device:
            return {"status": "error", "message": "Device not found"}
        device._capture_active = False
        if device._capture_sniffer:
            if device._capture_sniffer.running:
                device._capture_sniffer.stop()
            device._capture_sniffer = None
        logger.info("Packet capture stopped for %s", mac)
        return {"status": "ok"}

    def set_snmp_enabled(self, enabled: bool) -> None:
        self.snmp_enabled = enabled
        if enabled:
            has_online = any(
                d.state == DeviceState.ONLINE and d.profile.snmp
                for d in self.devices.values()
            )
            if has_online:
                self._start_snmp_responder()
            logger.info("SNMP responder enabled")
        else:
            self._stop_snmp_responder()
            logger.info("SNMP responder disabled")

    def _update_ip_index(self, device: DeviceInstance) -> None:
        """Keep the IP-to-device lookup in sync."""
        self._ip_to_device = {
            d.assigned_ip: d
            for d in self.devices.values()
            if d.assigned_ip and d.state == DeviceState.ONLINE
        }

    async def connect_device(self, mac: str) -> bool:
        """Start the connect sequence for a device.

        For dot1x devices: creates a macvlan, runs wpa_supplicant for 802.1X
        auth, then proceeds to DHCP on the main interface.
        For MAB devices: uses the existing DHCP retry loop.
        """
        device = self.devices.get(mac)
        if not device:
            logger.error("Device not found: %s", mac)
            return False

        # Allow AUTHENTICATING/CONNECTING here: the web endpoint sets these
        # states synchronously before firing the task so that the first
        # GET /api/devices after the POST returns the correct transitional
        # state instead of STOPPED.
        if device.state not in (
            DeviceState.STOPPED, DeviceState.AUTH_FAILED,
            DeviceState.AUTHENTICATING, DeviceState.CONNECTING,
        ):
            logger.warning("Device %s is not stopped (state=%s)", mac, device.state)
            return False

        device.last_ping = None
        device.auth_flow_events = []  # clear events from previous auth attempt
        logger.info("Connecting device: %s (%s)", device.profile.name, mac)

        if device.profile.auth:
            return await self._connect_dot1x(device)
        return await self._connect_mab(device)

    async def _connect_dot1x(self, device: DeviceInstance) -> bool:
        """802.1X authentication followed by DHCP."""
        mac = device.profile.mac
        auth = device.profile.auth

        device.state = DeviceState.AUTHENTICATING
        device.status_detail = f"EAP {auth.method}"
        device.error_message = None  # clear any previous error
        device.auth_started_at = time.time()
        device.auth_completed_at = None
        self._log_packet(device, "EAPOL", f"Starting {auth.method} auth")

        try:
            iface_name, _ = await start_wpa_supplicant(
                mac, auth, self.interface,
            )
            device._macvlan_iface = iface_name
        except Exception as exc:
            logger.error("wpa_supplicant start failed for %s: %s", mac, exc)
            device.state = DeviceState.AUTH_FAILED
            device.auth_completed_at = time.time()
            device.error_message = str(exc)
            device.status_detail = f"wpa_supplicant error: {exc}"
            self._log_packet(device, "EAPOL", f"Start failed: {exc}")
            return False

        device.status_detail = "Authenticating..."
        result, auth_events = await monitor_wpa_auth(iface_name, timeout=30.0)
        device.auth_completed_at = time.time()
        device.auth_flow_events = auth_events

        if result == "authorized":
            device.state = DeviceState.AUTHORIZED
            device.status_detail = "Authorized"
            self._log_packet(device, "EAPOL", "EAP SUCCESS - Authorized")
            logger.info("802.1X authorized: %s (%s)", device.profile.name, mac)
            return await self._do_dhcp_sequence(device)

        self._log_packet(device, "EAPOL", f"Auth result: {result}")
        logger.warning("802.1X failed for %s: %s", mac, result)

        # Store a human-readable reason for the UI
        result_labels = {
            "auth_failed": "EAP authentication rejected by RADIUS server",
            "timeout": "EAP authentication timed out — no response from switch/ISE",
        }
        device.error_message = result_labels.get(result, f"EAP {result}")

        if device._macvlan_iface:
            self._log_packet(device, "EAPOL", "Cleaning up wpa_supplicant")
            await stop_wpa_supplicant(mac)
            device._macvlan_iface = None

        device.status_detail = "Probing port..."
        self._log_packet(device, "DHCP Discover", "dot1x failed — probing for open port")
        logger.info("dot1x failed for %s — probing port for open access", mac)

        return await self._do_fallback_dhcp_probe(device)

    async def _connect_mab(self, device: DeviceInstance) -> bool:
        """MAB DHCP connect with extended retry window.

        Uses a longer retry count + exponential backoff to cover the dot1x
        fallthrough window on Cisco switches (default tx-period=30s,
        max-reauth-req=2 → switch authorises MAB ~30-90s after first frame).
        If DHCP succeeds before all retries are exhausted the loop exits early.
        """
        mac = device.profile.mac
        device.state = DeviceState.CONNECTING

        offered_ip: Optional[str] = None
        backoff = DHCP_BACKOFF_BASE

        for attempt in range(1, DHCP_MAX_RETRIES_MAB + 1):
            device.status_detail = "DHCP Discover %d/%d" % (attempt, DHCP_MAX_RETRIES_MAB)

            discover_pkt = build_dhcp_discover(device.profile, self.interface)
            device.xid = discover_pkt["BOOTP"].xid

            offered_ip = await self._send_and_wait_for_dhcp(
                device, discover_pkt, msg_type=2,
            )

            if attempt == 1:
                self._log_packet(device, "DHCP Discover", "Broadcast DHCP Discover")
            else:
                self._log_packet(
                    device, "DHCP Discover",
                    f"Retry {attempt}/{DHCP_MAX_RETRIES_MAB} (waiting for MAB port-auth)",
                )

            if offered_ip:
                device.status_detail = "DHCP Offer received"
                logger.info(
                    "DHCP Offer received for %s on attempt %d: %s",
                    mac, attempt, offered_ip,
                )
                break

            logger.info(
                "No DHCP Offer for %s (attempt %d/%d, backoff %.1fs) "
                "-- switch may still be running dot1x timer before MAB",
                mac, attempt, DHCP_MAX_RETRIES_MAB, backoff,
            )
            # Don't sleep after the last attempt
            if attempt < DHCP_MAX_RETRIES_MAB and device.state == DeviceState.CONNECTING:
                await asyncio.sleep(backoff)
                backoff = min(backoff * 1.5, DHCP_BACKOFF_MAX)

        if offered_ip:
            device.status_detail = "DHCP Request"
            request_pkt = build_dhcp_request(
                device.profile, device.xid, offered_ip,
                device.server_ip or "255.255.255.255",
            )

            ack_ip = await self._send_and_wait_for_dhcp(
                device, request_pkt, msg_type=5,
            )
            self._log_packet(device, "DHCP Request", f"Requesting {offered_ip}")

            if ack_ip:
                device.assigned_ip = ack_ip
            else:
                device.assigned_ip = None
                logger.warning("DHCP ACK not received for %s", mac)
        else:
            device.assigned_ip = None
            logger.info(
                "No DHCP Offer after %d attempts for %s "
                "-- device online for MAB but no IP; keepalive will retry DHCP",
                DHCP_MAX_RETRIES_MAB, mac,
            )

        device.state = DeviceState.ONLINE
        device.status_detail = ""
        device.connected_at = time.time()
        self._update_ip_index(device)

        self._start_arp_responder()
        self._start_icmp_responder()
        if self.snmp_enabled and device.profile.snmp:
            self._start_snmp_responder()

        device._keepalive_task = asyncio.create_task(
            self._keepalive_loop(device)
        )

        logger.info(
            "Device online: %s (%s) ip=%s gw=%s",
            device.profile.name, mac,
            device.assigned_ip or "none",
            device.gateway_ip or "none",
        )
        return True


    async def _do_dhcp_sequence(self, device: DeviceInstance) -> bool:
        """Run DHCP after 802.1X authorization, then go online."""
        mac = device.profile.mac
        device.status_detail = "DHCP Discover"

        offered_ip: Optional[str] = None

        for attempt in range(1, DHCP_MAX_RETRIES + 1):
            device.status_detail = "DHCP Discover %d/%d" % (attempt, DHCP_MAX_RETRIES)

            discover_pkt = build_dhcp_discover(device.profile, self.interface)
            device.xid = discover_pkt["BOOTP"].xid

            offered_ip = await self._send_and_wait_for_dhcp(
                device, discover_pkt, msg_type=2,
            )
            self._log_packet(device, "DHCP Discover",
                             f"Broadcast DHCP Discover (post-auth, attempt {attempt})")

            if offered_ip:
                break

        if offered_ip:
            device.status_detail = "DHCP Request"
            request_pkt = build_dhcp_request(
                device.profile, device.xid, offered_ip,
                device.server_ip or "255.255.255.255",
            )
            ack_ip = await self._send_and_wait_for_dhcp(
                device, request_pkt, msg_type=5,
            )
            self._log_packet(device, "DHCP Request", f"Requesting {offered_ip}")
            device.assigned_ip = ack_ip if ack_ip else None
        else:
            device.assigned_ip = None

        device.state = DeviceState.ONLINE
        device.status_detail = ""
        device.connected_at = time.time()
        self._update_ip_index(device)

        self._start_arp_responder()
        self._start_icmp_responder()
        if self.snmp_enabled and device.profile.snmp:
            self._start_snmp_responder()

        device._keepalive_task = asyncio.create_task(
            self._keepalive_loop(device)
        )

        logger.info(
            "Device online (dot1x): %s (%s) ip=%s gw=%s",
            device.profile.name, mac,
            device.assigned_ip or "none",
            device.gateway_ip or "none",
        )
        return True

    async def _do_fallback_dhcp_probe(self, device: DeviceInstance) -> bool:
        """After dot1x failure, probe whether the port is still passing traffic.

        If DHCP succeeds the port is open (MAB fallback, open auth, monitor
        mode, or auth-fail VLAN).  We go ONLINE with a flag so the UI can
        show the appropriate indicator without asserting the specific cause.
        """
        mac = device.profile.mac
        offered_ip: Optional[str] = None

        for attempt in range(1, DHCP_MAX_RETRIES + 1):
            device.status_detail = "Port probe %d/%d" % (attempt, DHCP_MAX_RETRIES)

            discover_pkt = build_dhcp_discover(device.profile, self.interface)
            device.xid = discover_pkt["BOOTP"].xid

            offered_ip = await self._send_and_wait_for_dhcp(
                device, discover_pkt, msg_type=2,
            )
            self._log_packet(
                device, "DHCP Discover",
                f"Port probe attempt {attempt}/{DHCP_MAX_RETRIES}",
            )

            if offered_ip:
                break

        if offered_ip:
            device.status_detail = "DHCP Request"
            request_pkt = build_dhcp_request(
                device.profile, device.xid, offered_ip,
                device.server_ip or "255.255.255.255",
            )
            ack_ip = await self._send_and_wait_for_dhcp(
                device, request_pkt, msg_type=5,
            )
            self._log_packet(device, "DHCP Request", f"Requesting {offered_ip}")
            device.assigned_ip = ack_ip if ack_ip else None
        else:
            device.assigned_ip = None

        if device.assigned_ip:
            device.dot1x_failed_open = True
            device.state = DeviceState.ONLINE
            device.status_detail = "dot1x failed \u2014 port open (check NAD/ISE)"
            device.connected_at = time.time()
            self._update_ip_index(device)

            self._start_arp_responder()
            self._start_icmp_responder()
            if self.snmp_enabled and device.profile.snmp:
                self._start_snmp_responder()

            device._keepalive_task = asyncio.create_task(
                self._keepalive_loop(device)
            )

            self._log_packet(
                device, "EAPOL",
                "Port open despite dot1x failure — check switch/ISE for cause",
            )
            logger.info(
                "Port open (dot1x failed): %s (%s) ip=%s gw=%s",
                device.profile.name, mac,
                device.assigned_ip or "none",
                device.gateway_ip or "none",
            )
            return True

        device.state = DeviceState.AUTH_FAILED
        device.status_detail = "Auth failed, port closed"
        self._log_packet(device, "EAPOL", "Port closed — no fallback detected")
        logger.info("Port closed for %s — no MAB fallback", mac)
        return False

    async def disconnect_device(self, mac: str) -> bool:
        """Perform a clean disconnect: DHCP Release + EAPOL-Logoff if dot1x."""
        device = self.devices.get(mac)
        if not device:
            logger.error("Device not found: %s", mac)
            return False

        active_states = (
            DeviceState.ONLINE, DeviceState.CONNECTING,
            DeviceState.AUTHENTICATING, DeviceState.AUTHORIZED,
            DeviceState.AUTH_FAILED,
        )
        if device.state not in active_states:
            logger.warning("Device %s is not active (state=%s)", mac, device.state)
            return False

        device.state = DeviceState.DISCONNECTING

        if device._keepalive_task:
            device._keepalive_task.cancel()
            try:
                await device._keepalive_task
            except asyncio.CancelledError:
                pass
            device._keepalive_task = None

        if device.assigned_ip and device.server_ip:
            release_pkt = build_dhcp_release(
                device.profile, device.assigned_ip, device.server_ip
            )
            await async_send_packet(release_pkt, self.interface)
            self._log_packet(
                device, "DHCP Release",
                f"Released {device.assigned_ip} to {device.server_ip}",
            )

        if device.profile.auth and device._macvlan_iface:
            self._log_packet(device, "EAPOL", "Logoff / cleanup")
            await stop_wpa_supplicant(mac)
            device._macvlan_iface = None

        device.state = DeviceState.STOPPED
        device.status_detail = ""
        device.connected_at = None
        device.assigned_ip = None
        device.server_ip = None
        device.gateway_ip = None
        device.gateway_mac = None
        device.dhcp_subnet = None
        device.dhcp_dns = []
        device.dhcp_lease_time = None
        device.xid = 0
        device.last_ping = None
        device.dot1x_failed_open = False
        self._update_ip_index(device)

        logger.info("Device disconnected: %s (%s)", device.profile.name, mac)
        return True

    async def connect_all(self) -> list[str]:
        """Connect all stopped devices. Returns list of MACs that were connected."""
        connected = []
        for mac, device in self.devices.items():
            if device.state in (DeviceState.STOPPED, DeviceState.AUTH_FAILED):
                await self.connect_device(mac)
                connected.append(mac)
        return connected

    async def disconnect_all(self) -> list[str]:
        """Disconnect all active devices. Returns list of MACs that were disconnected."""
        disconnected = []
        active_states = (
            DeviceState.ONLINE, DeviceState.CONNECTING,
            DeviceState.AUTHENTICATING, DeviceState.AUTHORIZED,
            DeviceState.AUTH_FAILED,
        )
        for mac, device in list(self.devices.items()):
            if device.state in active_states:
                await self.disconnect_device(mac)
                disconnected.append(mac)
        return disconnected

    async def ping_device(self, mac: str, target: Optional[str] = None,
                          count: int = 4) -> PingResult:
        """Send *count* ICMP echo requests and collect per-probe RTTs."""
        device = self.devices.get(mac)
        if not device:
            return PingResult(target="", error="Device not found")

        if device.state != DeviceState.ONLINE:
            return PingResult(target="", error="Device is not online")

        if not device.assigned_ip:
            return PingResult(target="", error="No IP assigned (DHCP incomplete)")

        ping_target = target or device.gateway_ip
        if not ping_target:
            return PingResult(target="", error="No gateway IP available")

        # Set pending state immediately so the next GET /api/devices shows
        # the spinner with the correct target before the ping completes.
        device.last_ping = PingResult(target=ping_target, pending=True)

        dst_mac = device.gateway_mac or "ff:ff:ff:ff:ff:ff"
        rtts: list[Optional[float]] = []

        self._log_packet(device, "ICMP Ping", f"{count}x echo to {ping_target}")

        for seq in range(count):
            icmp_pkt = build_icmp_echo(device.profile, device.assigned_ip, ping_target, dst_mac)
            icmp_id = icmp_pkt[ICMP].id

            rtt_box: dict = {"rtt": None}
            event = asyncio.Event()
            loop = asyncio.get_running_loop()

            def _make_cb(box, evt, pid, dev_ip):
                def _cb(pkt):
                    if not pkt.haslayer(ICMP) or not pkt.haslayer(IP):
                        return
                    if pkt[ICMP].type != 0 or pkt[ICMP].id != pid:
                        return
                    if pkt[IP].dst != dev_ip:
                        return
                    box["rtt"] = (time.time() - box["t"]) * 1000
                    loop.call_soon_threadsafe(evt.set)
                return _cb

            rtt_box["t"] = time.time()
            sniffer = AsyncSniffer(
                iface=self.interface,
                filter=f"icmp and dst host {device.assigned_ip}",
                prn=_make_cb(rtt_box, event, icmp_id, device.assigned_ip),
                store=False,
                timeout=PING_TIMEOUT,
            )
            sniffer.start()
            await asyncio.sleep(0.02)
            await async_send_packet(icmp_pkt, self.interface)

            try:
                await asyncio.wait_for(event.wait(), timeout=PING_TIMEOUT)
            except asyncio.TimeoutError:
                pass
            finally:
                if sniffer.running:
                    # sniffer.stop() calls thread.join() — run in executor
                    # to avoid blocking the event loop
                    await asyncio.get_running_loop().run_in_executor(None, sniffer.stop)

            if rtt_box["rtt"] is not None:
                rtts.append(round(rtt_box["rtt"], 1))
            else:
                rtts.append(None)

            if seq < count - 1:
                await asyncio.sleep(0.3)

        ok = [r for r in rtts if r is not None]
        summary_parts = [f"{r}ms" if r is not None else "*" for r in rtts]
        summary = " ".join(summary_parts)
        if ok:
            self._log_packet(device, "ICMP Reply", f"{ping_target}: {summary}")
            logger.info("Ping %s -> %s: %s", device.profile.name, ping_target, summary)
        else:
            self._log_packet(device, "ICMP Timeout", f"{ping_target}: all timed out")
            logger.info("Ping %s -> %s: all timed out", device.profile.name, ping_target)

        ping_result = PingResult(target=ping_target, rtts=rtts, pending=False)
        device.last_ping = ping_result
        return ping_result

    async def _send_and_wait_for_dhcp(
        self, device: DeviceInstance, pkt: Ether, msg_type: int,
    ) -> Optional[str]:
        """Start a sniffer, THEN send *pkt*, and wait for a DHCP response.

        Starting the sniffer before sending eliminates the race where a fast
        response arrives before the sniffer is ready.

        *msg_type* is the DHCP message-type to wait for (2 = Offer, 5 = ACK).
        Also captures gateway IP (option 3 / router) and the Ethernet source
        MAC of the DHCP server for use as the next-hop MAC in ping operations.
        """
        result: dict[str, Optional[str]] = {"ip": None}
        event = asyncio.Event()
        loop = asyncio.get_running_loop()

        def _pkt_callback(rx):
            if not rx.haslayer(BOOTP) or not rx.haslayer(DHCP):
                return
            bootp = rx[BOOTP]
            if bootp.xid != device.xid:
                return
            dhcp_opts = rx[DHCP].options
            for opt in dhcp_opts:
                if isinstance(opt, tuple) and opt[0] == "message-type" and opt[1] == msg_type:
                    result["ip"] = bootp.yiaddr
                    for o in dhcp_opts:
                        if not isinstance(o, tuple):
                            continue
                        if o[0] == "server_id":
                            device.server_ip = o[1]
                        elif o[0] == "router":
                            gw = o[1]
                            device.gateway_ip = gw if isinstance(gw, str) else gw[0]
                        elif o[0] == "subnet_mask" and msg_type == 5:
                            device.dhcp_subnet = o[1]
                        elif o[0] == "name_server" and msg_type == 5:
                            dns = o[1]
                            device.dhcp_dns = [dns] if isinstance(dns, str) else list(dns)
                        elif o[0] == "lease_time" and msg_type == 5:
                            device.dhcp_lease_time = int(o[1]) if o[1] else None
                    if rx.haslayer(Ether):
                        device.gateway_mac = rx[Ether].src
                    loop.call_soon_threadsafe(event.set)
                    return

        sniffer = AsyncSniffer(
            iface=self.interface,
            filter="udp and port 68",
            prn=_pkt_callback,
            store=False,
            timeout=DHCP_TIMEOUT,
        )
        sniffer.start()

        await asyncio.sleep(0.05)
        await async_send_packet(pkt, self.interface)

        try:
            await asyncio.wait_for(event.wait(), timeout=DHCP_TIMEOUT)
        except asyncio.TimeoutError:
            pass
        finally:
            if sniffer.running:
                await asyncio.get_running_loop().run_in_executor(None, sniffer.stop)

        return result["ip"]

    async def _keepalive_loop(self, device: DeviceInstance) -> None:
        """Send keepalive traffic while online.

        Burst phase (first 8 cycles, 3 s apart):
          - ARP gratuitous
          - 10 TCP SYN probes to public IPs  (~54 B each → 540 B out)
          - ICMP echo to gateway (512 B payload → ~556 B out)
          - Optional mDNS/SSDP
          Burst bidir per cycle: ~2.2 KB; 8 cycles ≈ 17 KB in 24 s.

        Steady phase (configured interval, default 30 s):
          - 4 TCP SYN probes (~216 B out)
          - ICMP echo 256 B payload (~300 B out)
          Steady bidir per cycle: ~1.0 KB.

        TCP SYN probes are the primary client-visibility signal; platforms
        like Meraki filter ARP/DHCP/DNS at the control plane but always
        count forwarded TCP toward client activity.
        """
        steady_interval = device.profile.traffic_interval_sec
        burst_interval = 3
        burst_cycles = 8
        cycle = 0
        ip = device.assigned_ip or "0.0.0.0"

        # Background DHCP retry state — used when device went ONLINE with no IP.
        # This handles the race where the switch was still running the dot1x
        # tx-period timer when MACforge's connect-phase window expired.
        # Retry schedule (seconds after going ONLINE): 5, 15, 30, 60, 120, 240
        _bg_dhcp_delays = [5, 10, 15, 30, 60, 120]
        _bg_dhcp_idx = 0
        _bg_dhcp_at: Optional[float] = (
            time.time() + _bg_dhcp_delays[0]
            if not device.assigned_ip else None
        )

        while device.state == DeviceState.ONLINE:
            # ── background DHCP retry if no IP yet ────────────────────────────
            if _bg_dhcp_at is not None and time.time() >= _bg_dhcp_at:
                if not device.assigned_ip:
                    logger.info(
                        "Background DHCP retry for %s (no IP, attempt %d/%d)",
                        device.profile.mac,
                        _bg_dhcp_idx + 1,
                        len(_bg_dhcp_delays),
                    )
                    discover_pkt = build_dhcp_discover(device.profile, self.interface)
                    device.xid = discover_pkt["BOOTP"].xid
                    offered_ip = await self._send_and_wait_for_dhcp(
                        device, discover_pkt, msg_type=2,
                    )
                    if offered_ip:
                        request_pkt = build_dhcp_request(
                            device.profile, device.xid, offered_ip,
                            device.server_ip or "255.255.255.255",
                        )
                        ack_ip = await self._send_and_wait_for_dhcp(
                            device, request_pkt, msg_type=5,
                        )
                        if ack_ip:
                            device.assigned_ip = ack_ip
                            ip = ack_ip
                            self._update_ip_index(device)
                            _bg_dhcp_at = None  # success — stop retrying
                            self._log_packet(
                                device, "DHCP ACK",
                                f"Background DHCP acquired {ack_ip}",
                            )
                            logger.info(
                                "Background DHCP succeeded for %s: %s",
                                device.profile.mac, ack_ip,
                            )
                        else:
                            logger.warning(
                                "Background DHCP Offer for %s but no ACK",
                                device.profile.mac,
                            )
                    # Advance to next delay, or stop if schedule exhausted
                    if _bg_dhcp_at is not None:
                        _bg_dhcp_idx += 1
                        if _bg_dhcp_idx < len(_bg_dhcp_delays):
                            _bg_dhcp_at = time.time() + _bg_dhcp_delays[_bg_dhcp_idx]
                        else:
                            _bg_dhcp_at = None
                            logger.info(
                                "Background DHCP retries exhausted for %s — giving up",
                                device.profile.mac,
                            )
                else:
                    _bg_dhcp_at = None  # IP was acquired elsewhere

            # ── keepalive traffic ──────────────────────────────────────────────
            if ip == "0.0.0.0":
                ip = device.assigned_ip or "0.0.0.0"

            cycle += 1
            bursting = cycle <= burst_cycles
            interval = burst_interval if bursting else steady_interval
            syn_count = 10 if bursting else 4
            icmp_payload = 512 if bursting else 256

            arp_pkt = build_gratuitous_arp(device.profile, ip)
            await async_send_packet(arp_pkt, self.interface)
            self._log_packet(device, "ARP", f"Gratuitous ARP for {ip}")

            if ip != "0.0.0.0" and device.gateway_ip and device.gateway_mac:
                for _ in range(syn_count):
                    syn_pkt = build_tcp_syn(
                        device.profile, ip, device.gateway_mac,
                    )
                    await async_send_packet(syn_pkt, self.interface)
                    device.packets_sent += 1
                self._log_packet(
                    device, "TCP",
                    f"SYN probes via {device.gateway_ip} (×{syn_count})",
                )

                ping_pkt = build_icmp_echo(
                    device.profile, ip,
                    device.gateway_ip, device.gateway_mac,
                    payload_size=icmp_payload,
                )
                await async_send_packet(ping_pkt, self.interface)
                device.packets_sent += 1
                self._log_packet(device, "ICMP", f"Keepalive ping → {device.gateway_ip}")

            if device.profile.mdns and ip != "0.0.0.0":
                mdns_pkt = build_mdns_announcement(
                    device.profile, ip, device.profile.mdns
                )
                await async_send_packet(mdns_pkt, self.interface)
                self._log_packet(device, "mDNS", device.profile.mdns.service_type)

            if device.profile.ssdp and ip != "0.0.0.0":
                ssdp_pkt = build_ssdp_alive(
                    device.profile, ip, device.profile.ssdp
                )
                await async_send_packet(ssdp_pkt, self.interface)
                self._log_packet(device, "SSDP", device.profile.ssdp.device_type)

            await asyncio.sleep(interval)
