"""Scapy packet-crafting engine for device emulation.

Builds and sends DHCP Discover/Request/Release, ARP gratuitous announcements,
mDNS service records, and SSDP announcements using spoofed source MACs.
"""

from __future__ import annotations

import asyncio
import logging
import random
import struct
from typing import Optional

from scapy.all import (
    ARP,
    BOOTP,
    DHCP,
    DNS,
    DNSQR,
    DNSRR,
    ICMP,
    IP,
    TCP,
    UDP,
    Ether,
    sendp,
)
from scapy.asn1.asn1 import ASN1_INTEGER, ASN1_NULL, ASN1_OID, ASN1_STRING
from scapy.layers.snmp import SNMP, SNMPresponse, SNMPvarbind

from macforge.models import DeviceProfile, MDNSService, SNMPProfile, SSDPProfile

logger = logging.getLogger(__name__)

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68
MDNS_ADDR = "224.0.0.251"
MDNS_PORT = 5353
SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900


def _mac_bytes(mac: str) -> bytes:
    return bytes.fromhex(mac.replace(":", "").replace("-", ""))


def _build_client_id(profile: DeviceProfile) -> Optional[bytes]:
    """Build DHCP option 61 value based on profile configuration."""
    cid = profile.dhcp.client_id
    if cid is None:
        return None
    if cid == "mac":
        return b"\x01" + _mac_bytes(profile.mac)
    return cid.encode()


def _build_dhcp_options(profile: DeviceProfile, msg_type: int,
                        xid: int, requested_ip: str = "") -> list:
    """Build the DHCP options list respecting the profile's options_order."""
    option_map: dict[int, tuple] = {
        53: ("message-type", msg_type),
        55: ("param_req_list", profile.dhcp.param_request_list),
    }

    client_id = _build_client_id(profile)
    if client_id is not None:
        option_map[61] = ("client_id", client_id)

    if profile.dhcp.hostname:
        option_map[12] = ("hostname", profile.dhcp.hostname)

    if profile.dhcp.vendor_class:
        option_map[60] = ("vendor_class_id", profile.dhcp.vendor_class)

    if msg_type == 1:
        option_map[81] = option_map.get(81, (81, b"\x00\x00\x00"))

    if requested_ip and msg_type == 3:
        option_map[50] = ("requested_addr", requested_ip)

    opts = []
    for opt_num in profile.dhcp.options_order:
        if opt_num in option_map and opt_num != 255:
            opts.append(option_map.pop(opt_num))

    for opt_num, val in sorted(option_map.items()):
        if opt_num != 53 and opt_num not in {o[0] if isinstance(o, tuple) else -1 for o in opts}:
            opts.append(val)

    if ("message-type", msg_type) not in opts:
        opts.insert(0, ("message-type", msg_type))

    opts.append("end")
    return opts


def build_dhcp_discover(profile: DeviceProfile, iface: str) -> Ether:
    """Build a DHCP Discover packet with full device fingerprint."""
    xid = random.randint(1, 0xFFFFFFFF)
    mac_bytes = _mac_bytes(profile.mac)

    opts = _build_dhcp_options(profile, msg_type=1, xid=xid)

    pkt = (
        Ether(src=profile.mac, dst=BROADCAST_MAC)
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=DHCP_CLIENT_PORT, dport=DHCP_SERVER_PORT)
        / BOOTP(
            chaddr=mac_bytes + b"\x00" * 10,
            xid=xid,
            flags=0x8000,
        )
        / DHCP(options=opts)
    )
    return pkt


def build_dhcp_request(profile: DeviceProfile, xid: int,
                       offered_ip: str, server_ip: str) -> Ether:
    """Build a DHCP Request packet accepting an offered IP."""
    mac_bytes = _mac_bytes(profile.mac)

    opts = _build_dhcp_options(profile, msg_type=3, xid=xid, requested_ip=offered_ip)
    server_opt = ("server_id", server_ip)
    opts.insert(1, server_opt)

    pkt = (
        Ether(src=profile.mac, dst=BROADCAST_MAC)
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=DHCP_CLIENT_PORT, dport=DHCP_SERVER_PORT)
        / BOOTP(
            chaddr=mac_bytes + b"\x00" * 10,
            xid=xid,
            flags=0x8000,
        )
        / DHCP(options=opts)
    )
    return pkt


def build_dhcp_release(profile: DeviceProfile, client_ip: str,
                       server_ip: str) -> Ether:
    """Build a DHCP Release packet for clean session teardown."""
    mac_bytes = _mac_bytes(profile.mac)
    xid = random.randint(1, 0xFFFFFFFF)

    opts = [
        ("message-type", 7),
        ("server_id", server_ip),
    ]
    client_id = _build_client_id(profile)
    if client_id is not None:
        opts.append(("client_id", client_id))
    opts.append("end")

    pkt = (
        Ether(src=profile.mac, dst=BROADCAST_MAC)
        / IP(src=client_ip, dst=server_ip)
        / UDP(sport=DHCP_CLIENT_PORT, dport=DHCP_SERVER_PORT)
        / BOOTP(
            chaddr=mac_bytes + b"\x00" * 10,
            xid=xid,
            ciaddr=client_ip,
        )
        / DHCP(options=opts)
    )
    return pkt


def build_gratuitous_arp(profile: DeviceProfile, ip: str) -> Ether:
    """Build a gratuitous ARP to keep the MAC alive in the switch CAM table."""
    pkt = (
        Ether(src=profile.mac, dst=BROADCAST_MAC)
        / ARP(
            op="is-at",
            hwsrc=profile.mac,
            psrc=ip,
            hwdst=BROADCAST_MAC,
            pdst=ip,
        )
    )
    return pkt


def build_mdns_announcement(profile: DeviceProfile, ip: str,
                            service: MDNSService) -> Ether:
    """Build an mDNS service announcement packet."""
    hostname = profile.dhcp.hostname or profile.name.replace(" ", "-")
    fqdn = f"{hostname}.local"

    pkt = (
        Ether(src=profile.mac, dst="01:00:5e:00:00:fb")
        / IP(src=ip, dst=MDNS_ADDR, ttl=255)
        / UDP(sport=MDNS_PORT, dport=MDNS_PORT)
        / DNS(
            qr=1,
            aa=1,
            an=DNSRR(
                rrname=f"{service.service_name}.{service.service_type}.local",
                type="SRV",
                ttl=120,
                rdata=struct.pack("!HHH", 0, 0, service.port) + fqdn.encode() + b"\x00",
            ),
        )
    )
    return pkt


def build_ssdp_alive(profile: DeviceProfile, ip: str,
                     ssdp: SSDPProfile) -> Ether:
    """Build an SSDP alive notification packet."""
    friendly = ssdp.friendly_name or profile.name
    usn = f"uuid:macforge-{profile.mac.replace(':', '')}::{ssdp.device_type}"

    payload = (
        "NOTIFY * HTTP/1.1\r\n"
        f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
        "CACHE-CONTROL: max-age=1800\r\n"
        f"LOCATION: http://{ip}:8080/description.xml\r\n"
        f"NT: {ssdp.device_type}\r\n"
        "NTS: ssdp:alive\r\n"
        f"SERVER: {friendly}\r\n"
        f"USN: {usn}\r\n"
        "\r\n"
    )

    pkt = (
        Ether(src=profile.mac, dst="01:00:5e:7f:ff:fa")
        / IP(src=ip, dst=SSDP_ADDR, ttl=4)
        / UDP(sport=1900, dport=SSDP_PORT)
        / payload.encode()
    )
    return pkt


def build_keepalive_udp(profile: DeviceProfile, src_ip: str,
                       dst_ip: str, dst_mac: str,
                       payload_size: int = 512) -> Ether:
    """Build a small UDP packet to the gateway to generate background traffic.

    Uses port 9 (discard) so the gateway silently drops it.
    Default 512-byte payload keeps overhead low while satisfying
    platforms that require minimum traffic volume (e.g. Meraki ~1 KB).
    """
    pkt = (
        Ether(src=profile.mac, dst=dst_mac)
        / IP(src=src_ip, dst=dst_ip, ttl=64)
        / UDP(sport=random.randint(49152, 65535), dport=9)
        / (b"\x00" * payload_size)
    )
    return pkt


DNS_QUERY_DOMAINS = [
    "www.google.com", "www.microsoft.com", "time.apple.com",
    "connectivitycheck.gstatic.com", "www.msftconnecttest.com",
    "captive.apple.com", "clients3.google.com", "ocsp.digicert.com",
    "ntp.ubuntu.com", "update.googleapis.com",
]


def build_dns_query(profile: DeviceProfile, src_ip: str,
                    dst_mac: str, dns_server: str = "8.8.8.8",
                    domain: Optional[str] = None) -> Ether:
    """Build a DNS A-record query routed through the gateway.

    Uses realistic domain names that real devices query.
    Traffic is forwarded by the gateway, generating routable
    bidirectional UDP that platforms like Meraki count as client activity.
    """
    qname = domain or random.choice(DNS_QUERY_DOMAINS)
    pkt = (
        Ether(src=profile.mac, dst=dst_mac)
        / IP(src=src_ip, dst=dns_server, ttl=64)
        / UDP(sport=random.randint(49152, 65535), dport=53)
        / DNS(rd=1, qd=DNSQR(qname=qname, qtype="A"))
    )
    return pkt


TCP_SYN_TARGETS = [
    ("23.192.228.84", 80),     # Akamai (connectivity checks)
    ("142.250.80.46", 443),    # Google
    ("204.79.197.200", 443),   # Bing/Microsoft
    ("151.101.1.69", 443),     # Reddit/Fastly CDN
    ("13.107.42.14", 80),      # Microsoft connectivity
]


def build_tcp_syn(profile: DeviceProfile, src_ip: str,
                  dst_mac: str,
                  dst_ip: str | None = None,
                  dst_port: int | None = None) -> Ether:
    """Build a TCP SYN packet to a public IP.

    Single outbound packet (~54 bytes) that is forwarded through the
    data plane. Meraki and similar platforms count forwarded TCP as
    client activity even when ARP/DHCP/DNS are filtered.
    """
    if dst_ip is None or dst_port is None:
        target = random.choice(TCP_SYN_TARGETS)
        dst_ip = dst_ip or target[0]
        dst_port = dst_port or target[1]
    pkt = (
        Ether(src=profile.mac, dst=dst_mac)
        / IP(src=src_ip, dst=dst_ip, ttl=64)
        / TCP(sport=random.randint(49152, 65535), dport=dst_port, flags="S",
              seq=random.randint(0, 0xFFFFFFFF))
    )
    return pkt


def build_icmp_echo(profile: DeviceProfile, src_ip: str,
                    dst_ip: str, dst_mac: str,
                    payload_size: int = 256) -> Ether:
    """Build an ICMP echo request (ping) with the spoofed source MAC/IP.

    Default 256-byte payload so each request+reply pair generates ~600 bytes
    of bidirectional traffic, satisfying platforms like Meraki that require
    minimum traffic volume to register a client.
    """
    pad = b"MACforge-" + (b"\x00" * max(0, payload_size - 9))
    pkt = (
        Ether(src=profile.mac, dst=dst_mac)
        / IP(src=src_ip, dst=dst_ip, ttl=64)
        / ICMP(type=8, code=0, id=random.randint(1, 0xFFFF), seq=1)
        / pad
    )
    return pkt


def build_icmp_reply(src_mac: str, src_ip: str,
                     dst_mac: str, dst_ip: str,
                     icmp_id: int, icmp_seq: int,
                     payload: bytes = b"") -> Ether:
    """Build an ICMP echo reply for incoming pings to emulated devices."""
    pkt = (
        Ether(src=src_mac, dst=dst_mac)
        / IP(src=src_ip, dst=dst_ip, ttl=64)
        / ICMP(type=0, code=0, id=icmp_id, seq=icmp_seq)
        / payload
    )
    return pkt


def build_arp_reply(src_mac: str, src_ip: str,
                    dst_mac: str, dst_ip: str) -> Ether:
    """Build an ARP reply so the gateway can route ICMP replies back to us."""
    pkt = (
        Ether(src=src_mac, dst=dst_mac)
        / ARP(
            op="is-at",
            hwsrc=src_mac,
            psrc=src_ip,
            hwdst=dst_mac,
            pdst=dst_ip,
        )
    )
    return pkt


SYSTEM_OIDS = {
    "1.3.6.1.2.1.1.1.0": "sys_descr",
    "1.3.6.1.2.1.1.2.0": "sys_object_id",
    "1.3.6.1.2.1.1.3.0": "sys_uptime",
    "1.3.6.1.2.1.1.4.0": "sys_contact",
    "1.3.6.1.2.1.1.5.0": "sys_name",
    "1.3.6.1.2.1.1.6.0": "sys_location",
    # Host Resources MIB — ISE SNMP probe checks this for device identification
    "1.3.6.1.2.1.25.3.2.1.3.1": "hr_device_descr",
}

GETNEXT_ORDER = [
    "1.3.6.1.2.1.1.1.0",
    "1.3.6.1.2.1.1.2.0",
    "1.3.6.1.2.1.1.3.0",
    "1.3.6.1.2.1.1.4.0",
    "1.3.6.1.2.1.1.5.0",
    "1.3.6.1.2.1.1.6.0",
    "1.3.6.1.2.1.25.3.2.1.3.1",
]


def _oid_value(oid_str: str, snmp_profile: SNMPProfile, uptime_ticks: int):
    """Return the ASN.1 value for a system MIB OID."""
    field = SYSTEM_OIDS.get(oid_str)
    if field == "sys_descr":
        return ASN1_STRING(snmp_profile.sys_descr)
    if field == "sys_object_id":
        return ASN1_OID(snmp_profile.sys_object_id)
    if field == "sys_uptime":
        return ASN1_INTEGER(uptime_ticks)
    if field == "sys_contact":
        return ASN1_STRING(snmp_profile.sys_contact)
    if field == "sys_name":
        return ASN1_STRING(snmp_profile.sys_name)
    if field == "sys_location":
        return ASN1_STRING(snmp_profile.sys_location)
    if field == "hr_device_descr" and snmp_profile.hr_device_descr:
        return ASN1_STRING(snmp_profile.hr_device_descr)
    return None


def _next_oid(oid_str: str) -> Optional[str]:
    """Return the next OID in the system MIB tree for GETNEXT."""
    if oid_str < GETNEXT_ORDER[0]:
        return GETNEXT_ORDER[0]
    for i, oid in enumerate(GETNEXT_ORDER):
        if oid_str <= oid and i + 1 < len(GETNEXT_ORDER):
            if oid_str == oid:
                return GETNEXT_ORDER[i + 1]
            return oid
    return None


def build_snmp_response(
    src_mac: str, src_ip: str,
    dst_mac: str, dst_ip: str,
    dst_port: int,
    snmp_pkt: SNMP,
    snmp_profile: SNMPProfile,
    uptime_ticks: int = 0,
) -> Optional[Ether]:
    """Build an SNMP response packet for a GET or GETNEXT request."""
    pdu = snmp_pkt.PDU
    pdu_type = pdu.__class__.__name__
    is_getnext = pdu_type == "SNMPnext"

    varbinds = []
    vb = pdu.varbindlist
    while vb is not None and hasattr(vb, "oid"):
        req_oid = vb.oid.val
        if is_getnext:
            target_oid = _next_oid(req_oid)
            if target_oid is None:
                vb = vb.payload if hasattr(vb, "payload") and isinstance(vb.payload, SNMPvarbind) else None
                continue
        else:
            target_oid = req_oid

        val = _oid_value(target_oid, snmp_profile, uptime_ticks)
        if val is not None:
            varbinds.append(SNMPvarbind(oid=ASN1_OID(target_oid), value=val))
        else:
            varbinds.append(SNMPvarbind(oid=ASN1_OID(target_oid), value=ASN1_NULL(0)))

        vb = vb.payload if hasattr(vb, "payload") and isinstance(vb.payload, SNMPvarbind) else None

    if not varbinds:
        return None

    resp_varbindlist = varbinds[0]
    for extra in varbinds[1:]:
        resp_varbindlist /= extra

    response = (
        Ether(src=src_mac, dst=dst_mac)
        / IP(src=src_ip, dst=dst_ip, ttl=64)
        / UDP(sport=161, dport=dst_port)
        / SNMP(
            version=snmp_pkt.version,
            community=snmp_pkt.community,
            PDU=SNMPresponse(
                id=pdu.id,
                varbindlist=resp_varbindlist,
            ),
        )
    )
    return response


def send_packet(pkt: Ether, iface: str) -> None:
    """Send a raw L2 packet on the specified interface (synchronous).

    Use async_send_packet() from async contexts to avoid blocking the
    asyncio event loop — sendp() opens a raw socket and blocks until sent.
    """
    try:
        sendp(pkt, iface=iface, verbose=False)
    except Exception:
        logger.exception("Failed to send packet on %s", iface)


async def async_send_packet(pkt: Ether, iface: str) -> None:
    """Non-blocking wrapper around send_packet for use in async code.

    Runs sendp() in the default thread-pool executor so the asyncio event
    loop is never blocked by raw socket I/O.
    """
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, send_packet, pkt, iface)
