"""Pydantic models for device profiles and API state."""

from __future__ import annotations

import enum
from typing import Optional

from pydantic import BaseModel, Field


class DeviceState(str, enum.Enum):
    STOPPED = "stopped"
    CONNECTING = "connecting"
    AUTHENTICATING = "authenticating"
    AUTHORIZED = "authorized"
    ONLINE = "online"
    AUTH_FAILED = "auth_failed"
    DISCONNECTING = "disconnecting"


class DHCPProfile(BaseModel):
    hostname: str = ""
    vendor_class: str = ""
    client_id: Optional[str] = "mac"
    options_order: list[int] = Field(default_factory=lambda: [53, 61, 12, 60, 55])
    param_request_list: list[int] = Field(default_factory=lambda: [1, 3, 6, 15])


class SSDPProfile(BaseModel):
    device_type: str = ""
    friendly_name: str = ""


class MDNSService(BaseModel):
    service_type: str = ""
    service_name: str = ""
    port: int = 0
    txt_records: dict[str, str] = Field(default_factory=dict)


class Personality(BaseModel):
    category: str = ""
    os: str = ""
    device_type: str = ""


class SNMPProfile(BaseModel):
    sys_descr: str = ""
    sys_object_id: str = ""
    sys_name: str = ""
    sys_contact: str = ""
    sys_location: str = ""
    # Host Resources MIB — OID 1.3.6.1.2.1.25.3.2.1.3.1
    # ISE SNMP probe checks hrDeviceDescr for detailed device identification
    hr_device_descr: str = ""


class AuthProfile(BaseModel):
    """802.1X supplicant configuration for a device."""
    method: str = "peap-mschapv2"
    identity: str = ""
    auth_type: str = "user"
    password: Optional[str] = None
    anonymous_identity: Optional[str] = None
    client_cert: Optional[str] = None
    private_key: Optional[str] = None
    private_key_password: Optional[str] = None
    ca_cert: Optional[str] = None
    validate_server_cert: bool = False
    phase2: str = "MSCHAPV2"
    peap_version: int = 0
    fast_reconnect: bool = True
    pac_provisioning: bool = False
    pac_file: Optional[str] = None
    eapol_version: int = 2
    fragment_size: int = 1398
    # TEAP (RFC 7170) — requires wpa_supplicant >= 2.10
    # Inner methods: "MSCHAPV2", "EAP-TLS", or "Chained" (machine+user in one tunnel)
    teap_inner_method: str = "MSCHAPV2"
    machine_identity: Optional[str] = None   # e.g. host/WIN11-LAB (Chained only)
    machine_cert: Optional[str] = None       # machine client cert filename (Chained)
    machine_key: Optional[str] = None        # machine private key filename (Chained)
    machine_key_password: Optional[str] = None  # machine key passphrase (Chained)


class DeviceProfile(BaseModel):
    name: str
    mac: str
    personality: Personality = Field(default_factory=Personality)
    dhcp: DHCPProfile = Field(default_factory=DHCPProfile)
    auth: Optional[AuthProfile] = None
    mdns: Optional[MDNSService] = None
    ssdp: Optional[SSDPProfile] = None
    snmp: Optional[SNMPProfile] = None
    lldp: bool = False
    traffic_interval_sec: int = 30
    # Phase 2 placeholder: per-device data interface override.
    # When set, this device sends packets on this interface instead of the
    # orchestrator's global data interface. None = use orchestrator default.
    # Full per-device routing (multiple switch ports) is a Phase 2 feature.
    interface: Optional[str] = None


class PingResult(BaseModel):
    target: str
    rtts: list[Optional[float]] = Field(default_factory=list)
    error: Optional[str] = None
    pending: bool = False  # True while ping is in-flight (fire-and-forget)


class DeviceStatus(BaseModel):
    name: str
    mac: str
    state: DeviceState
    status_detail: str = ""
    error_message: Optional[str] = None   # set on auth_failed / connect error
    personality: Personality
    dhcp: DHCPProfile
    auth_method: Optional[str] = None
    auth_state: Optional[str] = None
    auth_identity: Optional[str] = None
    uptime_sec: float = 0.0
    packets_sent: int = 0
    assigned_ip: Optional[str] = None
    gateway_ip: Optional[str] = None
    dhcp_server_ip: Optional[str] = None
    dhcp_subnet: Optional[str] = None
    dhcp_dns: list[str] = Field(default_factory=list)
    dhcp_lease_time: Optional[int] = None
    connected_at: Optional[float] = None
    auth_started_at: Optional[float] = None
    auth_completed_at: Optional[float] = None
    last_ping: Optional[PingResult] = None
    is_custom: bool = False
    diagnostic_error_count: int = 0


class DeviceCreatePayload(BaseModel):
    name: str
    mac: str = ""
    oui_hint: str = ""
    personality: Personality = Field(default_factory=Personality)
    dhcp: DHCPProfile = Field(default_factory=DHCPProfile)
    auth: Optional[AuthProfile] = None
    traffic_interval_sec: int = 30


class DeviceEditPayload(BaseModel):
    name: Optional[str] = None
    personality: Optional[Personality] = None
    dhcp: Optional[DHCPProfile] = None
    traffic_interval_sec: Optional[int] = None


class PacketLogEntry(BaseModel):
    timestamp: float
    device_name: str
    mac: str
    packet_type: str
    detail: str


class PacketEvent(BaseModel):
    """A single captured packet event for the per-device Packet Inspector (Phase 5)."""
    timestamp: float
    direction: str          # "sent" | "recv"
    protocol: str           # "EAPOL" | "DHCP" | "ARP" | "ICMP" | "mDNS" | "SSDP"
    summary: str
    size_bytes: int
    detail: dict = {}       # protocol-specific decoded fields for UI expand
    raw_bytes: bytes = b""  # raw frame bytes for pcap export (not serialised to JSON)


class NADConfig(BaseModel):
    """SSH connection settings for a Cisco IOS/IOS-XE network access device (Phase 3)."""
    host: str = ""
    port: int = 22
    username: str = ""
    password: str = ""
    enable_password: str = ""


class AuthFlowEvent(BaseModel):
    """A single parsed event from the wpa_supplicant auth exchange."""
    timestamp: float
    step: int
    actor: str          # "supplicant" | "authenticator" | "radius"
    event_type: str     # "identity" | "method_propose" | "method_accept" |
                        #  "tls_start" | "tls_done" | "inner_auth" |
                        #  "cert_received" | "cert_san" | "success" | "failure" |
                        #  "nak" | "teap_tlv" | "connected" | "timeout" | "info"
    detail: str
    raw_log_line: str

class CoARequest(BaseModel):
    """Payload for POST /api/devices/{mac}/coa."""
    # ERS CoA: "reauth" | "disconnect" | "port_bounce"
    # ANC (no session ID needed): "anc:<policy_name>"
    action: str
    # Optional: pre-supply the ISE session ID to skip the MnT session-lookup step.
    session_id: Optional[str] = None