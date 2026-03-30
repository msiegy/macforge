#!/bin/bash
set -e

echo "[MACforge] Applying stealth iptables rules..."

# Allow DHCP client replies (UDP 68)
iptables -A INPUT -p udp --dport 68 -j ACCEPT 2>/dev/null || true

# Allow web UI (TCP 8080)
iptables -A INPUT -p tcp --dport 8080 -j ACCEPT 2>/dev/null || true

# Allow SSH so we don't lock ourselves out under --network host
iptables -A INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null || true

# Allow return traffic for connections we initiated (ping replies, etc.)
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true

# Allow SNMP to reach emulated devices (handled by MACforge SNMP responder).
# No real SNMP daemon runs in this container, so the host IP won't answer.
iptables -A INPUT -p udp --dport 161 -j ACCEPT 2>/dev/null || true

# Block all other inbound TCP SYN (nmap stealth)
iptables -A INPUT -p tcp --syn -j DROP 2>/dev/null || true

echo "[MACforge] Stealth mode active -- web UI on :8080, nmap blocked, SNMP via responder"

exec python -m macforge.cli "$@"
