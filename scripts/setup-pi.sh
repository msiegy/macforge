#!/bin/bash
# MACforge Raspberry Pi Setup Script
# Tested on: Raspberry Pi 3B/3B+/4B with Raspberry Pi OS (64-bit) Lite
#
# This script handles everything:
#   - System dependencies
#   - Docker installation
#   - Disable services that interfere with MAB testing (lldpd, avahi, cdp)
#   - Clone and build MACforge
#   - Detect the correct Ethernet interface
#   - Launch MACforge with host networking
#
# Usage:
#   git clone https://github.com/msiegy/macforge.git ~/macforge
#   bash ~/macforge/scripts/setup-pi.sh
#
# Options:
#   --kiosk   Also install X server, Chromium, and a systemd service to
#             auto-launch the MACforge touch UI on an attached display.

set -e

REPO_URL="https://github.com/msiegy/macforge.git"
INSTALL_DIR="$HOME/macforge"
CONTAINER_NAME="macforge"
KIOSK_MODE=false

for arg in "$@"; do
  case "$arg" in
    --kiosk) KIOSK_MODE=true ;;
  esac
done

STEP_TOTAL=8
if [ "$KIOSK_MODE" = true ]; then
  STEP_TOTAL=10
fi

echo ""
echo "========================================="
echo "  MACforge - Raspberry Pi Setup"
if [ "$KIOSK_MODE" = true ]; then
  echo "  (with kiosk display)"
fi
echo "========================================="
echo ""

# ---------------------------------------------------------------------------
# 1. Verify 64-bit OS
# ---------------------------------------------------------------------------
echo "[1/8] Checking architecture..."
ARCH=$(uname -m)
if [ "$ARCH" = "aarch64" ]; then
  echo "  OK: aarch64 (Raspberry Pi)"
elif [ "$ARCH" = "x86_64" ]; then
  echo "  NOTE: x86_64 detected — this script targets Raspberry Pi."
  echo "  For Ubuntu/VM deployments use scripts/setup-vm.sh instead."
  echo "  Continuing anyway..."
else
  echo "ERROR: Unsupported architecture: $ARCH"
  exit 1
fi

# ---------------------------------------------------------------------------
# 2. System dependencies
# ---------------------------------------------------------------------------
echo "[2/8] Installing system dependencies..."
sudo apt-get update -qq
sudo apt-get install -y -qq git curl iptables libpcap-dev > /dev/null

# ---------------------------------------------------------------------------
# 3. Install Docker
# ---------------------------------------------------------------------------
echo "[3/8] Installing Docker..."
if command -v docker &> /dev/null; then
  echo "  Docker already installed: $(docker --version)"
else
  curl -fsSL https://get.docker.com | sh
  sudo usermod -aG docker "$USER"
  echo "  Docker installed. Group added (using sudo for this session)."
fi

# ---------------------------------------------------------------------------
# 4. Disable services that leak host identity onto the switch port
# ---------------------------------------------------------------------------
echo "[4/8] Disabling host services that interfere with MAB profiling..."

# LLDP daemon -- leaks host identity via LLDP frames
if systemctl list-unit-files lldpd.service &>/dev/null 2>&1; then
  sudo systemctl stop lldpd 2>/dev/null || true
  sudo systemctl disable lldpd 2>/dev/null || true
  echo "  Disabled: lldpd"
else
  echo "  lldpd not installed (OK)"
fi

# Avahi/mDNS -- host's own mDNS announcements can confuse ISE profiling
if systemctl list-unit-files avahi-daemon.service &>/dev/null 2>&1; then
  sudo systemctl stop avahi-daemon 2>/dev/null || true
  sudo systemctl disable avahi-daemon 2>/dev/null || true
  echo "  Disabled: avahi-daemon"
else
  echo "  avahi-daemon not installed (OK)"
fi

# ARP flux -- on multi-homed hosts (eth0 + wlan0), Linux responds to ARP
# requests for wlan0's IP on eth0, causing switches/Meraki to see a ghost
# client with the wired MAC but the WiFi IP.
SYSCTL_CONF="/etc/sysctl.d/99-macforge.conf"
if [ ! -f "$SYSCTL_CONF" ]; then
  sudo tee "$SYSCTL_CONF" > /dev/null << 'SYSCTLEOF'
# MACforge: prevent ARP flux on multi-homed hosts.
# Without this, the wlan0 IP leaks onto eth0 via ARP, causing switches
# and platforms like Meraki to see a phantom client entry.
net.ipv4.conf.all.arp_announce=2
net.ipv4.conf.all.arp_filter=1
net.ipv4.conf.default.arp_announce=2
net.ipv4.conf.default.arp_filter=1
SYSCTLEOF
  sudo sysctl --system > /dev/null 2>&1
  echo "  Applied: ARP flux prevention (arp_announce=2, arp_filter=1)"
else
  echo "  ARP flux sysctl already configured"
fi

# ---------------------------------------------------------------------------
# 5. Detect Ethernet interface
# ---------------------------------------------------------------------------
echo "[5/8] Detecting Ethernet interface..."
ETH_IFACE=""
for iface in eth0 end0 $(ls /sys/class/net/ | grep -E '^en'); do
  if [ -d "/sys/class/net/$iface" ] && [ "$(cat /sys/class/net/$iface/type 2>/dev/null)" = "1" ]; then
    CARRIER=$(cat /sys/class/net/$iface/carrier 2>/dev/null || echo "0")
    if [ "$CARRIER" = "1" ] || [ -z "$ETH_IFACE" ]; then
      ETH_IFACE="$iface"
    fi
  fi
done

if [ -z "$ETH_IFACE" ]; then
  echo "  WARNING: No wired Ethernet interface detected."
  echo "  Defaulting to eth0. Change with: --interface <name>"
  ETH_IFACE="eth0"
else
  echo "  Found: $ETH_IFACE"
fi

# ---------------------------------------------------------------------------
# 6. Clone or update MACforge
# ---------------------------------------------------------------------------
echo "[6/8] Getting MACforge source..."
if [ -d "$INSTALL_DIR/.git" ]; then
  echo "  Updating existing clone..."
  cd "$INSTALL_DIR" && git pull --ff-only
else
  if [ -d "$INSTALL_DIR" ]; then
    echo "  Directory exists but is not a git repo. Using as-is."
  else
    git clone "$REPO_URL" "$INSTALL_DIR"
    echo "  Cloned to $INSTALL_DIR"
  fi
  cd "$INSTALL_DIR"
fi

# ---------------------------------------------------------------------------
# 7. Build Docker image
# ---------------------------------------------------------------------------
echo "[7/8] Building Docker image (this takes a few minutes on Pi)..."
echo "  Note: builds wpa_supplicant_teap from source for TEAP support;"
echo "  all other EAP methods use the apt wpasupplicant package."
sudo docker build -t macforge . 2>&1 | tail -10

# ---------------------------------------------------------------------------
# 8. Launch MACforge
# ---------------------------------------------------------------------------
echo "[8/8] Starting MACforge..."

mkdir -p "$INSTALL_DIR/data/certs"
cd "$INSTALL_DIR"

# Stop any existing container cleanly before (re)starting.
sudo docker compose down 2>/dev/null || true

# Interface auto-detection handles standard Pi setups (wlan0 = management,
# eth0/end0 = data/switch port) without any extra configuration.
# If your setup has more than two NICs, create a .env file from .env.example.
sudo docker compose up -d

# ---------------------------------------------------------------------------
# 9/10. Kiosk display setup (optional)
# ---------------------------------------------------------------------------
if [ "$KIOSK_MODE" = true ]; then
  echo "[9/${STEP_TOTAL}] Installing kiosk display packages..."
  sudo apt-get install -y -qq \
    xserver-xorg-core xserver-xorg-video-fbdev \
    xinit x11-xserver-utils chromium > /dev/null 2>&1 || \
  sudo apt-get install -y -qq \
    xserver-xorg-core xserver-xorg-video-fbdev \
    xinit x11-xserver-utils chromium-browser > /dev/null 2>&1
  echo "  Installed: X server, Chromium"

  echo "[10/${STEP_TOTAL}] Configuring kiosk autostart..."

  # Install kiosk launcher to a system path
  sudo mkdir -p /opt/macforge/scripts
  sudo cp "$INSTALL_DIR/scripts/kiosk.sh" /opt/macforge/scripts/kiosk.sh
  sudo chmod +x /opt/macforge/scripts/kiosk.sh

  # Detect framebuffer -- SPI TFTs are usually /dev/fb1, HDMI/DSI is /dev/fb0
  KIOSK_FB="/dev/fb0"
  if [ -e /dev/fb1 ]; then
    KIOSK_FB="/dev/fb1"
    echo "  Detected /dev/fb1 (SPI TFT display)"
  else
    echo "  Using /dev/fb0 (HDMI/DSI display)"
  fi

  # Write the service file with the correct framebuffer
  sudo tee /etc/systemd/system/macforge-kiosk.service > /dev/null << SVCEOF
[Unit]
Description=MACforge Kiosk (Chromium on touchscreen)
After=docker.service network-online.target
Wants=network-online.target
ConditionPathExists=/usr/bin/chromium

[Service]
Type=simple
ExecStart=/opt/macforge/scripts/kiosk.sh ${KIOSK_FB}
Restart=on-failure
RestartSec=5
Environment=HOME=/root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVCEOF

  sudo systemctl daemon-reload
  sudo systemctl enable macforge-kiosk.service
  echo "  Kiosk service enabled (macforge-kiosk.service)"
  echo ""
  echo "  IMPORTANT: You must configure your display overlay in /boot/config.txt"
  echo "  Common overlays:"
  echo "    3.5\" SPI TFT (ILI9486):  dtoverlay=tft35a:rotate=90"
  echo "    7\" DSI (official):       (works out of the box on fb0)"
  echo "    Smart Pi Touch (HDMI):   (works out of the box on fb0)"
  echo "  Reboot after editing /boot/config.txt."
  echo ""
fi

# ---------------------------------------------------------------------------
# Verify and print access info
# ---------------------------------------------------------------------------
sleep 3

if sudo docker compose ps --quiet 2>/dev/null | grep -q .; then
  WIFI_IP=$(ip -4 addr show wlan0 2>/dev/null | grep -oP 'inet \K[\d.]+' || echo "")
  ETH_IP=$(ip -4 addr show "$ETH_IFACE" 2>/dev/null | grep -oP 'inet \K[\d.]+' || echo "")
  HOSTNAME=$(hostname)

  echo ""
  echo "========================================="
  echo "  MACforge is running"
  echo "========================================="
  echo ""
  echo "  Data/NAD interface : $ETH_IFACE  (auto-detected — EAP/MAB frames → switch)"
  echo ""
  echo "  Web UI access:"
  if [ -n "$WIFI_IP" ]; then
    echo "    http://${WIFI_IP}:8080  (Wi-Fi)"
  fi
  if [ -n "$ETH_IP" ]; then
    echo "    http://${ETH_IP}:8080  (Ethernet)"
  fi
  echo "    http://${HOSTNAME}.local:8080  (mDNS -- if avahi re-enabled)"
  echo ""
  echo "  Manage with Docker Compose (run from $INSTALL_DIR):"
  echo "    cd $INSTALL_DIR"
  echo "    docker compose logs -f    # live logs"
  echo "    docker compose stop       # stop"
  echo "    docker compose up -d      # start again"
  echo "    docker compose down       # stop and remove container"
  echo "    docker compose build      # rebuild image after code changes"
  echo ""
  echo "  To override interface (non-standard NIC names):"
  echo "    cp $INSTALL_DIR/.env.example $INSTALL_DIR/.env"
  echo "    # Edit .env, then: docker compose up -d"
  echo ""
  echo "  Host hardening applied:"
  echo "    - lldpd disabled (no LLDP leak)"
  echo "    - avahi-daemon disabled (no host mDNS leak)"
  echo "    - ARP flux prevention (wlan0 IP won't leak onto eth0)"
  echo "    - Container stealth iptables active (blocks nmap/SNMP)"
  echo ""

  if [ "$KIOSK_MODE" = true ]; then
    echo "  Kiosk display:"
    echo "    - Service: macforge-kiosk.service (enabled on boot)"
    echo "    - Start now: sudo systemctl start macforge-kiosk"
    echo "    - Logs:      journalctl -u macforge-kiosk -f"
    echo "    - Touch UI:  http://localhost:8080/touch"
    echo ""
  fi
else
  echo ""
  echo "ERROR: Container failed to start."
  echo "Check logs: cd $INSTALL_DIR && docker compose logs"
  echo ""
  exit 1
fi
