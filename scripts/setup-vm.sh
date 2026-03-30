#!/bin/bash
# MACforge VM / Ubuntu Setup Script
# Tested on: Ubuntu 22.04 LTS, Ubuntu 24.04 LTS (x86_64)
# Also works on: Debian 12 Bookworm, Rocky Linux 9 / RHEL 9 (with notes)
#
# IMPORTANT — Network interface requirement:
#   The interface passed to MACforge MUST be connected to your switch at L2
#   (bridged/trunk, not NAT). MACforge injects raw 802.1X/MAB frames that
#   must reach the switch port directly. A NAT or host-only interface will
#   NOT work for authentication testing.
#
#   In VMware:  set the NIC to "Bridged" mode
#   In VirtualBox: set the NIC to "Bridged Adapter"
#   In KVM/libvirt: attach to a bridge that connects to the physical NIC
#
# Usage:
#   git clone https://github.com/msiegy/macforge.git ~/macforge
#   bash ~/macforge/scripts/setup-vm.sh

set -e

REPO_URL="https://github.com/msiegy/macforge.git"
INSTALL_DIR="$HOME/macforge"
CONTAINER_NAME="macforge"

echo ""
echo "========================================="
echo "  MACforge - Ubuntu / VM Setup"
echo "========================================="
echo ""

# ---------------------------------------------------------------------------
# 1. Check OS and architecture
# ---------------------------------------------------------------------------
echo "[1/7] Checking environment..."
ARCH=$(uname -m)
if [ "$ARCH" != "x86_64" ] && [ "$ARCH" != "aarch64" ]; then
  echo "ERROR: Unsupported architecture: $ARCH"
  exit 1
fi
echo "  Architecture: $ARCH"

# Detect distro for Docker install and SELinux handling
if [ -f /etc/os-release ]; then
  . /etc/os-release
  DISTRO_ID="${ID:-unknown}"
  DISTRO_VERSION="${VERSION_ID:-unknown}"
  echo "  OS: $PRETTY_NAME"
else
  DISTRO_ID="unknown"
  echo "  OS: unknown (proceeding)"
fi

# ---------------------------------------------------------------------------
# 2. System dependencies
# ---------------------------------------------------------------------------
echo "[2/7] Installing system dependencies..."

case "$DISTRO_ID" in
  ubuntu|debian)
    sudo apt-get update -qq
    sudo apt-get install -y -qq git curl iptables iproute2 > /dev/null
    ;;
  rhel|rocky|almalinux|centos|fedora)
    sudo dnf install -y -q git curl iptables iproute > /dev/null
    ;;
  *)
    echo "  WARNING: Unknown distro '$DISTRO_ID' — skipping package install."
    echo "  Ensure git, curl, iptables, and iproute2 are installed manually."
    ;;
esac
echo "  Done"

# ---------------------------------------------------------------------------
# 3. Install Docker
# ---------------------------------------------------------------------------
echo "[3/7] Installing Docker..."
if command -v docker &> /dev/null; then
  echo "  Docker already installed: $(docker --version)"
else
  case "$DISTRO_ID" in
    ubuntu|debian)
      curl -fsSL https://get.docker.com | sh
      ;;
    rhel|rocky|almalinux|centos)
      sudo dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo 2>/dev/null || \
        sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
      sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin
      sudo systemctl enable --now docker
      ;;
    fedora)
      sudo dnf install -y docker
      sudo systemctl enable --now docker
      ;;
    *)
      echo "  WARNING: Cannot auto-install Docker on '$DISTRO_ID'."
      echo "  Install Docker manually: https://docs.docker.com/engine/install/"
      read -rp "  Press Enter once Docker is installed to continue..."
      ;;
  esac
  sudo usermod -aG docker "$USER"
  echo "  Docker installed."
fi

# SELinux note for RHEL/Rocky
if command -v getenforce &>/dev/null && [ "$(getenforce)" = "Enforcing" ]; then
  echo ""
  echo "  NOTE: SELinux is Enforcing. MACforge requires --privileged for macvlan ops."
  echo "  If you see 'Operation not permitted' errors, run:"
  echo "    sudo setenforce 0  (temporary)"
  echo "  or configure an appropriate SELinux policy for macvlan."
  echo ""
fi

# ---------------------------------------------------------------------------
# 4. Disable services that interfere with MAB/802.1X profiling
# ---------------------------------------------------------------------------
echo "[4/7] Disabling host services that interfere with endpoint profiling..."

# lldpd — leaks host identity via LLDP frames on the switch port
if systemctl list-unit-files lldpd.service &>/dev/null 2>&1; then
  sudo systemctl stop lldpd 2>/dev/null || true
  sudo systemctl disable lldpd 2>/dev/null || true
  echo "  Disabled: lldpd"
else
  echo "  lldpd not installed (OK)"
fi

# avahi — host mDNS can confuse ISE device profiling
if systemctl list-unit-files avahi-daemon.service &>/dev/null 2>&1; then
  sudo systemctl stop avahi-daemon 2>/dev/null || true
  sudo systemctl disable avahi-daemon 2>/dev/null || true
  echo "  Disabled: avahi-daemon"
else
  echo "  avahi-daemon not installed (OK)"
fi

# NetworkManager — if it manages the switch-facing interface it will interfere.
# We unmanage just that interface rather than disabling NM entirely.
if command -v nmcli &>/dev/null; then
  echo ""
  echo "  NetworkManager detected. The interface used for 802.1X/MAB testing"
  echo "  must NOT be managed by NetworkManager (it will fight wpa_supplicant)."
  echo ""
  echo "  Detected interfaces:"
  ip -o link show | awk '$2 != "lo:" {gsub(/:/, "", $2); print "    " $2}' | head -10
  echo ""
  read -rp "  Enter the interface name to unmanage (e.g. ens33, eth0): " SWITCH_IFACE
  if [ -n "$SWITCH_IFACE" ]; then
    # Add unmanaged entry to NetworkManager
    NM_CONF="/etc/NetworkManager/conf.d/macforge-unmanaged.conf"
    MAC=$(cat /sys/class/net/"$SWITCH_IFACE"/address 2>/dev/null || echo "")
    if [ -n "$MAC" ]; then
      sudo tee "$NM_CONF" > /dev/null << EOF
[keyfile]
unmanaged-devices=mac:${MAC}
EOF
      sudo systemctl reload NetworkManager 2>/dev/null || true
      echo "  Unmanaged: $SWITCH_IFACE ($MAC) — written to $NM_CONF"
    else
      echo "  WARNING: Could not read MAC for $SWITCH_IFACE — skipping NM unmanage"
    fi
  fi
else
  # No NM — detect the interface automatically
  SWITCH_IFACE=""
fi

# ---------------------------------------------------------------------------
# 5. Detect or confirm switch-facing Ethernet interface
# ---------------------------------------------------------------------------
echo "[5/7] Detecting switch-facing Ethernet interface..."

if [ -z "$SWITCH_IFACE" ]; then
  # Auto-detect: prefer carrier-up wired interfaces
  for iface in eth0 ens33 ens3 enp1s0 enp0s3 $(ls /sys/class/net/ | grep -E '^(en|eth)'); do
    if [ -d "/sys/class/net/$iface" ] && [ "$(cat /sys/class/net/$iface/type 2>/dev/null)" = "1" ]; then
      CARRIER=$(cat /sys/class/net/$iface/carrier 2>/dev/null || echo "0")
      if [ "$CARRIER" = "1" ] && [ -z "$SWITCH_IFACE" ]; then
        SWITCH_IFACE="$iface"
      fi
    fi
  done
fi

if [ -z "$SWITCH_IFACE" ]; then
  echo "  WARNING: No active wired interface found. Defaulting to eth0."
  echo "  Available interfaces:"
  ip -o link show | awk '$2 != "lo:" {gsub(/:/, "", $2); print "    " $2}'
  echo "  To override: cp $INSTALL_DIR/.env.example $INSTALL_DIR/.env"
  echo "  Set MACFORGE_DATA_IFACE in .env, then re-run this script."
  SWITCH_IFACE="eth0"
else
  echo "  Using: $SWITCH_IFACE"
fi

# ---------------------------------------------------------------------------
# 6. Clone or update MACforge
# ---------------------------------------------------------------------------
echo "[6/7] Getting MACforge source..."
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
# 7. Build Docker image and launch
# ---------------------------------------------------------------------------
echo "[7/7] Building Docker image and launching..."
echo "  Note: builds wpa_supplicant_teap from source for TEAP support;"
echo "  all other EAP methods use the apt wpasupplicant package."
sudo docker build -t macforge . 2>&1 | tail -10

echo ""
echo "  Starting MACforge..."

mkdir -p "$INSTALL_DIR/data/certs"
cd "$INSTALL_DIR"

# Stop any existing container cleanly before (re)starting.
sudo docker compose down 2>/dev/null || true

# Interface auto-detection handles standard two-NIC VM setups
# (management NIC with default route + switch-facing NIC) automatically.
# If your VM has more than two NICs, create a .env file from .env.example.
sudo docker compose up -d

# ---------------------------------------------------------------------------
# Verify and print access info
# ---------------------------------------------------------------------------
sleep 3

if sudo docker compose ps --quiet 2>/dev/null | grep -q .; then
  # Show all non-loopback IPv4 addresses
  ALL_IPS=$(ip -4 addr show | grep -oP 'inet \K[\d.]+' | grep -v '127\.')
  HOSTNAME=$(hostname)

  echo ""
  echo "========================================="
  echo "  MACforge is running"
  echo "========================================="
  echo ""
  echo "  Data/NAD interface : $SWITCH_IFACE  (auto-detected — EAP/MAB frames → switch)"
  echo ""
  echo "  Web UI access:"
  for ip in $ALL_IPS; do
    echo "    http://${ip}:8080"
  done
  echo "    http://${HOSTNAME}.local:8080  (if mDNS available)"
  echo ""
  echo "  Manage with Docker Compose (run from $INSTALL_DIR):"
  echo "    cd $INSTALL_DIR"
  echo "    docker compose logs -f    # live logs"
  echo "    docker compose stop       # stop"
  echo "    docker compose up -d      # start again"
  echo "    docker compose down       # stop and remove container"
  echo "    docker compose build      # rebuild image after code changes"
  echo ""
  echo "  To override interface (non-standard NIC names or 3+ NICs):"
  echo "    cp $INSTALL_DIR/.env.example $INSTALL_DIR/.env"
  echo "    # Edit .env, then: docker compose up -d"
  echo ""
  echo "  IMPORTANT — Verify bridged networking:"
  echo "    Your VM NIC ($SWITCH_IFACE) must be in BRIDGED mode,"
  echo "    not NAT. MAB/802.1X frames must reach the physical switch port."
  echo ""
  echo "  Host hardening applied:"
  echo "    - lldpd disabled (no LLDP leak to switch)"
  echo "    - avahi-daemon disabled (no host mDNS leak)"
  if command -v nmcli &>/dev/null && [ -n "$SWITCH_IFACE" ]; then
    echo "    - NetworkManager unmanaged: $SWITCH_IFACE"
  fi
  echo ""
else
  echo ""
  echo "ERROR: Container failed to start."
  echo "Check logs: cd $INSTALL_DIR && docker compose logs"
  echo ""
  exit 1
fi
