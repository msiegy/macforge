# MACforge on Raspberry Pi

Turn a Raspberry Pi into a portable, dedicated MAB testing appliance. Plug it into a switch port, control it from your laptop over Wi-Fi, and emulate 20+ network devices.

## Requirements

- **Raspberry Pi 3B v1.2+, 3B+, or 4B** -- Pi 3 (1GB) works, Pi 4 (4GB) is more comfortable
- **Raspberry Pi OS (64-bit) Lite** -- 64-bit is required (see below)
- **MicroSD card** (16GB+) or USB SSD (preferred for durability on Pi 4)
- **Ethernet cable** to connect the Pi to the MAB switch port
- **Power supply** (micro-USB for Pi 3, USB-C for Pi 4, or PoE adapter)
- **Wi-Fi access** for management (built-in on Pi 3B+ and Pi 4)

## Quick Setup

SSH into your Pi and run:

```bash
git clone https://github.com/msiegy/macforge.git ~/macforge
bash ~/macforge/scripts/setup-pi.sh
```

The script handles everything:
- Verifies 64-bit OS
- Installs Docker and system dependencies
- Disables lldpd and avahi-daemon (prevents host identity leaking onto the switch port)
- Detects the correct Ethernet interface
- Clones/updates MACforge and builds the Docker image
- Launches MACforge with host networking and auto-restart on boot

**Have a touchscreen?** Add `--kiosk` to also install X server, Chromium, and auto-launch the UI on boot:

```bash
bash macforge/scripts/setup-pi.sh --kiosk
```

## Manual Setup (Step by Step)

### Step 1: Install the Base OS

**Recommended: Raspberry Pi OS (64-bit) Lite**

The 64-bit (arm64) version is required so Docker pulls the correct `python:3.12-slim` arm64 image. The Lite variant (no desktop) is sufficient since MACforge has its own web UI.

1. Download [Raspberry Pi Imager](https://www.raspberrypi.com/software/)
2. Choose **Raspberry Pi OS (64-bit) Lite** -- based on Debian Bookworm
3. In the imager settings (gear icon), configure:
   - Hostname: `macforge`
   - Enable SSH (password or key-based)
   - Configure Wi-Fi (your lab SSID/password)
   - Set username/password
4. Flash to your SD card or USB SSD
5. Boot the Pi

**Alternative: Ubuntu Server 24.04 LTS** also works -- same arm64 compatibility, slightly more overhead.

#### Verify 64-bit

After first boot, SSH in and confirm:

```bash
uname -m
# Must output: aarch64
```

If it shows `armv7l`, you have the 32-bit OS installed. Reflash with the 64-bit version.

### Step 2: Install Docker

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER

# Log out and back in for group change to take effect
exit
# SSH back in

# Verify
docker --version
```

### Step 3: Disable Host Services

These services leak the Pi's own identity onto the switch port, which can cause ISE to profile based on the host instead of the emulated devices.

```bash
# LLDP -- sends host identity via LLDP frames on the Ethernet port
sudo systemctl stop lldpd 2>/dev/null
sudo systemctl disable lldpd 2>/dev/null

# Avahi/mDNS -- broadcasts the Pi's own mDNS service records
sudo systemctl stop avahi-daemon 2>/dev/null
sudo systemctl disable avahi-daemon 2>/dev/null
```

### Step 4: Clone and Build

```bash
git clone https://github.com/msiegy/macforge.git ~/macforge
cd ~/macforge
sudo docker build -t macforge .
```

The build takes 5-10 minutes on Pi 4, 10-15 minutes on Pi 3. wpa_supplicant is compiled from source **only for TEAP support** — the Bookworm apt package omits `CONFIG_EAP_TEAP=y` and there is no runtime workaround. All other EAP methods (PEAP, EAP-TLS, EAP-FAST, EAP-TTLS) use the standard apt binary.

#### Alternative: Cross-Build on a Faster Machine

If you have Docker Buildx on a faster workstation:

```bash
# On your workstation:
docker buildx build --platform linux/arm64 -t macforge --load .
docker save macforge | gzip > macforge-arm64.tar.gz
scp macforge-arm64.tar.gz pi@macforge.local:~/

# On the Pi:
docker load < ~/macforge-arm64.tar.gz
```

### Step 5: Identify the Ethernet Interface

```bash
ip link show
# Look for eth0 (common), end0 (newer Pi OS), or enx<mac> (USB adapter)
```

### Step 6: Launch MACforge

```bash
mkdir -p ~/macforge/data/certs
cd ~/macforge
docker compose up -d
```

MACforge auto-detects both interfaces — no flags required. On a Pi with wlan0 (Wi-Fi) and eth0/end0 (Ethernet), it automatically uses:
- **wlan0** → management interface (web UI accessible over Wi-Fi)
- **eth0 / end0** → data interface (EAP/MAB frames sent to the switch)

All container configuration (capabilities, volumes, restart policy) lives in `docker-compose.yml` — no need to memorize run flags.

### Step 7: Access the Web UI

Open `http://<pi-wifi-ip>:8080` from your laptop or phone on the same Wi-Fi network.

## Network Topology

The ideal Pi setup uses **Wi-Fi for management** and **Ethernet for MAB traffic**:

```
Your laptop / phone (browser)
    |
    | Wi-Fi (wlan0)  ← management / web UI
    v
  [Raspberry Pi running MACforge]
    |
    | Ethernet (eth0/end0)  ← data / EAP / MAB frames
    v
  [Switch Port - MAB enabled]
    |
    v
  [RADIUS / ISE]
```

MACforge **auto-detects both interfaces**: the NIC carrying the default gateway (wlan0) is
used as the management interface; the other physical NIC (eth0/end0) is used as the
data/NAD interface where emulated device frames are sent. No `--interface` flags required
for a standard Pi two-NIC setup. The interface panel (click the badge in the web UI header)
shows which NIC is assigned each role.

### Configure Wi-Fi (if not done during OS install)

```bash
sudo nmcli device wifi connect "YOUR_SSID" password "YOUR_PASSWORD"
```

## Host Hardening Checklist

All of these are handled by the setup script, but verify if setting up manually:

- [ ] **lldpd disabled** -- `sudo systemctl is-enabled lldpd` should show `disabled` or `not found`
- [ ] **avahi-daemon disabled** -- `sudo systemctl is-enabled avahi-daemon` should show `disabled` or `not found`
- [ ] **Container stealth mode** -- check `cd ~/macforge && docker compose logs | grep stealth` shows iptables rules applied
- [ ] **Correct interface** -- verify with `cd ~/macforge && docker compose logs | grep -i interface` that MACforge logs the expected management and data interfaces at startup
- [ ] **No other DHCP client** -- if running host networking, make sure the Pi's own DHCP client on `eth0` doesn't conflict. The Pi's DHCP lease uses the Pi's real MAC, which is different from the spoofed MACs, so this is usually fine.

## Auto-Connect All Devices on Boot

To have all devices start sending traffic automatically when the Pi powers on (no web UI interaction needed), change the command in `docker-compose.yml`:

```yaml
command: ["--mode", "cli", "--start-all"]
```

Then restart:

```bash
cd ~/macforge && docker compose up -d
```

The container already has `restart: unless-stopped`, so it will also reconnect all devices automatically after a reboot.

## Touchscreen Display (Optional)

MACforge includes a compact touch UI designed for small TFT screens, and also works great on larger displays. The setup script's `--kiosk` flag automates the installation.

### Quick Setup

```bash
bash macforge/scripts/setup-pi.sh --kiosk
```

This installs X server, Chromium, and a systemd service that auto-launches the UI on boot.

### Supported Displays

| Display | Resolution | Framebuffer | UI Served | Notes |
|---------|-----------|-------------|-----------|-------|
| 3.5" SPI TFT (ILI9486) | 480x320 | `/dev/fb1` | `/touch` | Requires dtoverlay |
| 5" HDMI | 800x480 | `/dev/fb0` | `/` | Works out of the box |
| 7" Official DSI | 800x480 | `/dev/fb0` | `/` | Works out of the box |
| 7" Smart Pi Touch (HDMI) | 1280x720 | `/dev/fb0` | `/` | Works out of the box |

The kiosk launcher auto-detects the screen resolution:
- **Width < 800px**: serves `/touch` (compact touch UI with 0.75x scaling)
- **Width >= 800px**: serves `/` (full web UI at 1x scaling)

### Display Overlay Configuration

SPI TFT displays need a device tree overlay in `/boot/config.txt`. Add the appropriate line and reboot:

```bash
# 3.5" ILI9486 (MPI3501 / tft35a)
dtoverlay=tft35a:rotate=90

# 3.5" ILI9341
dtoverlay=tft35a:rotate=90

# 5" HDMI (usually works without an overlay)
# Just set: hdmi_group=2 and hdmi_mode=87 if needed
```

HDMI and DSI displays generally work without overlays.

### Manual Kiosk Launch

If you prefer to start the kiosk manually instead of as a service:

```bash
# SPI TFT on /dev/fb1
sudo scripts/kiosk.sh /dev/fb1

# HDMI/DSI on /dev/fb0
sudo scripts/kiosk.sh /dev/fb0

# Or launch Chromium directly
sudo xinit /usr/bin/chromium --kiosk --no-sandbox --disable-gpu \
  --window-size=480,320 --force-device-scale-factor=0.75 \
  http://localhost:8080/touch -- :0 -nocursor
```

### Kiosk Service Management

```bash
# Start the kiosk now
sudo systemctl start macforge-kiosk

# Stop the kiosk
sudo systemctl stop macforge-kiosk

# Disable auto-start on boot
sudo systemctl disable macforge-kiosk

# View kiosk logs
journalctl -u macforge-kiosk -f
```

### Changing the Framebuffer

If the kiosk starts on the wrong display, edit the service:

```bash
sudo systemctl edit macforge-kiosk
```

Add an override for the framebuffer path:

```ini
[Service]
ExecStart=
ExecStart=/opt/macforge/scripts/kiosk.sh /dev/fb0
```

### Touch Calibration

If touch input is offset, install and run the calibration tool:

```bash
sudo apt-get install xinput-calibrator
DISPLAY=:0 xinput_calibrator
```

Copy the output into `/etc/X11/xorg.conf.d/99-calibration.conf`.

## Tips

### USB SSD Instead of SD Card (Pi 4)

Docker's container writes can wear out SD cards. A USB SSD is more durable and faster:

```bash
sudo raspi-config
# Advanced Options > Boot Order > USB Boot
```

### USB Ethernet Adapter (Second NIC)

If you need a wired management connection instead of Wi-Fi:

```bash
# Check the adapter name
ip link show
# Might show as enx<mac> or eth1
```

With a USB adapter, there are now three NICs (wlan0, eth0, enx…). Auto-detection picks two — but may not pick the one you want for the switch port. Override via `.env`:

```bash
cp ~/macforge/.env.example ~/macforge/.env
# Set MACFORGE_DATA_IFACE=enxABCDEF123456 (your USB adapter name)
cd ~/macforge && docker compose up -d
```

### Monitor from Your Phone

The web UI works from a phone browser. Connect to the same Wi-Fi as the Pi and navigate to `http://macforge.local:8080` or `http://<pi-ip>:8080`.

### Verify Spoofed Traffic Without a Switch

```bash
# Watch for MACforge's spoofed frames on the wire
sudo tcpdump -i eth0 -e -n 'udp port 67 or udp port 68 or arp'
```

You should see frames with Nintendo Switch, Windows, HP printer MACs, etc. as source addresses.

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `uname -m` shows `armv7l` | 32-bit OS | Reflash with Raspberry Pi OS 64-bit |
| Docker build fails | Missing deps or low memory | Run `sudo apt install libpcap-dev`; try cross-build instead |
| ISE profiles as "Linux" | Host lldpd/avahi leaking identity | Verify both are disabled (Step 3) |
| Web UI not reachable | Wrong IP or firewall | Use Pi's Wi-Fi IP, not Ethernet IP |
| "No device profiles found" | Profiles volume not mounted | Verify `./profiles:/app/profiles:ro` in `docker-compose.yml`; run `docker compose up -d` |
| Packets not reaching switch | Wrong interface | Run `ip link show`; set `MACFORGE_DATA_IFACE` in `.env`, then `docker compose up -d` |
| 802.1X device fails — "Operation not permitted" | `privileged` missing | Verify `privileged: true` in `docker-compose.yml` (required for macvlan) |
| TEAP — "unknown EAP method 'TEAP'" | Old container image without TEAP support | `cd ~/macforge && docker compose build --no-cache && docker compose up -d` |
| EAP-TLS times out silently (no ISE auth events) | `wpa_supplicant_teap` absent — TEAP fallback warning in logs | Rebuild the image; EAP-TLS uses the apt binary and should work regardless |
| EAP-TLS: `SSL3 alert: fatal: unknown CA` | ISE trusted cert missing the client-auth trust flag | ISE: Administration → System → Certificates → Trusted Certificates → edit the CA → enable **Trust for client authentication and Syslog** |
