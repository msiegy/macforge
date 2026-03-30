# MACforge Deployment Guide

## Build the Docker Image

From the `MACforge/` directory:

```bash
docker build -t macforge .
```

> **Note:** The build compiles `sscep` from source (absent from Debian arm64 apt) and a
> second `wpa_supplicant` binary from source specifically for TEAP. This takes ~3 min on
> a modern workstation, ~8-10 min on a Raspberry Pi 4.
>
> **Why two wpa_supplicant binaries?**
> - `/usr/sbin/wpa_supplicant` — installed from the Debian apt package (`wpasupplicant`).
>   Used for **PEAP, EAP-TLS, EAP-FAST, EAP-TTLS**. Correctly built with internal MD4/DES.
> - `/usr/local/sbin/wpa_supplicant_teap` — built from **git HEAD** (`hostap.git`, v2.12-devel)
>   with `CONFIG_EAP_TEAP=y`. Used **only for TEAP** — the apt package has no `CONFIG_EAP_TEAP=y`
>   and there is no runtime workaround. **Must be v2.12-devel or later**: wpa_supplicant 2.10 had
>   a Crypto-Binding MAC computation bug for TEAP+MSCHAPv2 (ISE error `11577`); fixed in git HEAD.
>
> **OpenSSL 3.x note:** OpenSSL 3.0+ (Ubuntu 22.04+, Debian Bookworm, RHEL 9+) disables
> the "legacy" provider which includes MD4 and DES. MSCHAPv2 requires both. The apt
> `wpasupplicant` package is compiled with `CONFIG_INTERNAL_MD4=y`/`CONFIG_INTERNAL_DES=y`
> which bypasses OpenSSL for those primitives. When building from source with
> `CONFIG_TLS=openssl`, do NOT set `CONFIG_INTERNAL_MD4/DES` — they conflict at link time
> (duplicate symbol). Instead, `crypto_openssl.c` provides them via the lower-level API
> which still works even when the EVP legacy provider is disabled.

## Choose Your Network Mode

### Option A: macvlan (Real MAB Testing Against a Physical Switch)

This gives the container direct L2 access to the same segment as your switch port. The emulated device MACs will appear as real endpoints to the switch.

```bash
# Create macvlan network -- update these for YOUR environment:
#   parent = the host NIC physically cabled to the MAB switch port
#   subnet/gateway = the VLAN/subnet on that port
docker network create -d macvlan \
  --subnet=10.10.10.0/24 \
  --gateway=10.10.10.1 \
  -o parent=eth1 \
  mab-net

# Run MACforge on that network
docker run -d --name macforge \
  --privileged \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  --network mab-net \
  -v "$PWD/data:/app/data" \
  -v "$PWD/profiles:/app/profiles:ro" \
  -p 8080:8080 \
  macforge --mode web --verbose
```

With macvlan, the container's `eth0` is directly on the physical segment. Scapy sends raw frames out `eth0` with the spoofed MACs, and those frames hit the switch port as if they came from real devices.

### Option B: Host Networking — Docker Compose (Recommended)

The standard and recommended deployment. From the project directory:

```bash
cd ~/macforge
docker compose up -d
```

MACforge auto-detects the management interface (NIC with the default route) and the data/switch-facing interface (the other NIC on a two-NIC host). No extra flags required.

**Non-standard NIC names or 3+ NICs?** Override via `.env`:

```bash
cp ~/macforge/.env.example ~/macforge/.env
# Set MACFORGE_DATA_IFACE and optionally MACFORGE_IFACE in .env
docker compose up -d
```

You can also switch the active interface at runtime from the web UI interface panel.

### Managing the container (all environments)

```bash
cd ~/macforge
docker compose logs -f    # live log stream
docker compose stop       # stop gracefully
docker compose up -d      # start / restart
docker compose down       # stop and remove container
docker compose build      # rebuild image after pulling code updates
```

## Access the Web UI

Open `http://<docker-host-ip>:8080` in your browser. All device cards start in the stopped state. Click **Connect** on individual devices or **Connect All** to start sending traffic.

## Switch Port Configuration

The switch port connected to the Docker host must be configured for MAB. For multiple simultaneous emulated devices, use multi-auth mode.

Cisco IOS example:

```
interface GigabitEthernet1/0/1
  switchport mode access
  switchport access vlan 100
  authentication host-mode multi-auth
  authentication port-control auto
  mab
  dot1x pae authenticator
```

If only testing one device at a time, single-host mode works:

```
interface GigabitEthernet1/0/1
  switchport mode access
  switchport access vlan 100
  authentication host-mode single-host
  authentication port-control auto
  mab
```

## Host Preparation Checklist

1. **Identify the right NIC**: Run `ip link` to list interfaces. On a two-NIC host, MACforge auto-detects: the NIC with the default gateway becomes management, the other becomes the data/switch port. If auto-detection picks wrong (3+ NICs), set `MACFORGE_DATA_IFACE` in a `.env` file (copy from `.env.example`).

2. **Disable lldpd**: If the host runs `lldpd`, stop it on that NIC so it doesn't leak the host's identity:
   ```bash
   sudo systemctl stop lldpd
   sudo systemctl disable lldpd
   ```

3. **Verify Docker capabilities**: The container needs `--privileged`, `NET_RAW`, and `NET_ADMIN`. `--privileged` is required for macvlan creation (802.1X devices). Rootless Docker does not support these — you need standard Docker with root privileges.

4. **Check iptables support**: The container runs iptables at startup for stealth mode. The host kernel must have `iptables` / `nf_tables` modules loaded (default on most Linux distros).

## Verify It's Working

Once a device is connected in the UI:

- **On the switch**: `show mac address-table` shows the spoofed MAC on the port
- **On ISE/RADIUS**: A MAB authentication event appears with the MAC as the `Calling-Station-Id`
- **In the MACforge UI**: The packet log shows DHCP Discover/Request sent, and if there's a real DHCP server, the device gets an IP assigned

### Testing Without a Switch

If you're testing the container itself first (no switch), start normally with Docker Compose and use `tcpdump` in a separate terminal to verify spoofed frames are being sent:

```bash
# Terminal 1 — start MACforge
cd ~/macforge && docker compose up -d

# Terminal 2 — watch for spoofed traffic on the wire
sudo tcpdump -i eth0 -e -n 'udp port 67 or udp port 68 or arp'
```

You'll see frames with the Nintendo Switch MAC, Windows MAC, etc. as source addresses.

## Volumes and Persistent Data

MACforge uses **bind mounts** (not Docker named volumes) so you can directly manage files on the host:

| Host path | Container path | Purpose |
|-----------|---------------|----------|
| `./data/` | `/app/data/` | Config JSON files, cert store, MAC seed |
| `./data/certs/` | `/app/data/certs/` | EAP-TLS certs, keys, CA bundles |
| `./profiles/` | `/app/profiles/` | Device profile YAML (read-only) |

### MAC Address Determinism

MACforge generates deterministic MAC addresses based on the host NIC's hardware MAC. Each device retains its vendor OUI but the last 3 bytes are derived from the host, so:

- Same Pi/server = same MACs every run (survives rebuilds, reboots, reinstalls)
- Different hardware = different MACs (no collisions across deployments)

To run **multiple instances on the same host** with unique MACs, clone the repo to a second directory and set `MACFORGE_INSTANCE_ID` in each instance's `.env`:

```bash
# Instance A — already running from ~/macforge
# ~/macforge/.env contains: MACFORGE_DATA_IFACE=eth0, MACFORGE_INSTANCE_ID=port1

# Instance B — second switch port
git clone https://github.com/msiegy/macforge.git ~/macforge-port2
cd ~/macforge-port2
cp .env.example .env
# Set MACFORGE_DATA_IFACE=eth1 and MACFORGE_INSTANCE_ID=port2 in .env
docker compose up -d
```

The seed fingerprint is visible in the web UI (hover over the interface badge) and via `GET /api/interface`.

If the NIC MAC cannot be read (e.g. containerized without host networking), a random seed is generated once and persisted to `/app/data/.mac_seed` so MACs remain stable across restarts.

Running from `~/macforge/` on the Pi? Your working cert paths are:
```
~/macforge/data/certs/   ← scp or cp certs here
~/macforge/data/         ← auth_config.json, custom_devices.json, ise_config.json live here
```

Files written by the container (JSON configs) will be owned by `root` because the container runs as root. This is expected — they are mode `644` so your user can read them, and the container can update them freely.

## Custom Profiles

Mount a custom profiles directory to override or extend the built-in devices. Edit the `volumes:` section in `docker-compose.yml`:

```yaml
volumes:
  - ./data:/app/data
  - /path/to/my/profiles:/app/profiles:ro   # ← change this line
```

Then restart:

```bash
cd ~/macforge && docker compose up -d
```

## Headless / CLI Mode

For automated testing without the web UI:

```bash
cd ~/macforge
docker compose run --rm macforge --mode cli --start-all --verbose
```

This connects all devices immediately and runs until Ctrl+C. Interface auto-detection applies here too.

## Stopping and Cleanup

```bash
cd ~/macforge

# Stop the container (disconnects all devices cleanly via DHCP Release)
docker compose stop

# Stop and remove the container
docker compose down

# Remove the macvlan network if created (Option A only)
docker network rm mab-net
```

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| "No device profiles found" | Profiles directory missing or empty | Check `--profiles-dir` or ensure `profiles/` is mounted |
| Packets not reaching switch | Wrong interface specified | Verify with `ip link`; use the NIC connected to the switch |
| "Operation not permitted" on sendp | Missing capabilities | Verify `NET_RAW` and `NET_ADMIN` are set in `docker-compose.yml` (default: yes) |
| 802.1X fails — "Operation not permitted" | `privileged` missing | Verify `privileged: true` in `docker-compose.yml` (required for macvlan creation) |
| TEAP — "unknown EAP method 'TEAP'" | Using apt wpa_supplicant instead of source-built binary | MACforge auto-selects the right binary; if you see this, rebuild the image |
| PEAP — "Unsupported Phase2 EAP method 'MSCHAPV2'" | Source-built wpa_supplicant used for PEAP (pre-dual-binary builds) | Rebuild the image — MACforge now uses the apt binary for PEAP |
| ISE profiles device as "Linux" | ISE nmap/SNMP probe seeing the container | Verify iptables stealth rules loaded (check container logs) |
| MAC not appearing on switch | Interface down or cable issue | Check `ip link show <interface>` is UP |
| Web UI not accessible | Port not published or firewall | Ensure `-p 8080:8080` or `--network host` |
| EAP-TLS times out silently (no ISE auth events) | Source-built binary missing and fallback to apt binary occurred, but TEAP was also configured | Check container logs for "falling back" warning; ensure Docker image is rebuilt so `wpa_supplicant_teap` is present for TEAP devices |
| EAP-TLS: `SSL3 alert: fatal: unknown CA` | ISE trusted cert missing the client-auth trust flag | ISE: Administration → System → Certificates → Trusted Certificates → edit the CA → enable **Trust for client authentication and Syslog** |
| EAP-TLS: `Failed to load root certificates` | `ca_cert=""` passed to OpenSSL — causes ENOENT on empty path | Rebuild the image; current code omits `ca_cert` entirely when not validating server cert, which OpenSSL treats as `SSL_VERIFY_NONE` |

## VM / Non-Raspberry Pi Deployments

MACforge is tested on Raspberry Pi 4 (Debian Bookworm arm64) but works on any Linux host
that supports macvlan and raw sockets. Notes for common platforms:

| Platform | Notes |
|----------|-------|
| **Ubuntu 22.04 / 24.04** | OpenSSL 3.x — same MD4/DES legacy provider issue as Bookworm. Docker build handles this correctly. No extra steps. |
| **RHEL 9 / Rocky 9 / AlmaLinux 9** | OpenSSL 3.x — same as Ubuntu. Additionally, SELinux may block macvlan ops — run container with `--privileged` or add appropriate SELinux policy. |
| **Ubuntu 20.04** | OpenSSL 1.1 — MD4/DES available by default. Build still works; dual-binary strategy still used for TEAP. |
| **Any VM** | Use `--data-interface` (or `MACFORGE_DATA_IFACE`) to specify the bridged/SR-IOV NIC connected to the switch. A NAT interface will not work for MAB/802.1X (packets never reach the switch). With exactly two NICs, MACforge auto-detects: default-route NIC = management, other NIC = data. |
| **WSL2** | Not supported — WSL2 networking does not support raw L2 sockets or macvlan. Use a Linux VM or bare metal. |
