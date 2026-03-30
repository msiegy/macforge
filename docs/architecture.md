# MACforge — Architecture Reference
Useful when making structural or API changes

## Folder Structure

    MACforge/
    ├── Dockerfile                  # python:3.12-slim-bookworm + apt wpasupplicant + wpa_supplicant_teap (source, TEAP only) + sscep (source)
    ├── docker-compose.yml          # host-mode container with bind mounts (./data, ./profiles)
    ├── entrypoint.sh               # iptables stealth rules → python -m macforge.cli
    ├── requirements.txt
    │
    ├── macforge/
    │   ├── cli.py                  # arg parsing, starts web or headless mode
    │   ├── web.py                  # FastAPI app — all REST endpoints
    │   ├── orchestrator.py         # device lifecycle, ARP/ICMP/SNMP responders
    │   ├── engine.py               # Scapy packet builders (DHCP, ARP, TCP SYN, ICMP, mDNS, SSDP, SNMP)
    │   ├── models.py               # Pydantic models (DeviceProfile, AuthProfile, DeviceStatus)
    │   ├── profiles.py             # YAML loader + deterministic MAC generation (HMAC-SHA256 seed)
    │   ├── dot1x.py                # wpa_supplicant + macvlan + cert storage
    │   ├── certgen.py              # Lab CA, client cert, CSR (cryptography lib)
    │   ├── ise_api.py              # Cisco ISE OpenAPI v1
    │   ├── scep_client.py          # enroll_scep() via sscep + enroll_step_ca() stubbed
    │   └── static/
    │       ├── index.html          # single-page tabbed UI
    │       ├── style.css           # ~1930 lines
    │       ├── app.js              # ~2297 lines
    │       └── touch/              # compact RPi touchscreen UI
    │
    ├── profiles/
    │   ├── dot1x.yaml              # 2 built-in 802.1X profiles (PEAP-MSCHAPv2, EAP-FAST)
    │   ├── apple.yaml / windows.yaml / linux.yaml
    │   ├── printers.yaml / iot.yaml / gaming.yaml
    │   ├── medical.yaml / industrial.yaml
    │
    ├── scripts/
    │   ├── setup-pi.sh / setup-vm.sh
    │   ├── kiosk.sh / macforge-kiosk.service
    │   └── gen-lab-certs.sh
    │
    └── docs/
        ├── architecture.md         # this file
        ├── DEPLOYMENT.md
        ├── RASPBERRY_PI.md
        └── teap-feasibility.md     # internal engineering reference

## Component Relationships

    Browser (app.js)  ←─ HTTP/JSON polling 2s ─→  FastAPI (web.py)
                                                        │
                                                  Orchestrator
                                                 ┌──────┼──────┐
                                              Engine  dot1x   certgen
                                             (Scapy)         ise_api
                                                            scep_client

## Data Flow
1. Startup: cli.py loads YAML profiles → compute_seed(interface) → remap_profile_macs() → Orchestrator(seed=) → FastAPI on :8080
2. MAB connect: Orchestrator → Scapy DHCP Discover/Request → IP → keepalive loop (ARP + TCP SYN + ICMP)
3. 802.1X connect: Orchestrator → macvlan → wpa_supplicant → auth success → DHCP → keepalive loop
   On failure: destroy_macvlan() → attempt DHCP for MAB fallback detection → amber badge
4. Frontend: app.js polls GET /api/devices every 2s → in-place DOM card updates

## MAC Address Seed
- Seed = SHA-256(host_NIC_MAC + MACFORGE_INSTANCE_ID env var)
- YAML profile MACs remapped at load: OUI preserved, last 3 bytes = HMAC-SHA256(seed, "profile:{OUI}:{name}")
- Runtime MACs (create/clone): HMAC-SHA256(seed, "gen:{OUI}:{counter}:{attempt}")
- Fallback: if NIC MAC unreadable, a random seed is generated and persisted to /app/data/.mac_seed
- Fingerprint (first 8 hex chars) exposed via GET /api/interface → seed_fingerprint

## Keepalive Traffic
- Burst phase (first 8 cycles, 3 s apart): 10 TCP SYN probes + ICMP echo (512 B) ≈ 2.2 KB bidir/cycle
- Steady phase (default 30 s): 4 TCP SYN probes + ICMP echo (256 B) ≈ 1.0 KB bidir/cycle
- TCP SYN targets: public IPs (Google, Microsoft, Akamai, Fastly) on ports 80/443
- TCP chosen because Meraki and similar platforms filter ARP/DHCP/DNS at the control plane

## Persistent Storage (/app/data/)
- auth_config.json — 802.1X profiles keyed by MAC
- custom_devices.json — user-created devices + overrides
- ise_config.json — ISE hostname, credentials, verify_tls
- certs/ — PEM/DER/P12 certificates, keys, CSRs

## Docker Run
    docker run -d --name macforge \
      --network host \
      --privileged \
      --restart unless-stopped \
      --cap-add NET_ADMIN --cap-add NET_RAW \
      -v ./data:/app/data \
      -v ./profiles:/app/profiles:ro \
      macforge --mode web --data-interface eth0

- --network host        → required for L2 Scapy + wpa_supplicant
- --privileged         → required for iptables + macvlan creation
- --data-interface     → switch-facing NIC (EAP/MAB/DHCP frames); auto-detected on two-NIC hosts
- --interface          → management NIC (web UI / keepalive traffic); auto-detected

## Ports
- 8080 → Web UI
- 161/udp → SNMP (when enabled)
- 68/udp → DHCP replies

## Key Architectural Decisions
- wpa_supplicant (not Scapy) for 802.1X — full EAP crypto without reimplementing TLS
- Dual-binary strategy: apt `wpasupplicant` for PEAP/TLS/FAST/TTLS; source-built `wpa_supplicant_teap` for TEAP only (apt package lacks CONFIG_EAP_TEAP)
- macvlan per device — each 802.1X device needs its own L2 identity on the physical port
- Deterministic MAC seed via HMAC-SHA256 — same NIC always produces the same MACs; MACFORGE_INSTANCE_ID differentiates multiple instances on one host
- TCP SYN probes for keepalives — platforms like Meraki filter ARP/DHCP/DNS; TCP is always forwarded through the data plane
- Host networking (not bridge) — required for L2 Scapy packets to reach physical switch
- Vanilla JS (no React/Vue) — no build step, small image, runs on RPi
- Polling not WebSockets — device state changes infrequent enough; 2s is fine
- Two CSS design systems — device cards (--bg-*) + cert page (--st-* Stitch) kept separate intentionally
- In-place DOM updates — prevents card jumping on 2s refresh
- Unified Configure drawer — Device + 802.1X tabs rendered once at open; switchConfigTab() toggles display only
- Deferred re-sort — 3.5s debounce; intermediate states never trigger reorder
- sscep built from source — absent from Debian Bookworm arm64 apt
- wpa_supplicant_teap built from source — apt wpasupplicant lacks CONFIG_EAP_TEAP; OpenSSL 3.x compat handled via crypto_openssl.c lower-level API (do not use CONFIG_INTERNAL_MD4/DES with CONFIG_TLS=openssl — duplicate symbol linker error)
- python:3.12-slim-bookworm pinned — slim moved to trixie silently, broke sscep
- auth_type is metadata only — never read by generate_wpa_conf(); use renderAuthTypeField() for UI
- enroll_scep() and enroll_step_ca() are fully separate code paths — never conflate them

## API Endpoint Reference

### Devices
    GET    /api/devices
    POST   /api/devices
    GET    /api/devices/{mac}
    PUT    /api/devices/{mac}
    DELETE /api/devices/{mac}
    POST   /api/devices/{mac}/connect
    POST   /api/devices/{mac}/disconnect
    POST   /api/devices/{mac}/ping?target=
    POST   /api/devices/{mac}/clone
    POST   /api/devices/connect-all
    POST   /api/devices/disconnect-all

### Auth (802.1X)
    GET    /api/devices/{mac}/auth
    PUT    /api/devices/{mac}/auth
    DELETE /api/devices/{mac}/auth
    GET    /api/devices/{mac}/auth-flow      # parsed EAP state machine events
    GET    /api/devices/{mac}/dot1x-log      # raw wpa_supplicant log lines
    GET    /api/dot1x/readiness             # probe both wpa_supplicant binaries

### Packet Capture
    GET    /api/devices/{mac}/packets
    GET    /api/devices/{mac}/packets/download
    POST   /api/devices/{mac}/capture/start
    POST   /api/devices/{mac}/capture/stop

### Certificates
    GET    /api/certs
    POST   /api/certs/upload
    POST   /api/certs/paste
    DELETE /api/certs/{filename}
    GET    /api/certs/{filename}/download
    GET    /api/certs/{filename}/info

### PKI
    GET    /api/pki/lab-ca
    POST   /api/pki/generate-ca
    POST   /api/pki/generate-client
    POST   /api/pki/generate-csr
    GET    /api/pki/enrollment-capabilities
    POST   /api/pki/test-ndes
    POST   /api/pki/enroll-scep
    POST   /api/pki/enroll-step-ca

### ISE Integration
    GET    /api/ise/config
    PUT    /api/ise/config
    POST   /api/ise/test
    POST   /api/ise/push-ca
    GET    /api/ise/anc-policies
    GET    /api/devices/{mac}/ise-session
    GET    /api/devices/{mac}/ise-endpoint
    GET    /api/devices/{mac}/ise-history
    POST   /api/devices/{mac}/coa           # Change of Authorization (reauth/disconnect/bounce)

### NAD (Network Access Device)
    GET    /api/nad/config
    PUT    /api/nad/config
    POST   /api/devices/{mac}/nad-probe

### System
    GET    /api/logs?limit=200
    GET    /api/settings
    POST   /api/settings
    GET    /api/interface                   # active mgmt interface + seed fingerprint
    GET    /api/interfaces                  # all host NICs
    PUT    /api/interface/data              # change active data/NAD interface at runtime
    GET    /api/vendor-ouis