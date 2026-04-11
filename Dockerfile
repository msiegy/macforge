FROM python:3.12-slim-bookworm

# wpa_supplicant strategy:
#   - apt wpasupplicant (2.10-12+deb12u3): has PEAP/TLS/FAST/TTLS/MSCHAPv2 but NOT TEAP
#   - source build → /usr/local/sbin/wpa_supplicant_teap: has TEAP + all others
#   dot1x.py picks the binary based on EAP method at runtime.
#
# sscep built from source because it was dropped from Debian trixie apt
# and was never in bookworm arm64.
ARG SSCEP_VERSION=0.10.0
# wpa_supplicant 2.10 has a known TEAP Crypto-Binding bug with MSCHAPv2 (ISE error 11577).
# Building from git HEAD picks up post-2.10 TEAP fixes. Pin to a known-good commit
# once TEAP is confirmed working to keep the build reproducible.
ARG WPA_GIT_COMMIT=HEAD

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iptables \
        iproute2 \
        procps \
        tcpdump \
        openssl \
        ca-certificates \
        wpasupplicant \
        gcc \
        make \
        libssl-dev \
        pkg-config \
        wget \
        git \
        autoconf \
        automake \
        libtool \
    \
    # ── sscep (SCEP/NDES enrollment) ────────────────────────────────────────
    && wget -q https://github.com/certnanny/sscep/archive/refs/tags/v${SSCEP_VERSION}.tar.gz \
            -O /tmp/sscep.tar.gz \
    && tar -xzf /tmp/sscep.tar.gz -C /tmp \
    && cd /tmp/sscep-${SSCEP_VERSION} \
    && autoreconf -fi \
    && ./configure \
    && make \
    && make install \
    \
    # ── wpa_supplicant_teap (TEAP RFC 7170 only) ─────────────────────────────
    # apt wpasupplicant works for PEAP/TLS/FAST/TTLS but omits CONFIG_EAP_TEAP.
    # We build a separate binary just for TEAP, installed as wpa_supplicant_teap.
    # Building from git (post-2.10) to pick up TEAP Crypto-Binding fixes for
    # MSCHAPv2 interop with Cisco ISE (error 11577 in wpa_supplicant 2.10).
    && git clone --depth=1 https://w1.fi/hostap.git /tmp/hostap \
    && cd /tmp/hostap/wpa_supplicant \
    && { \
        echo 'CONFIG_DRIVER_WIRED=y'; \
        echo 'CONFIG_IEEE8021X_EAPOL=y'; \
        echo 'CONFIG_TLS=openssl'; \
        echo 'CONFIG_TLSV12=y'; \
        echo 'CONFIG_TLSV13=y'; \
        echo 'CONFIG_EAP_MD5=y'; \
        echo 'CONFIG_EAP_TLS=y'; \
        echo 'CONFIG_EAP_PEAP=y'; \
        echo 'CONFIG_EAP_TTLS=y'; \
        echo 'CONFIG_EAP_FAST=y'; \
        echo 'CONFIG_EAP_TEAP=y'; \
        echo 'CONFIG_EAP_MSCHAPV2=y'; \
        echo 'CONFIG_EAP_GTC=y'; \
        echo 'CONFIG_EAP_OTP=y'; \
        echo 'CONFIG_EAP_LEAP=y'; \
        echo 'CONFIG_PKCS12=y'; \
        echo 'CONFIG_SMARTCARD=y'; \
        echo 'CONFIG_CTRL_IFACE=y'; \
        echo 'CONFIG_CTRL_IFACE_UNIX=y'; \
        echo 'CONFIG_BACKEND=file'; \
        echo 'CONFIG_DEBUG_FILE=y'; \
        echo 'CONFIG_DEBUG_SYSLOG=y'; \
       } > .config \
    && cat .config \
    && make -j$(nproc) \
    && install -m 755 wpa_supplicant /usr/local/sbin/wpa_supplicant_teap \
    && make eapol_test \
    && install -m 755 eapol_test /usr/local/bin/eapol_test \
    \
    # ── clean up build deps and temp files ──────────────────────────────────
    && apt-get purge -y gcc make libssl-dev pkg-config wget git autoconf automake libtool \
    && apt-get autoremove -y \
    && rm -rf /tmp/sscep* /tmp/hostap /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY macforge/ macforge/
COPY profiles/ profiles/

RUN mkdir -p /app/data/certs

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8080

ENTRYPOINT ["/entrypoint.sh"]
CMD ["--mode", "web"]
