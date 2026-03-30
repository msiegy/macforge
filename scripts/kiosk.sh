#!/bin/bash
# MACforge Kiosk Launcher
# Starts X server and Chromium in kiosk mode on the attached display.
# Auto-detects screen resolution and chooses the appropriate UI:
#   - Small screens (width < 800): /touch  (compact touch UI)
#   - Larger screens:              /       (full web UI)
#
# Usage: sudo scripts/kiosk.sh [framebuffer]
#   framebuffer defaults to /dev/fb0, use /dev/fb1 for SPI TFT displays

set -e

FB="${1:-/dev/fb0}"
MACFORGE_URL="http://localhost:8080"

if [ ! -e "$FB" ]; then
  echo "[kiosk] Framebuffer $FB not found. Available:"
  ls /dev/fb* 2>/dev/null || echo "  (none)"
  exit 1
fi

# Read resolution from the framebuffer
read_fb_resolution() {
  local fb_name
  fb_name=$(basename "$FB")
  local w h
  w=$(cat "/sys/class/graphics/${fb_name}/virtual_size" 2>/dev/null | cut -d, -f1)
  h=$(cat "/sys/class/graphics/${fb_name}/virtual_size" 2>/dev/null | cut -d, -f2)
  if [ -n "$w" ] && [ -n "$h" ]; then
    echo "${w}x${h}"
  else
    echo "480x320"
  fi
}

RESOLUTION=$(read_fb_resolution)
WIDTH=$(echo "$RESOLUTION" | cut -dx -f1)
HEIGHT=$(echo "$RESOLUTION" | cut -dx -f2)

echo "[kiosk] Framebuffer: $FB"
echo "[kiosk] Resolution:  ${WIDTH}x${HEIGHT}"

if [ "$WIDTH" -lt 800 ] 2>/dev/null; then
  UI_PATH="/touch"
  echo "[kiosk] Small screen detected -> compact touch UI"
else
  UI_PATH="/"
  echo "[kiosk] Standard screen -> full web UI"
fi

URL="${MACFORGE_URL}${UI_PATH}"
echo "[kiosk] Launching: $URL"

# Ensure xorg.conf.d exists and has our fbdev config
XORG_CONF="/etc/X11/xorg.conf.d/99-macforge-fbdev.conf"
if [ ! -f "$XORG_CONF" ]; then
  mkdir -p /etc/X11/xorg.conf.d
  cat > "$XORG_CONF" << XEOF
Section "Device"
    Identifier "fbdev"
    Driver     "fbdev"
    Option     "fbdev" "$FB"
EndSection
XEOF
  echo "[kiosk] Created $XORG_CONF for $FB"
fi

# Clean up stale X lock files (e.g. after power loss or crash)
if [ -f /tmp/.X0-lock ]; then
  if ! kill -0 "$(cat /tmp/.X0-lock 2>/dev/null)" 2>/dev/null; then
    echo "[kiosk] Removing stale X lock files"
    rm -f /tmp/.X0-lock /tmp/.X11-unix/X0
  fi
fi

# Wait for MACforge to be reachable (up to 30s)
echo -n "[kiosk] Waiting for MACforge API"
for i in $(seq 1 30); do
  if curl -sf "${MACFORGE_URL}/api/interface" > /dev/null 2>&1; then
    echo " ready"
    break
  fi
  echo -n "."
  sleep 1
  if [ "$i" -eq 30 ]; then
    echo " timeout (starting anyway)"
  fi
done

exec xinit /usr/bin/chromium \
  --kiosk \
  --start-fullscreen \
  --no-sandbox \
  --disable-infobars \
  --disable-session-crashed-bubble \
  --noerrdialogs \
  --disable-translate \
  --disable-features=TranslateUI \
  --disable-gpu \
  --enable-touch-events \
  --window-position=0,0 \
  "$URL" \
  -- :0 -nocursor
