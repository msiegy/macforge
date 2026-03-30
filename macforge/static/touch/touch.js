const POLL_MS = 2000;
const DRAG_THRESHOLD = 8;
let devices = [];
let expandedMac = null;
let pingResults = {};

async function api(url, opts = {}) {
  const res = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  if (!res.ok) throw new Error(res.statusText);
  return res.json();
}

function esc(str) {
  const d = document.createElement("div");
  d.textContent = str;
  return d.innerHTML;
}

function macDash(mac) {
  return mac.replace(/:/g, "-");
}

function renderCounts() {
  const online = devices.filter((d) => d.state === "online").length;
  const el = document.getElementById("statusCounts");
  el.textContent = online + "/" + devices.length + " Online";
}

function renderList() {
  const list = document.getElementById("deviceList");
  const scrollTop = list.scrollTop;

  let html = "";
  for (const dev of devices) {
    const md = macDash(dev.mac);
    const isExp = expandedMac === dev.mac;
    const ip = dev.assigned_ip || "--";
    const canPing = dev.state === "online" && dev.assigned_ip;
    const canConnect = dev.state === "stopped" || dev.state === "auth_failed";
    const canDisconnect = ["online", "connecting", "authenticating", "authorized", "auth_failed"].indexOf(dev.state) >= 0;

    html += '<div class="device-row' + (isExp ? " expanded" : "") + '" data-mac="' + esc(dev.mac) + '">';
    html += '<span class="dot ' + esc(dev.state) + '"></span>';
    html += '<span class="dev-name">' + esc(dev.name) + '</span>';
    if (dev.auth_method) {
      html += '<span class="auth-tag">' + esc(dev.auth_method.split("-")[0].toUpperCase()) + '</span>';
    }
    html += '<span class="dev-ip">' + esc(ip) + '</span>';
    html += '<span class="dev-chevron">' + (isExp ? "\u25BC" : "\u25B6") + '</span>';
    html += '</div>';

    if (isExp) {
      html += '<div class="expand-panel">';
      if (canConnect) {
        html += '<button class="exp-btn act-connect" data-action="connect" data-md="' + esc(md) + '">Connect</button>';
      }
      if (canDisconnect) {
        html += '<button class="exp-btn act-disconnect" data-action="disconnect" data-md="' + esc(md) + '">Disconnect</button>';
      }
      if (canPing) {
        html += '<button class="exp-btn act-ping" data-action="ping" data-md="' + esc(md) + '">Ping GW</button>';
      }

      const pr = pingResults[dev.mac];
      if (pr) {
        html += '<span class="ping-inline ' + pr.cls + '">' + esc(pr.text) + '</span>';
      }

      if (dev.status_detail) {
        html += '<span class="detail-text">' + esc(dev.status_detail) + '</span>';
      }
      html += '</div>';
    }
  }

  list.innerHTML = html;
  list.scrollTop = scrollTop;
}

function renderTicker() {
  api("/api/logs?limit=1").then((logs) => {
    const el = document.querySelector(".ticker-text");
    if (logs.length === 0) {
      el.textContent = "--";
      return;
    }
    const e = logs[0];
    const t = new Date(e.timestamp * 1000).toLocaleTimeString("en-US", { hour12: false });
    el.textContent = t + "  " + e.device_name + "  " + e.packet_type + "  " + e.detail;
  }).catch(() => {});
}

function toggleExpand(mac) {
  expandedMac = expandedMac === mac ? null : mac;
  renderList();
}

async function doConnect(md) {
  try {
    await api("/api/devices/" + md + "/connect", { method: "POST" });
  } catch (_) {}
  refresh();
}

async function doDisconnect(md) {
  try {
    await api("/api/devices/" + md + "/disconnect", { method: "POST" });
  } catch (_) {}
  refresh();
}

async function doPing(md) {
  const mac = md.replace(/-/g, ":");
  pingResults[mac] = { text: "...", cls: "pending" };
  renderList();
  try {
    const r = await api("/api/devices/" + md + "/ping?count=2", { method: "POST" });
    const rtts = (r.rtts || []).filter((v) => v !== null);
    if (r.error) {
      pingResults[mac] = { text: r.error, cls: "fail" };
    } else if (rtts.length > 0) {
      const avg = (rtts.reduce((a, b) => a + b, 0) / rtts.length).toFixed(1);
      pingResults[mac] = { text: avg + "ms " + rtts.length + "/" + r.rtts.length, cls: "" };
    } else {
      pingResults[mac] = { text: "timeout", cls: "fail" };
    }
  } catch (_) {
    pingResults[mac] = { text: "error", cls: "fail" };
  }
  renderList();
}

async function connectAll() {
  try { await api("/api/devices/connect-all", { method: "POST" }); } catch (_) {}
  refresh();
}

async function disconnectAll() {
  try { await api("/api/devices/disconnect-all", { method: "POST" }); } catch (_) {}
  refresh();
}

async function toggleSNMP() {
  const enabled = document.getElementById("snmpToggle").checked;
  try {
    await api("/api/settings", { method: "POST", body: JSON.stringify({ snmp_enabled: enabled }) });
  } catch (_) {
    document.getElementById("snmpToggle").checked = !enabled;
  }
}

async function loadSettings() {
  try {
    const s = await api("/api/settings");
    document.getElementById("snmpToggle").checked = s.snmp_enabled;
  } catch (_) {}
}

async function loadInterface() {
  try {
    const d = await api("/api/interface");
    document.getElementById("ifaceBadge").textContent = d.interface;
  } catch (_) {}
}

async function refresh() {
  try {
    devices = await api("/api/devices");
    renderCounts();
    renderList();
    renderTicker();
  } catch (_) {}
}

/* ---------- Drag-to-scroll with momentum ---------- */
(function initDragScroll() {
  const list = document.getElementById("deviceList");
  let dragging = false;
  let startY = 0;
  let startScroll = 0;
  let totalDelta = 0;
  let lastY = 0;
  let lastTime = 0;
  let velocity = 0;
  let momentumId = null;

  function pointerY(e) {
    if (e.touches && e.touches.length) return e.touches[0].clientY;
    return e.clientY;
  }

  function onDown(e) {
    if (momentumId) { cancelAnimationFrame(momentumId); momentumId = null; }
    dragging = true;
    startY = pointerY(e);
    lastY = startY;
    startScroll = list.scrollTop;
    totalDelta = 0;
    velocity = 0;
    lastTime = Date.now();
  }

  function onMove(e) {
    if (!dragging) return;
    var y = pointerY(e);
    var dy = startY - y;
    totalDelta = Math.abs(dy);
    list.scrollTop = startScroll + dy;

    var now = Date.now();
    var dt = now - lastTime;
    if (dt > 0) {
      velocity = (lastY - y) / dt;
    }
    lastY = y;
    lastTime = now;

    if (totalDelta > DRAG_THRESHOLD) {
      e.preventDefault();
    }
  }

  function onUp(e) {
    if (!dragging) return;
    dragging = false;

    if (totalDelta <= DRAG_THRESHOLD) {
      handleTap(e);
      return;
    }

    startMomentum();
  }

  function startMomentum() {
    var friction = 0.95;
    var v = velocity * 16;

    function step() {
      if (Math.abs(v) < 0.5) return;
      list.scrollTop += v;
      v *= friction;
      momentumId = requestAnimationFrame(step);
    }
    momentumId = requestAnimationFrame(step);
  }

  function handleTap(e) {
    var target = e.target || (e.changedTouches && e.changedTouches[0] && document.elementFromPoint(
      e.changedTouches[0].clientX, e.changedTouches[0].clientY));
    if (!target) return;

    var btn = target.closest(".exp-btn");
    if (btn) {
      var action = btn.getAttribute("data-action");
      var md = btn.getAttribute("data-md");
      if (action === "connect") doConnect(md);
      else if (action === "disconnect") doDisconnect(md);
      else if (action === "ping") doPing(md);
      return;
    }

    var row = target.closest(".device-row");
    if (row) {
      var mac = row.getAttribute("data-mac");
      if (mac) toggleExpand(mac);
    }
  }

  list.addEventListener("mousedown", onDown);
  list.addEventListener("mousemove", onMove);
  list.addEventListener("mouseup", onUp);
  list.addEventListener("mouseleave", function() { dragging = false; });

  list.addEventListener("touchstart", onDown, { passive: true });
  list.addEventListener("touchmove", onMove, { passive: false });
  list.addEventListener("touchend", onUp);
})();

document.getElementById("connectAllBtn").addEventListener("click", connectAll);
document.getElementById("disconnectAllBtn").addEventListener("click", disconnectAll);
document.getElementById("snmpToggle").addEventListener("change", toggleSNMP);

loadInterface();
loadSettings();
refresh();
setInterval(refresh, POLL_MS);
