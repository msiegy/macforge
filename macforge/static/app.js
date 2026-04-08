const API = "";
const POLL_INTERVAL = 2000;

let devices = [];
let logs = [];
let configMac = null;
let configMode = null;
let configSection = "mab";
let configActiveTab = "device";
let configAuthDirty = false;
let configIsReadOnly = false;
let configLoadedAuth = null;
let certCache = [];
let drawerEnrollCaps = null;
let drawerLabCaExists = false;
let activeTab = "devices";
let refreshInFlight = false;
let previousStates = {};
let pendingPings = new Set();   // macDash values with optimistic spinner before first server response
let pingTimestamps = {};         // macDash -> epoch ms when last result arrived

// Device detail panel state
let detailMac = null;                   // MAC of the currently-open device detail panel
let detailActiveTab = "auth-flow";      // which tab is visible in the detail panel
let detailRefreshInFlight = false;      // prevents concurrent detail polls
let detailPollTimer = null;             // setInterval handle for faster detail polling
let detailCaptureActive = false;        // Packets tab capture toggle
let detailAuthFlowRendered = false;     // true once auth flow is rendered in terminal state

let iseConfigured = false;              // true when ISE hostname has been saved


const FETCH_TIMEOUT_MS = 6000;  // abort fetch if server doesn't respond in 6s
const FETCH_TIMEOUT_SLOW_MS = 30000;  // for slow endpoints (readiness probes ~10s)

async function fetchJSONWithTimeout(url, opts = {}, timeoutMs = FETCH_TIMEOUT_MS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(API + url, {
      headers: { "Content-Type": "application/json" },
      signal: controller.signal,
      ...opts,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || res.statusText);
    }
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}

async function fetchJSON(url, opts = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(API + url, {
      headers: { "Content-Type": "application/json" },
      signal: controller.signal,
      ...opts,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || res.statusText);
    }
    return res.json();
  } finally {
    clearTimeout(timer);
  }
}

function formatTime(ts) {
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString("en-US", { hour12: false });
}

function formatUptime(sec) {
  if (sec <= 0) return "--";
  const m = Math.floor(sec / 60);
  const s = Math.floor(sec % 60);
  if (m === 0) return `${s}s`;
  return `${m}m ${s}s`;
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

/* ─── Toast Notifications ────────────────────────────────────────── */

function showToast(message, type = "info", duration = 4000) {
  const container = document.getElementById("toastContainer");
  if (!container) return;
  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  toast.style.whiteSpace = "pre-wrap";
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => toast.remove(), duration);
}

/* ─── SVG Eye Icon HTML ──────────────────────────────────────────── */

const EYE_ICON_SVG = '<svg class="eye-icon" viewBox="0 0 24 24"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';

/* ─── Tab Switching ───────────────────────────────────────────────── */

function switchTab(tabName) {
  activeTab = tabName;
  document.querySelectorAll(".tab").forEach((t) => {
    t.classList.toggle("active", t.dataset.tab === tabName);
  });
  document.querySelectorAll(".tab-pane").forEach((p) => {
    p.classList.toggle("active", p.id === `pane-${tabName}`);
  });
  if (tabName === "certs") {
    refreshCertTable();
    refreshLabCaStatus();
    loadISEConfig();
    loadEnrollmentCaps();
  }
}

document.querySelectorAll(".tab").forEach((t) => {
  t.addEventListener("click", () => switchTab(t.dataset.tab));
});

/* ─── Tab Counts ──────────────────────────────────────────────────── */

function updateTabCounts() {
  const dot1xDevs = devices.filter((d) => d.auth_method);
  const mabDevs = devices.filter((d) => !d.auth_method);

  document.getElementById("tabDeviceCount").textContent = devices.length;
  document.getElementById("tabLogCount").textContent = logs.length;
  document.getElementById("dot1xCount").textContent = dot1xDevs.length;
  document.getElementById("mabCount").textContent = mabDevs.length;
  const certCountEl = document.getElementById("tabCertCount");
  if (certCountEl) certCountEl.textContent = certCache.length;
}

/* ─── Ping Result ─────────────────────────────────────────────────── */

function pingElapsedLabel(macDash) {
  const ts = pingTimestamps[macDash];
  if (!ts) return "";
  const sec = Math.round((Date.now() - ts) / 1000);
  if (sec < 2) return "just now";
  if (sec < 60) return `${sec}s ago`;
  return `${Math.round(sec / 60)}m ago`;
}

function renderPingResult(dev) {
  const macDash = dev.mac.replace(/:/g, "-");
  const p = dev.last_ping;

  // Use server-side pending flag as the authoritative spinner trigger.
  // pendingPings provides an optimistic spinner before the first poll response.
  if ((p && p.pending) || pendingPings.has(macDash)) {
    const target = (p && p.target) || "target";
    return `<div class="ping-result ping-running">
      <span class="ping-spinner"></span> Pinging ${escapeHtml(target)}…
    </div>`;
  }

  if (!p) return "";

  // Record completion time for age display (once per result)
  if (!pingTimestamps[macDash + "_done"]) {
    pingTimestamps[macDash] = Date.now();
    pingTimestamps[macDash + "_done"] = true;
  }

  const age = pingElapsedLabel(macDash);
  const ageHtml = age ? ` <span class="ping-age">${age}</span>` : "";
  if (p.error) {
    return `<div class="ping-result ping-fail">${escapeHtml(p.error)}${ageHtml}</div>`;
  }
  const rtts = p.rtts || [];
  const ok = rtts.filter((r) => r !== null);
  const spans = rtts
    .map((r) =>
      r !== null
        ? `<span class="rtt-ok">${r}</span>`
        : `<span class="rtt-fail">*</span>`
    )
    .join(" ");
  const cssClass = ok.length > 0 ? "ping-ok" : "ping-fail";
  const avg = ok.length ? (ok.reduce((a, b) => a + b, 0) / ok.length).toFixed(1) : "--";
  return `<div class="ping-result ${cssClass}">${escapeHtml(p.target)}: ${spans} ms&nbsp; avg ${avg}ms&nbsp; ${ok.length}/${rtts.length}${ageHtml}</div>`;
}

/* ─── Device Card ─────────────────────────────────────────────────── */

function authBadgeHtml(dev) {
  if (!dev.auth_method) return "";
  const label = dev.auth_method.toUpperCase().replace("-", " ");
  let html = `<span class="auth-badge">${escapeHtml(label)}</span>`;
  if (dev.auth_state === "dot1x_failed_open") {
    html += `<span class="auth-badge failed">FAILED</span>`;
  }
  return html;
}

function renderDeviceCard(dev) {
  const stateClass = dev.state;
  const canConnect = dev.state === "stopped" || dev.state === "auth_failed";
  const canDisconnect = ["online", "connecting", "authenticating", "authorized", "auth_failed"].includes(dev.state);
  const canPing = dev.state === "online" && dev.assigned_ip;
  const macDash = dev.mac.replace(/:/g, "-");
  const isDot1x = !!dev.auth_method;

  const deleteBtn = dev.is_custom
    ? `<button class="btn-icon delete-btn" onclick="deleteDevice('${escapeHtml(macDash)}')" title="Delete device">&times;</button>`
    : "";

  const identityLine = (isDot1x && dev.auth_identity)
    ? `<div class="card-identity">${escapeHtml(dev.auth_identity)}</div>`
    : "";

  const errorLine = (dev.state === "auth_failed" && dev.error_message)
    ? `<div class="card-error-msg" title="${escapeHtml(dev.error_message)}">&#9888; ${escapeHtml(dev.error_message.length > 80 ? dev.error_message.slice(0, 80) + "…" : dev.error_message)}</div>`
    : "";

  return `
    <div class="device-card state-${stateClass}" data-mac="${escapeHtml(dev.mac)}">
      <div class="card-top">
        <div>
          <div class="device-name">${escapeHtml(dev.name)}${authBadgeHtml(dev)}</div>
          ${identityLine}
          ${errorLine}
          <span class="category-tag ${escapeHtml(dev.personality.category)}">${escapeHtml(dev.personality.category)}</span>
        </div>
        <div class="state-indicator">
          <span class="state-dot ${stateClass}"></span>
          ${escapeHtml(dev.state)}${dev.status_detail ? `<span class="status-detail">${escapeHtml(dev.status_detail)}</span>` : ""}
        </div>
      </div>
      <div class="card-details">
        <span class="detail-label">MAC</span>
        <span class="detail-value">${escapeHtml(dev.mac)}</span>
        <span class="detail-label">OS</span>
        <span class="detail-value">${escapeHtml(dev.personality.os || "--")}</span>
        <span class="detail-label">Hostname</span>
        <span class="detail-value">${escapeHtml(dev.dhcp.hostname || "--")}</span>
        <span class="detail-label">Class-ID</span>
        <span class="detail-value">${escapeHtml(dev.dhcp.vendor_class || "--")}</span>
        <span class="detail-label">IP</span>
        <span class="detail-value">${escapeHtml(dev.assigned_ip || "--")}</span>
        <span class="detail-label">Gateway</span>
        <span class="detail-value">${escapeHtml(dev.gateway_ip || "--")}</span>
        <span class="detail-label">Uptime</span>
        <span class="detail-value">${formatUptime(dev.uptime_sec)}</span>
        <span class="detail-label">Packets</span>
        <span class="detail-value">${dev.packets_sent}</span>
      </div>
      ${renderPingResult(dev)}
      <div class="card-actions">
        <button class="btn-card connect" ${canConnect ? "" : "disabled"}
                onclick="connectDevice('${escapeHtml(macDash)}')">Connect</button>
        <button class="btn-card disconnect" ${canDisconnect ? "" : "disabled"}
                onclick="disconnectDevice('${escapeHtml(macDash)}')">Disconnect</button>
      </div>
      <div class="card-toolbar">
        <button class="btn-icon detail-btn" onclick="openDeviceDetail('${escapeHtml(macDash)}')" title="Device detail &amp; diagnostics">&#9432;</button>
        <button class="btn-icon configure-btn" onclick="openConfigDrawer('${escapeHtml(macDash)}', null)" title="Configure device">&#9881;</button>
        <button class="btn-icon clone-btn" onclick="cloneDevice('${escapeHtml(macDash)}')" title="Clone device">&#10697;</button>
        ${deleteBtn}
      </div>
      <div class="ping-row" ${canPing ? "" : 'style="opacity:0.3;pointer-events:none"'}>
        <input type="text" class="ping-input" id="ping-target-${escapeHtml(macDash)}"
               placeholder="target (default: gateway)" value=""
               title="Leave blank for gateway, or enter IP like 8.8.8.8">
        <button class="btn-card ping" onclick="pingDevice('${escapeHtml(macDash)}')">Ping</button>
      </div>
    </div>
  `;
}

/* ─── Grouped Device Rendering ────────────────────────────────────── */

function preservePingState(containerEl) {
  const state = { focusedId: null, values: {} };
  const focused = document.activeElement;
  if (focused && focused.classList.contains("ping-input")) {
    state.focusedId = focused.id;
  }
  containerEl.querySelectorAll(".ping-input").forEach((el) => {
    if (el.id) state.values[el.id] = el.value;
  });
  return state;
}

function restorePingState(containerEl, state) {
  Object.keys(state.values).forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.value = state.values[id];
  });
  if (state.focusedId) {
    const el = document.getElementById(state.focusedId);
    if (el) el.focus();
  }
}

function getGridMacs(gridEl) {
  return Array.from(gridEl.querySelectorAll(".device-card"))
    .map((c) => c.dataset.mac);
}

function updateCardInPlace(dev) {
  const card = document.querySelector(`.device-card[data-mac="${dev.mac}"]`);
  if (!card) return false;

  const stateClass = dev.state;
  const canConnect = dev.state === "stopped" || dev.state === "auth_failed";
  const canDisconnect = ["online", "connecting", "authenticating", "authorized", "auth_failed"].includes(dev.state);
  const canPing = dev.state === "online" && dev.assigned_ip;
  const isStopped = dev.state === "stopped" || dev.state === "auth_failed";

  card.className = `device-card state-${stateClass}`;

  const nameEl = card.querySelector(".device-name");
  if (nameEl) nameEl.innerHTML = `${escapeHtml(dev.name)}${authBadgeHtml(dev)}`;

  // Update error message line (auth_failed state)
  let errorEl = card.querySelector(".card-error-msg");
  if (dev.state === "auth_failed" && dev.error_message) {
    const msg = dev.error_message.length > 80 ? dev.error_message.slice(0, 80) + "\u2026" : dev.error_message;
    const errorHtml = `<div class="card-error-msg" title="${escapeHtml(dev.error_message)}">&#9888; ${escapeHtml(msg)}</div>`;
    if (errorEl) {
      errorEl.outerHTML = errorHtml;
    } else if (nameEl) {
      nameEl.insertAdjacentHTML("afterend", errorHtml);
    }
  } else if (errorEl) {
    errorEl.remove();
  }

  // Update identity sub-line
  const isDot1x = !!dev.auth_method;
  let identityEl = card.querySelector(".card-identity");
  if (isDot1x && dev.auth_identity) {
    if (identityEl) {
      identityEl.textContent = dev.auth_identity;
    } else if (nameEl) {
      nameEl.insertAdjacentHTML("afterend", `<div class="card-identity">${escapeHtml(dev.auth_identity)}</div>`);
    }
  } else if (identityEl) {
    identityEl.remove();
  }

  const stateInd = card.querySelector(".state-indicator");
  if (stateInd) {
    stateInd.innerHTML = `<span class="state-dot ${stateClass}"></span>
      ${escapeHtml(dev.state)}${dev.status_detail ? `<span class="status-detail">${escapeHtml(dev.status_detail)}</span>` : ""}`;
  }

  const vals = card.querySelectorAll(".detail-value");
  if (vals.length >= 8) {
    vals[0].textContent = dev.mac;
    vals[1].textContent = dev.personality.os || "--";
    vals[2].textContent = dev.dhcp.hostname || "--";
    vals[3].textContent = dev.dhcp.vendor_class || "--";
    vals[4].textContent = dev.assigned_ip || "--";
    vals[5].textContent = dev.gateway_ip || "--";
    vals[6].textContent = formatUptime(dev.uptime_sec);
    vals[7].textContent = dev.packets_sent;
  }

  const pingResultEl = card.querySelector(".ping-result");
  const newPingHtml = renderPingResult(dev);
  if (pingResultEl && !newPingHtml) {
    pingResultEl.remove();
  } else if (newPingHtml) {
    if (pingResultEl) {
      pingResultEl.outerHTML = newPingHtml;
    } else {
      const details = card.querySelector(".card-details");
      if (details) details.insertAdjacentHTML("afterend", newPingHtml);
    }
  }

  const connectBtn = card.querySelector(".btn-card.connect");
  const disconnectBtn = card.querySelector(".btn-card.disconnect");
  if (connectBtn) connectBtn.disabled = !canConnect;
  if (disconnectBtn) disconnectBtn.disabled = !canDisconnect;

  const pingRow = card.querySelector(".ping-row");
  if (pingRow) {
    pingRow.style.opacity = canPing ? "" : "0.3";
    pingRow.style.pointerEvents = canPing ? "" : "none";
  }

  const prevState = previousStates[dev.mac];
  if (prevState && prevState !== dev.state) {
    card.classList.add("state-changed");
    setTimeout(() => card.classList.remove("state-changed"), 1200);
    // Show a richer toast for TEAP auth failures to surface common root causes
    if (dev.state === "auth_failed" && dev.auth_method === "teap") {
      showToast(
        `TEAP auth failed \u2014 check: ISE 3.1+ policy, wpa_supplicant \u2265 2.10, ` +
        `CA cert validation, and Compound Condition rule for chained auth.`,
        "error"
      );
    }
  }
  previousStates[dev.mac] = dev.state;

  return true;
}

function fullRenderGrid(gridEl, devList, emptyMsg) {
  const pingState = preservePingState(gridEl);
  if (devList.length === 0) {
    gridEl.innerHTML = `<div class="empty-section">${emptyMsg}</div>`;
  } else {
    gridEl.innerHTML = devList.map(renderDeviceCard).join("");
  }
  restorePingState(gridEl, pingState);
  devList.forEach((d) => { previousStates[d.mac] = d.state; });
}

function renderDevices() {
  const dot1xDevs = devices.filter((d) => d.auth_method);
  const mabDevs = devices.filter((d) => !d.auth_method);

  const dot1xGrid = document.getElementById("dot1xGrid");
  const mabGrid = document.getElementById("mabGrid");

  const dot1xMacs = new Set(dot1xDevs.map((d) => d.mac));
  const mabMacs = new Set(mabDevs.map((d) => d.mac));
  const existingDot1x = new Set(getGridMacs(dot1xGrid));
  const existingMab = new Set(getGridMacs(mabGrid));

  const setsEqual = (a, b) => a.size === b.size && [...a].every((v) => b.has(v));
  const structureChanged = !setsEqual(dot1xMacs, existingDot1x) || !setsEqual(mabMacs, existingMab);

  if (structureChanged) {
    // Device added or removed — rebuild grids in server order (no sorting)
    fullRenderGrid(dot1xGrid, dot1xDevs,
      'No 802.1X endpoints configured. Click <strong>+ New</strong> or use the <strong>&#9881;</strong> button on any device.');
    fullRenderGrid(mabGrid, mabDevs,
      'No MAB endpoints loaded. Click <strong>+ New</strong> to create one.');
  } else {
    // Same set of devices — update cards in-place (no DOM rebuild, no flicker)
    dot1xDevs.forEach(updateCardInPlace);
    mabDevs.forEach(updateCardInPlace);
  }

  updateTabCounts();
}

/* ─── Log Rendering ───────────────────────────────────────────────── */

function renderLogEntry(entry) {
  const typeClass = entry.packet_type.toLowerCase().split(" ")[0];
  return `
    <div class="log-entry">
      <span class="log-time">${formatTime(entry.timestamp)}</span>
      <span class="log-device">${escapeHtml(entry.device_name)}</span>
      <span class="log-type ${typeClass}">${escapeHtml(entry.packet_type)}</span>
      <span class="log-detail">${escapeHtml(entry.detail)}</span>
    </div>
  `;
}

function renderLogs() {
  const container = document.getElementById("logEntries");
  const countEl = document.getElementById("logCount");
  if (logs.length === 0) {
    container.innerHTML = '<div class="empty-state">No packets sent yet</div>';
    countEl.textContent = "0 entries";
  } else {
    container.innerHTML = logs.map(renderLogEntry).join("");
    countEl.textContent = `${logs.length} entries`;
  }
  updateTabCounts();
}

/* ─── Data Refresh ────────────────────────────────────────────────── */

async function refreshAll() {
  if (refreshInFlight) return;
  refreshInFlight = true;
  try {
    const [devData, logData] = await Promise.all([
      fetchJSON("/api/devices"),
      fetchJSON("/api/logs?limit=100"),
    ]);
    devices = devData;
    logs = logData;
    renderDevices();
    renderLogs();
    tickPingAges();
  } catch (err) {
    console.error("Refresh failed:", err.message);
  } finally {
    refreshInFlight = false;
  }
}

function tickPingAges() {
  // Update elapsed-time labels on existing ping result divs without re-rendering the whole card
  document.querySelectorAll(".ping-result:not(.ping-running)").forEach((el) => {
    const card = el.closest(".device-card");
    if (!card) return;
    const mac = card.dataset.mac;
    const macDash = mac ? mac.replace(/:/g, "-") : null;
    if (!macDash || !pingTimestamps[macDash]) return;
    // Auto-clear results older than 90 seconds
    if (Date.now() - pingTimestamps[macDash] > 90_000) {
      el.remove();
      return;
    }
    const ageEl = el.querySelector(".ping-age");
    const label = pingElapsedLabel(macDash);
    if (ageEl) {
      ageEl.textContent = label;
    } else if (label) {
      el.insertAdjacentHTML("beforeend", ` <span class="ping-age">${label}</span>`);
    }
  });
}

/* ─── Device Actions ──────────────────────────────────────────────── */

async function connectDevice(macDash) {
  // Server sets the transitional state synchronously before returning 200,
  // so refreshAll() after the POST immediately shows authenticating/connecting.
  // No need for an optimistic local flip — just kick off the POST and refresh.
  const mac = macDash.replace(/-/g, ":");
  const dev = devices.find((d) => d.mac === mac);
  // Brief optimistic flip only for immediate visual feedback while POST is in-flight
  if (dev) { dev.state = dev.auth_method ? "authenticating" : "connecting"; renderDevices(); }
  try {
    await fetchJSON(`/api/devices/${macDash}/connect`, { method: "POST" });
    await refreshAll();
  } catch (err) {
    // Revert optimistic state on failure
    if (dev) { dev.state = "stopped"; renderDevices(); }
    showToast("Connect failed: " + err.message, "error");
  }
}

async function disconnectDevice(macDash) {
  try {
    await fetchJSON(`/api/devices/${macDash}/disconnect`, { method: "POST" });
    await refreshAll();
  } catch (err) {
    showToast("Disconnect failed: " + err.message, "error");
    console.error("Disconnect failed:", err);
  }
}

async function pingDevice(macDash) {
  const input = document.getElementById(`ping-target-${macDash}`);
  const target = input ? input.value.trim() : "";
  const query = target ? `?target=${encodeURIComponent(target)}` : "";
  const mac = macDash.replace(/-/g, ":");

  // Optimistic local spinner until first server poll comes back
  pendingPings.add(macDash);
  const pingBtn = document.querySelector(`.device-card[data-mac="${mac}"] .btn-card.ping`);
  if (pingBtn) { pingBtn.disabled = true; pingBtn.textContent = "…"; }
  // Immediately show spinner in card without waiting for poll
  const dev = devices.find((d) => d.mac === mac);
  if (dev) {
    const card = document.querySelector(`.device-card[data-mac="${mac}"]`);
    if (card) {
      const spinnerHtml = `<div class="ping-result ping-running"><span class="ping-spinner"></span> Pinging ${escapeHtml(target || dev.gateway_ip || "target")}…</div>`;
      const resultEl = card.querySelector(".ping-result");
      if (resultEl) resultEl.outerHTML = spinnerHtml;
      else card.querySelector(".card-details")?.insertAdjacentHTML("afterend", spinnerHtml);
    }
  }

  try {
    // POST returns immediately (fire-and-forget on server)
    await fetchJSON(`/api/devices/${macDash}/ping${query}`, { method: "POST" });
  } catch (err) {
    console.error("Ping failed:", err);
  } finally {
    pendingPings.delete(macDash);
    if (pingBtn) { pingBtn.disabled = false; pingBtn.textContent = "Ping"; }
    // Clear _done marker so next ping records a fresh timestamp
    delete pingTimestamps[macDash + "_done"];
    await refreshAll();
  }
}

async function connectAll() {
  const stopped = devices.filter((d) => ["stopped","auth_failed"].includes(d.state));
  if (!stopped.length) { showToast("No devices to connect", "info"); return; }
  if (!confirm(`Connect all ${stopped.length} stopped device${stopped.length > 1 ? "s" : ""}?`)) return;
  try {
    await fetchJSON("/api/devices/connect-all", { method: "POST" });
    await refreshAll();
  } catch (err) {
    showToast("Connect all failed: " + err.message, "error");
  }
}

async function disconnectAll() {
  const active = devices.filter((d) => !["stopped"].includes(d.state));
  if (!active.length) { showToast("No devices to disconnect", "info"); return; }
  if (!confirm(`Disconnect all ${active.length} active device${active.length > 1 ? "s" : ""}?`)) return;
  try {
    await fetchJSON("/api/devices/disconnect-all", { method: "POST" });
    await refreshAll();
  } catch (err) {
    showToast("Disconnect all failed: " + err.message, "error");
  }
}

/* ─── Section Connect / Disconnect ────────────────────────────────── */

async function connectSection(section) {
  const group = section === "dot1x"
    ? devices.filter((d) => d.auth_method)
    : devices.filter((d) => !d.auth_method);
  const toConnect = group.filter((d) => ["stopped","auth_failed"].includes(d.state));
  if (!toConnect.length) { showToast("No devices to connect", "info"); return; }
  const label = section === "dot1x" ? "802.1X" : "MAB";
  if (!confirm(`Connect all ${toConnect.length} stopped ${label} device${toConnect.length > 1 ? "s" : ""}?`)) return;
  for (const dev of toConnect) {
    const macDash = dev.mac.replace(/:/g, "-");
    try {
      await fetchJSON(`/api/devices/${macDash}/connect`, { method: "POST" });
    } catch (_) {}
  }
  await refreshAll();
}

async function disconnectSection(section) {
  const group = section === "dot1x"
    ? devices.filter((d) => d.auth_method)
    : devices.filter((d) => !d.auth_method);
  const activeStates = ["online", "connecting", "authenticating", "authorized", "auth_failed"];
  const toDisconnect = group.filter((d) => activeStates.includes(d.state));
  if (!toDisconnect.length) { showToast("No devices to disconnect", "info"); return; }
  const label = section === "dot1x" ? "802.1X" : "MAB";
  if (!confirm(`Disconnect all ${toDisconnect.length} active ${label} device${toDisconnect.length > 1 ? "s" : ""}?`)) return;
  for (const dev of toDisconnect) {
    const macDash = dev.mac.replace(/:/g, "-");
    try {
      await fetchJSON(`/api/devices/${macDash}/disconnect`, { method: "POST" });
    } catch (_) {}
  }
  await refreshAll();
}

/* ─── Clone Device ────────────────────────────────────────────────── */

async function cloneDevice(macDash) {
  try {
    const cloned = await fetchJSON(`/api/devices/${macDash}/clone`, { method: "POST" });
    closeConfigDrawer();
    await refreshAll();
    const newMacDash = cloned.mac.replace(/:/g, "-");
    openEditDrawer(newMacDash);
  } catch (err) {
    showToast("Clone failed: " + err.message, "error");
  }
}

/* ─── Delete Device ───────────────────────────────────────────────── */

async function deleteDevice(macDash) {
  const mac = macDash.replace(/-/g, ":");
  const dev = devices.find((d) => d.mac === mac);
  const name = dev ? dev.name : mac;
  if (!confirm(`Delete "${name}"?\nThis cannot be undone.`)) return;
  try {
    await fetchJSON(`/api/devices/${macDash}`, { method: "DELETE" });
    await refreshAll();
  } catch (err) {
    showToast("Delete failed: " + err.message, "error");
  }
}

/* ─── Edit / Create Device Drawer ─────────────────────────────────── */

const CATEGORIES = [
  "laptop", "desktop", "workstation", "smartphone", "tablet",
  "server", "printer", "iot", "gaming", "medical", "industrial",
];

let vendorOuiTable = {};

async function loadVendorOuis() {
  try {
    vendorOuiTable = await fetchJSON("/api/vendor-ouis");
  } catch (_) {
    vendorOuiTable = {};
  }
}

function getVendorsForCategory(cat) {
  return vendorOuiTable[cat] || [];
}

function renderVendorOptions(cat, selectedOui) {
  const vendors = getVendorsForCategory(cat);
  if (vendors.length === 0) return '<option value="">No vendors for this category</option>';
  let html = '<option value="">Random from category</option>';
  vendors.forEach((v) => {
    const sel = v.oui === selectedOui ? "selected" : "";
    html += `<option value="${escapeHtml(v.oui)}" ${sel}>${escapeHtml(v.vendor)} (${escapeHtml(v.oui)})</option>`;
  });
  return html;
}

function updateMacPreview() {
  const preview = document.getElementById("macOuiPreview");
  const macInput = document.getElementById("editMac");
  if (!preview || !macInput) return;
  if (configMode === "edit") {
    preview.textContent = "";
    return;
  }
  if (macInput.value.trim()) {
    preview.textContent = "Using custom MAC";
    preview.className = "mac-preview";
    return;
  }
  const vendorSel = document.getElementById("editVendor");
  const catSel = document.getElementById("editCategory");
  if (vendorSel && vendorSel.value) {
    preview.textContent = `Will generate: ${vendorSel.value}:XX:XX:XX`;
    preview.className = "mac-preview mac-preview-oui";
  } else if (catSel && catSel.value && getVendorsForCategory(catSel.value).length > 0) {
    preview.textContent = "Will pick random vendor OUI from category";
    preview.className = "mac-preview";
  } else {
    preview.textContent = "Select a category to auto-generate a realistic MAC";
    preview.className = "mac-preview mac-preview-warn";
  }
}

/* ─── Unified Configure Drawer ────────────────────────────────────── */

function applyConfigTabVisibility() {
  const devicePanel = document.getElementById("configDevicePanel");
  const dot1xPanel  = document.getElementById("configDot1xPanel");
  if (devicePanel) devicePanel.style.display = configActiveTab === "device" ? "" : "none";
  if (dot1xPanel)  dot1xPanel.style.display  = configActiveTab === "dot1x"  ? "" : "none";
}

function switchConfigTab(tab) {
  configActiveTab = tab;
  document.getElementById("configTabDevice")?.classList.toggle("active", tab === "device");
  document.getElementById("configTabDot1x")?.classList.toggle("active", tab === "dot1x");
  applyConfigTabVisibility(); // just show/hide — never re-render, so typed values are preserved
}

async function openConfigDrawer(macDash, forceSection) {
  configIsReadOnly = false;
  configAuthDirty = false;

  await loadVendorOuis();
  try {
    const [certs, caps, labCa] = await Promise.all([
      fetchJSON("/api/certs"),
      fetchJSON("/api/pki/enrollment-capabilities"),
      fetchJSON("/api/pki/lab-ca"),
    ]);
    certCache = certs;
    drawerEnrollCaps = caps;
    drawerLabCaExists = labCa.exists || false;
  } catch (_) {
    certCache = [];
    drawerEnrollCaps = null;
    drawerLabCaExists = false;
  }

  if (!macDash) {
    // CREATE MODE
    configMac = null;
    configMode = "create";
    configLoadedAuth = null;
    configSection = forceSection || "mab";
    configActiveTab = (forceSection === "dot1x") ? "dot1x" : "device";
    document.getElementById("configDrawerTitle").textContent = "New Device";
    document.getElementById("configDrawerSubtitle").textContent = "";
    document.getElementById("configReadOnlyBanner").style.display = "none";
    document.getElementById("configDrawerSave").style.display = "";
    document.getElementById("configDrawerDelete").style.display = "none";
    document.getElementById("configTabDot1x").textContent = "802.1X";
  } else {
    // EDIT MODE
    const mac = macDash.replace(/-/g, ":");
    const dev = devices.find((d) => d.mac === mac);
    if (!dev) return;

    configMac = mac;
    configMode = "edit";
    const isStopped = dev.state === "stopped" || dev.state === "auth_failed";
    configIsReadOnly = !isStopped;

    try {
      configLoadedAuth = await fetchJSON(`/api/devices/${macDash}/auth`);
    } catch (_) {
      configLoadedAuth = null;
    }

    configActiveTab = dev.auth_method ? "dot1x" : "device";
    document.getElementById("configDrawerTitle").textContent = configIsReadOnly ? "View Device" : "Edit Device";
    document.getElementById("configDrawerSubtitle").textContent = `${dev.name}  (${mac})`;
    document.getElementById("configReadOnlyBanner").style.display = configIsReadOnly ? "" : "none";
    document.getElementById("configDrawerSave").style.display = configIsReadOnly ? "none" : "";
    document.getElementById("configDrawerDelete").style.display = (dev.is_custom && !configIsReadOnly) ? "" : "none";
    document.getElementById("configTabDot1x").textContent = dev.auth_method ? "802.1X \u2713" : "802.1X";
  }

  document.getElementById("configTabDevice").classList.toggle("active", configActiveTab === "device");
  document.getElementById("configTabDot1x").classList.toggle("active", configActiveTab === "dot1x");
  renderConfigDrawerBody();
  document.getElementById("configOverlay").classList.add("open");
}

function renderConfigDrawerBody() {
  const body = document.getElementById("configDrawerBody");
  if (!body) return;
  const dev = configMac ? devices.find((d) => d.mac === configMac) : null;
  const profile = dev ? { name: dev.name, mac: dev.mac, personality: dev.personality, dhcp: dev.dhcp } : null;
  const auth = configMac ? configLoadedAuth : null;

  // Render BOTH panels at once. switchConfigTab only toggles visibility,
  // so typed values survive tab switches without any snapshot/restore logic.
  body.innerHTML =
    `<div id="configDevicePanel">${renderDeviceTab(profile)}</div>` +
    `<div id="configDot1xPanel">${renderDot1xTab(auth, dev)}</div>`;

  applyConfigTabVisibility();
  bindDeviceTabEvents();
  bindMethodChange();

  // Dirty-track only the 802.1X panel inputs
  body.querySelectorAll("#configDot1xPanel input, #configDot1xPanel select, #configDot1xPanel textarea").forEach((el) => {
    el.addEventListener("change", () => { configAuthDirty = true; });
    el.addEventListener("input",  () => { configAuthDirty = true; });
  });

  if (configIsReadOnly) {
    body.querySelectorAll("input, select, textarea, button:not(.btn-cert-action):not(.btn-link)").forEach((el) => {
      el.disabled = true;
    });
  }
}

function renderDeviceTab(profile) {
  const cat = profile ? profile.personality.category : "";
  const catOptions = CATEGORIES.map(
    (c) => `<option value="${c}" ${c === cat ? "selected" : ""}>${c}</option>`
  ).join("");

  const isCreate = configMode !== "edit";
  const vendorHtml = isCreate ? renderVendorOptions(cat, "") : "";

  let macSection = "";
  if (isCreate) {
    macSection = `
      <div class="form-group">
        <label class="form-label">MAC Address</label>
        <input type="text" class="form-input" id="editMac" value="" placeholder="Leave blank to auto-generate, or enter your own">
        <span class="mac-preview" id="macOuiPreview">Select a category to auto-generate a realistic MAC</span>
      </div>
      <div class="form-group" id="vendorGroup">
        <label class="form-label">Vendor OUI</label>
        <select class="form-select" id="editVendor">${vendorHtml}</select>
        <span class="form-hint">Determines the MAC prefix for ISE OUI-based profiling</span>
      </div>`;
  } else {
    macSection = `
      <div class="form-group">
        <label class="form-label">MAC Address</label>
        <input type="text" class="form-input" id="editMac" value="${escapeHtml((profile && profile.mac) || "")}" disabled>
      </div>`;
  }

  let authSection = "";
  if (isCreate) {
    const isDot1x = configSection === "dot1x";
    authSection = `
    <div class="form-section"><div class="form-section-title">Authentication</div>
      <div class="form-group">
        <label class="form-label">Authentication Type</label>
        <select class="form-select" id="editAuthType" onchange="if(this.value==='dot1x') switchConfigTab('dot1x')">
          <option value="mab" ${isDot1x ? "" : "selected"}>MAB (MAC Authentication Bypass)</option>
          <option value="dot1x" ${isDot1x ? "selected" : ""}>802.1X</option>
        </select>
        <span class="form-hint">For 802.1X credentials, use the <strong>802.1X</strong> tab &rarr;</span>
      </div>
    </div>`;
  }

  return `
    <div class="form-section"><div class="form-section-title">Device Identity</div>
      <div class="form-group">
        <label class="form-label">Name</label>
        <input type="text" class="form-input" id="editName" value="${escapeHtml((profile && profile.name) || "")}" placeholder="e.g. Corporate Laptop">
      </div>
      ${macSection}
    </div>
    ${authSection}
    <div class="form-section"><div class="form-section-title">Personality</div>
      <div class="form-group">
        <label class="form-label">Category</label>
        <select class="form-select" id="editCategory">
          <option value="">-- select --</option>
          ${catOptions}
        </select>
      </div>
      <div class="form-group">
        <label class="form-label">Operating System</label>
        <input type="text" class="form-input" id="editOS" value="${escapeHtml((profile && profile.personality.os) || "")}" placeholder="e.g. Windows 11, iOS 17">
      </div>
      <div class="form-group">
        <label class="form-label">Device Type</label>
        <input type="text" class="form-input" id="editDevType" value="${escapeHtml((profile && profile.personality.device_type) || "")}" placeholder="e.g. Corporate laptop">
      </div>
    </div>
    <div class="form-section"><div class="form-section-title">DHCP</div>
      <div class="form-group">
        <label class="form-label">Hostname <span class="form-hint-inline">(option 12 &mdash; affects ISE profiling)</span></label>
        <input type="text" class="form-input" id="editHostname" value="${escapeHtml((profile && profile.dhcp.hostname) || "")}" placeholder="e.g. CORP-LAPTOP-01">
      </div>
      <div class="form-group">
        <label class="form-label">Vendor Class ID <span class="form-hint-inline">(option 60 &mdash; e.g. MSFT 5.0 for Windows)</span></label>
        <input type="text" class="form-input" id="editVendorClass" value="${escapeHtml((profile && profile.dhcp.vendor_class) || "")}" placeholder="e.g. MSFT 5.0">
      </div>
    </div>
  `;
}

function renderDot1xTab(auth, dev) {
  if (configMode === "edit" && !auth) {
    return `
      <div class="dot1x-empty-state">
        <div class="dot1x-empty-icon">&#128274;</div>
        <div class="dot1x-empty-title">802.1X not configured</div>
        <div class="dot1x-empty-desc">This device uses MAB. Fill in the fields below to add 802.1X authentication.</div>
      </div>
      ${renderDrawerBody(null)}`;
  }
  return renderDrawerBody(auth);
}

function updateDot1xTabLabel() {
  const authType = document.getElementById("editAuthType")?.value;
  const tab = document.getElementById("configTabDot1x");
  if (!tab) return;
  tab.textContent = authType === "dot1x" ? "802.1X \u2713" : "802.1X";
}

function bindDeviceTabEvents() {
  const catSel = document.getElementById("editCategory");
  const vendorSel = document.getElementById("editVendor");
  const macInput = document.getElementById("editMac");
  const nameInput = document.getElementById("editName");
  const hostnameInput = document.getElementById("editHostname");

  if (catSel && vendorSel) {
    catSel.addEventListener("change", () => {
      vendorSel.innerHTML = renderVendorOptions(catSel.value, "");
      updateMacPreview();
    });
  }
  if (vendorSel) vendorSel.addEventListener("change", updateMacPreview);
  if (macInput) macInput.addEventListener("input", updateMacPreview);

  if (nameInput && hostnameInput) {
    // Stop auto-syncing only if the user has directly edited the hostname field.
    hostnameInput.addEventListener("input", () => {
      hostnameInput.dataset.userEdited = "1";
    });
    nameInput.addEventListener("input", () => {
      if (!hostnameInput.dataset.userEdited) {
        hostnameInput.value = nameInput.value.trim()
          .toUpperCase()
          .replace(/[^A-Z0-9\s-]/g, "")
          .replace(/\s+/g, "-")
          .substring(0, 24);
      }
    });
  }

  // Identity → CN live-sync: when user types in the inline identity field,
  // propagate to any CN inputs that are still empty (same guard as name→hostname).
  const drawerBody = document.getElementById("configDrawerBody");
  if (drawerBody) {
    drawerBody.addEventListener("input", (e) => {
      const id = e.target && e.target.id;
      // Mark CN fields as user-edited when typed into directly — stops auto-sync for that field.
      if (id && /(?:LabcaCN|ScepCN|StepCN)$/.test(id)) {
        e.target.dataset.userEdited = "1";
      }
      // User identity → user cert CN fields (inline create panel)
      if (id === "inlineIdentity") {
        const v = e.target.value.trim();
        ["inlineLabcaCN", "inlineScepCN", "inlineStepCN"].forEach((cnId) => {
          const el = document.getElementById(cnId);
          if (el && !el.dataset.userEdited) el.value = v;
        });
      }
      // User identity → user cert CN fields (full 802.1X tab)
      if (id === "authIdentity") {
        const v = e.target.value.trim();
        ["authLabcaCN", "authScepCN", "authStepCN"].forEach((cnId) => {
          const el = document.getElementById(cnId);
          if (el && !el.dataset.userEdited) el.value = v;
        });
      }
      // Machine identity → machine cert CN fields (full 802.1X tab, Chained)
      // Strip the "host/" Kerberos SPN prefix — CN should be the FQDN only.
      if (id === "authMachineIdentity") {
        const raw = e.target.value.trim();
        const v = raw.startsWith("host/") ? raw.slice(5) : raw;
        ["authMachineLabcaCN", "authMachineScepCN", "authMachineStepCN"].forEach((cnId) => {
          const el = document.getElementById(cnId);
          if (el && !el.dataset.userEdited) el.value = v;
        });
      }
      // Machine identity → machine cert CN fields (inline create panel, Chained)
      if (id === "inlineMachineIdentity") {
        const raw = e.target.value.trim();
        const v = raw.startsWith("host/") ? raw.slice(5) : raw;
        ["inlineMachineLabcaCN", "inlineMachineScepCN", "inlineMachineStepCN"].forEach((cnId) => {
          const el = document.getElementById(cnId);
          if (el && !el.dataset.userEdited) el.value = v;
        });
      }
    });
  }
}

// Aliases so existing callers still work
function bindEditDrawerEvents() { bindDeviceTabEvents(); }

function collectEditForm() {
  const ouiHint = document.getElementById("editVendor")?.value || "";
  return {
    name: document.getElementById("editName")?.value.trim() || "Unnamed Device",
    mac: document.getElementById("editMac")?.value.trim() || "",
    oui_hint: ouiHint,
    personality: {
      category: document.getElementById("editCategory")?.value || "",
      os: document.getElementById("editOS")?.value.trim() || "",
      device_type: document.getElementById("editDevType")?.value.trim() || "",
    },
    dhcp: {
      hostname: document.getElementById("editHostname")?.value.trim() || "",
      vendor_class: document.getElementById("editVendorClass")?.value.trim() || "",
    },
  };
}

// Aliases for cloneDevice() which calls openEditDrawer after clone
function openEditDrawer(macDash) { openConfigDrawer(macDash, null); }
function openCreateDrawer(section) { openConfigDrawer(null, section); }
function closeEditDrawer() { closeConfigDrawer(); }
function closeDrawer() { closeConfigDrawer(); }

function closeConfigDrawer() {
  document.getElementById("configOverlay").classList.remove("open");
  configMac = null;
  configMode = null;
  configAuthDirty = false;
  configIsReadOnly = false;
}

function collectAuthForm() {
  const method = document.getElementById("authMethod")?.value || "peap-mschapv2";
  return {
    method,
    identity: document.getElementById("authIdentity")?.value || "",
    anonymous_identity: document.getElementById("authAnonIdentity")?.value || "",
    auth_type: document.getElementById("authType")?.value || "user",
    password: document.getElementById("authPassword")?.value || null,
    phase2: document.getElementById("authPhase2")?.value || "MSCHAPV2",
    peap_version: parseInt(document.getElementById("authPeapVer")?.value || "0", 10),
    client_cert: document.getElementById("authClientCert")?.value || null,
    private_key: document.getElementById("authPrivateKey")?.value || null,
    private_key_password: document.getElementById("authKeyPassword")?.value || null,
    ca_cert: document.getElementById("authCaCert")?.value || null,
    validate_server_cert: document.getElementById("authValidateCert")?.checked || false,
    pac_provisioning: document.getElementById("authPacProv")?.checked || false,
    pac_file: document.getElementById("authPacFile")?.value || null,
    eapol_version: parseInt(document.getElementById("authEapolVer")?.value || "2", 10),
    fragment_size: parseInt(document.getElementById("authFragSize")?.value || "1398", 10),
    fast_reconnect: document.getElementById("authFastReconn")?.checked ?? true,
    // TEAP-specific fields
    teap_inner_method: document.getElementById("authTeapInner")?.value || "MSCHAPV2",
    machine_identity: document.getElementById("authMachineIdentity")?.value || null,
    machine_cert: document.getElementById("authMachineClientCert")?.value || null,
    machine_key: document.getElementById("authMachinePrivateKey")?.value || null,
    machine_key_password: document.getElementById("authMachineKeyPass")?.value || null,
  };
}

async function saveConfigDrawer() {
  if (configIsReadOnly) return;
  const isCreate = configMode === "create";

  if (isCreate) {
    const data = collectEditForm();
    const authTypeEl = document.getElementById("editAuthType");
    const selectedMab = !authTypeEl || authTypeEl.value !== "dot1x";

    // Guard: warn if user left auth type = MAB but entered 802.1X credentials
    if (selectedMab && configAuthDirty) {
      const proceed = confirm(
        "Auth type is set to MAB on the Device tab, but 802.1X credentials were entered on the 802.1X tab.\n\n" +
        "• OK → create as MAB (802.1X settings will be ignored)\n" +
        "• Cancel → go back and switch Auth Type to 802.1X if that was intended"
      );
      if (!proceed) return;
    }

    const auth = !selectedMab ? collectAuthForm() : null;
    const payload = { name: data.name, mac: data.mac, oui_hint: data.oui_hint, personality: data.personality, dhcp: data.dhcp };
    if (auth) payload.auth = auth;
    try {
      const created = await fetchJSON("/api/devices", { method: "POST", body: JSON.stringify(payload) });
      closeConfigDrawer();
      await refreshAll();
      showToast(`Created ${created.name || "device"} (${auth ? "802.1X" : "MAB"})`, "success");
    } catch (err) {
      showToast("Create failed: " + err.message, "error");
    }
  } else if (configMode === "edit" && configMac) {
    const macDash = configMac.replace(/:/g, "-");
    const data = collectEditForm();
    try {
      await fetchJSON(`/api/devices/${macDash}`, {
        method: "PUT",
        body: JSON.stringify({ name: data.name, personality: data.personality, dhcp: data.dhcp }),
      });
      if (configAuthDirty) {
        const authData = collectAuthForm();
        const hasContent = authData.method && (authData.identity || authData.client_cert || authData.password);
        if (hasContent) {
          await fetchJSON(`/api/devices/${macDash}/auth`, { method: "PUT", body: JSON.stringify(authData) });
        }
      }
      closeConfigDrawer();
      await refreshAll();
      showToast("Device updated", "success");
    } catch (err) {
      showToast("Save failed: " + err.message, "error");
    }
  }
}

async function deleteFromConfigDrawer() {
  if (!configMac) return;
  const macDash = configMac.replace(/:/g, "-");
  const dev = devices.find((d) => d.mac === configMac);
  const name = dev ? dev.name : configMac;
  if (!confirm(`Delete "${name}"?\nThis cannot be undone.`)) return;
  try {
    await fetchJSON(`/api/devices/${macDash}`, { method: "DELETE" });
    closeConfigDrawer();
    await refreshAll();
  } catch (err) {
    showToast("Delete failed: " + err.message, "error");
  }
}

async function removeAuthConfig() {
  if (!configMac) return;
  const macDash = configMac.replace(/:/g, "-");
  if (!confirm("Remove 802.1X configuration and revert this device to MAB?")) return;
  try {
    await fetchJSON(`/api/devices/${macDash}/auth`, { method: "DELETE" });
    closeConfigDrawer();
    await refreshAll();
    showToast("Reverted to MAB", "success");
  } catch (err) {
    showToast("Remove failed: " + err.message, "error");
  }
}

function renderInlineAuthFields(auth) {
  const method = (auth && auth.method) || "peap-mschapv2";
  const isTeap = method === "teap";
  const teapInner = isTeap ? ((auth && auth.teap_inner_method) || "MSCHAPV2") : "";
  const needsPassword = ["peap-mschapv2", "peap", "eap-fast", "fast", "eap-ttls", "ttls"].includes(method)
    || (isTeap && (teapInner === "MSCHAPV2" || teapInner === "Chained"));
  // Chained uses machine cert (not a user cert) — user side is MSCHAPv2 password
  const needsCerts = method === "eap-tls" || (isTeap && teapInner === "EAP-TLS");
  const isEapFast = ["eap-fast", "fast"].includes(method);
  const isTeapChained = isTeap && teapInner === "Chained";

  let html = '<div class="form-group"><label class="form-label">EAP Method</label>';
  html += '<select class="form-select" id="inlineEapMethod" onchange="refreshInlineAuth()">';
  EAP_METHODS.forEach((m) => {
    html += `<option value="${m.value}" ${m.value === method ? "selected" : ""}>${m.label}</option>`;
  });
  html += "</select></div>";

  // TEAP warning banner
  if (isTeap) {
    html += `<div class="teap-warning-banner">&#9888; <strong>ISE 3.1+ required.</strong> TLS 1.3-capable. PAC-less. wpa_supplicant &ge; 2.10 needed.</div>`;
  }

  // TEAP inner method selector
  if (isTeap) {
    html += '<div class="form-group"><label class="form-label">Inner authentication</label>';
    html += '<select class="form-select" id="inlineTeapInner" onchange="refreshInlineAuth()">';
    [["MSCHAPV2", "MSCHAPv2 (username + password)"], ["EAP-TLS", "EAP-TLS (user certificate)"], ["Chained", "Chained (machine cert \u2295 user password)"]].forEach(([val, lbl]) => {
      html += `<option value="${val}" ${teapInner === val ? "selected" : ""}>${lbl}</option>`;
    });
    html += '</select></div>';
  }

  html += `<div class="form-group"><label class="form-label">Identity (username)</label>
    <input type="text" class="form-input" id="inlineIdentity" value="${escapeHtml((auth && auth.identity) || "")}" placeholder="user@example.com"></div>`;

  html += `<div class="form-group"><label class="form-label">Anonymous identity (outer)</label>
    <input type="text" class="form-input" id="inlineAnonIdentity" value="${escapeHtml((auth && auth.anonymous_identity) || "")}" placeholder="anonymous@example.com"></div>`;

  if (isTeapChained) {
    html += `<div class="form-group"><label class="form-label">Auth type</label>
      <div class="teap-authtype-note">&#9432; Chained — authenticates <strong>machine + user</strong> simultaneously.</div>
      <input type="hidden" id="editAuthTypeHidden" value="chained"></div>`;
  } else {
    // auth_type is metadata only — does not change what wpa_supplicant sends on the wire
    html += `<div class="form-group"><label class="form-label">Auth type</label>
      <select class="form-select" id="inlineAuthType">
        <option value="user" ${(!auth || auth.auth_type === "user") ? "selected" : ""}>User</option>
        <option value="machine" ${(auth && auth.auth_type === "machine") ? "selected" : ""}>Machine</option>
      </select>
      <span class="form-hint">&#9432; Metadata only &mdash; does not change what is sent on the wire. The identity string and certificate subject determine machine vs. user to ISE.</span></div>`;
  }

  if (needsPassword) {
    html += `<div class="form-group"><label class="form-label">Password</label>
      <div class="password-wrapper">
        <input type="password" class="form-input" id="inlinePassword" value="${escapeHtml((auth && auth.password) || "")}" placeholder="Enter password">
        <button type="button" class="password-toggle" onclick="togglePasswordVis('inlinePassword')">${EYE_ICON_SVG}</button>
      </div></div>`;
    if (!isTeap) {
      html += '<div class="form-group"><label class="form-label">Phase 2</label><select class="form-select" id="inlinePhase2">';
      PHASE2_OPTIONS.forEach((p) => {
        html += `<option value="${p}" ${(auth && auth.phase2 === p) ? "selected" : (p === "MSCHAPV2" && !auth ? "selected" : "")}>${p}</option>`;
      });
      html += "</select></div>";
    }
  }

  if (needsCerts) {
    html += renderCertSourcePanel("inline", auth, false);
    html += `<div class="form-group"><label class="form-label">Key password</label>
      <div class="password-wrapper">
        <input type="password" class="form-input" id="inlineKeyPass" value="" placeholder="Leave blank if unencrypted">
        <button type="button" class="password-toggle" onclick="togglePasswordVis('inlineKeyPass')">${EYE_ICON_SVG}</button>
      </div></div>`;
  }

  // Machine Identity section for inline Chained mode
  if (isTeapChained) {
    html += '<div class="teap-machine-section">';
    html += '<div class="form-section-title" style="margin-top:10px">&#128274; Machine Certificate</div>';
    html += '<span class="form-hint" style="display:block;margin-bottom:8px">The machine cert authenticates the device via the outer TLS handshake. The CN in the cert is the machine identity ISE evaluates. Use the CN field below to generate a matching cert.</span>';
    html += `<div class="form-group"><label class="form-label">Machine CN <span class="form-hint-inline">(for cert generation)</span></label>
      <input type="text" class="form-input" id="inlineMachineIdentity" value="${escapeHtml((auth && auth.machine_identity) || "")}" placeholder="WIN11-LAB.example.com"></div>`;
    html += renderCertSourcePanel("inlineMachine", auth, false, {
      existingCert: auth && auth.machine_cert,
      existingKey:  auth && auth.machine_key,
      cn: (auth && auth.machine_identity) || "",
    });
    html += `<div class="form-group"><label class="form-label">Machine key password</label>
      <div class="password-wrapper">
        <input type="password" class="form-input" id="inlineMachineKeyPass" value="" placeholder="Leave blank if unencrypted">
        <button type="button" class="password-toggle" onclick="togglePasswordVis('inlineMachineKeyPass')">${EYE_ICON_SVG}</button>
      </div></div>`;
    html += '</div>';
  }

  if (isEapFast) {
    html += `<div class="form-group form-toggle"><label class="form-label">PAC auto-provisioning</label>
      <label class="toggle-switch"><input type="checkbox" id="inlinePacProv" ${(auth && auth.pac_provisioning) ? "checked" : ""}>
      <span class="toggle-slider"></span></label></div>`;
  }

  html += certSelectHtml("inlineCaCert", "CA certificate", auth && auth.ca_cert, "cert");
  html += `<div class="form-group form-toggle"><label class="form-label">Validate server cert</label>
    <label class="toggle-switch"><input type="checkbox" id="inlineValidateCert" ${(auth && auth.validate_server_cert) ? "checked" : ""}>
    <span class="toggle-slider"></span></label></div>`;

  return html;
}

function toggleInlineAuth() {
  const sel = document.getElementById("editAuthType");
  const fields = document.getElementById("inlineAuthFields");
  if (!sel || !fields) return;
  fields.style.display = sel.value === "dot1x" ? "" : "none";
}

function refreshInlineAuth() {
  const container = document.getElementById("inlineAuthFields");
  if (!container) return;
  const method = document.getElementById("inlineEapMethod")?.value || "peap-mschapv2";
  const identity = document.getElementById("inlineIdentity")?.value || "";
  const anonId = document.getElementById("inlineAnonIdentity")?.value || "";
  const password = document.getElementById("inlinePassword")?.value || "";
  const teapInner = document.getElementById("inlineTeapInner")?.value || "MSCHAPV2";
  // Preserve ALL current field values so switching method doesn't wipe certs/flags
  const machineIdentity = document.getElementById("inlineMachineIdentity")?.value || "";
  const machineCert     = document.getElementById("inlineMachineClientCert")?.value || null;
  const machineKey      = document.getElementById("inlineMachinePrivateKey")?.value || null;
  const clientCert      = document.getElementById("inlineClientCert")?.value || null;
  const privateKey      = document.getElementById("inlinePrivateKey")?.value || null;
  const caCert          = document.getElementById("inlineCaCert")?.value || null;
  const validateCert    = document.getElementById("inlineValidateCert")?.checked || false;
  const fakeAuth = {
    method, identity, anonymous_identity: anonId, password, teap_inner_method: teapInner,
    machine_identity: machineIdentity || null,
    machine_cert: machineCert,
    machine_key:  machineKey,
    client_cert:  clientCert,
    private_key:  privateKey,
    ca_cert:      caCert,
    validate_server_cert: validateCert,
  };
  container.innerHTML = renderInlineAuthFields(fakeAuth);
}

function collectInlineAuth() {
  const authTypeEl = document.getElementById("editAuthType");
  if (!authTypeEl || authTypeEl.value !== "dot1x") return null;
  const method = document.getElementById("inlineEapMethod")?.value || "peap-mschapv2";
  return {
    method: method,
    identity: document.getElementById("inlineIdentity")?.value || "",
    anonymous_identity: document.getElementById("inlineAnonIdentity")?.value || "",
    auth_type: document.getElementById("inlineAuthType")?.value || document.getElementById("editAuthTypeHidden")?.value || "user",
    password: document.getElementById("inlinePassword")?.value || null,
    phase2: document.getElementById("inlinePhase2")?.value || "MSCHAPV2",
    client_cert: document.getElementById("inlineClientCert")?.value || null,
    private_key: document.getElementById("inlinePrivateKey")?.value || null,
    private_key_password: document.getElementById("inlineKeyPass")?.value || null,
    ca_cert: document.getElementById("inlineCaCert")?.value || null,
    validate_server_cert: document.getElementById("inlineValidateCert")?.checked || false,
    pac_provisioning: document.getElementById("inlinePacProv")?.checked || false,
    // TEAP-specific fields
    teap_inner_method: document.getElementById("inlineTeapInner")?.value || "MSCHAPV2",
    machine_identity: document.getElementById("inlineMachineIdentity")?.value || null,
    machine_cert: document.getElementById("inlineMachineClientCert")?.value || null,
    machine_key: document.getElementById("inlineMachinePrivateKey")?.value || null,
    machine_key_password: document.getElementById("inlineMachineKeyPass")?.value || null,
  };
}

function bindEditDrawerEvents() { bindDeviceTabEvents(); }

/* ─── Settings ────────────────────────────────────────────────────── */

/* ─── Interface Badge + Panel ─────────────────────────────────────── */

let _ifacePanelOpen = false;

function toggleIfacePanel() {
  const panel = document.getElementById("ifacePanel");
  if (!panel) return;
  _ifacePanelOpen = !_ifacePanelOpen;
  panel.style.display = _ifacePanelOpen ? "block" : "none";
  if (_ifacePanelOpen) renderIfacePanel();
}

async function renderIfacePanel() {
  const body = document.getElementById("ifacePanelBody");
  if (!body) return;
  body.innerHTML = '<div class="iface-loading">Loading…</div>';
  try {
    const [ifaceData, allData] = await Promise.all([
      fetchJSON("/api/interface"),
      fetchJSON("/api/interfaces"),
    ]);
    const ifaces = allData.interfaces || [];
    const dataIface = ifaceData.data_interface;
    const mgmtIface = ifaceData.mgmt_interface;

    const roleLabel = { "data": "DATA", "mgmt": "MGMT", "data+mgmt": "DATA+MGMT", "other": "" };
    const roleCls   = { "data": "role-data", "mgmt": "role-mgmt", "data+mgmt": "role-both", "other": "role-other" };
    const stateCls  = (s) => s === "up" ? "operstate-up" : "operstate-down";

    let rows = ifaces.map(i => `
      <tr class="iface-row${i.name === dataIface ? " iface-row-active" : ""}">
        <td class="iface-name">${escapeHtml(i.name)}</td>
        <td><span class="operstate-dot ${stateCls(i.operstate)}" title="${escapeHtml(i.operstate)}"></span>${escapeHtml(i.operstate)}</td>
        <td class="iface-ip">${escapeHtml(i.ip || "—")}</td>
        <td class="iface-mac">${escapeHtml(i.mac || "—")}</td>
        <td>${i.role ? `<span class="iface-role-badge ${roleCls[i.role] || ''}">${roleLabel[i.role] || i.role}</span>` : ""}</td>
        <td>${i.role !== "data" && i.role !== "data+mgmt"
          ? `<button class="btn btn-sm btn-section-connect" onclick="setDataInterface('${escapeHtml(i.name)}')">Set as Data</button>`
          : `<span class="iface-active-indicator">✓ Active</span>`
        }</td>
      </tr>`).join("");

    body.innerHTML = `
      <div class="iface-summary">
        <div class="iface-summary-row"><span class="iface-summary-label">Management (web UI)</span><span class="iface-summary-val">${escapeHtml(mgmtIface)}${ifaceData.mgmt?.ip ? " · " + escapeHtml(ifaceData.mgmt.ip) : ""}</span></div>
        <div class="iface-summary-row"><span class="iface-summary-label">Data / NAD (EAP · MAB)</span><span class="iface-summary-val">${escapeHtml(dataIface)}${ifaceData.data?.ip ? " · " + escapeHtml(ifaceData.data.ip) : ""}</span></div>
        ${ifaceData.same ? '<div class="iface-same-notice">Single-NIC mode — management and data share the same interface.</div>' : ""}
      </div>
      ${ifaceData.data?.operstate && ifaceData.data.operstate !== "up" ? `
      <div class="iface-down-warning">
        ⚠️ Data interface <strong>${escapeHtml(dataIface)}</strong> is <strong>${escapeHtml(ifaceData.data.operstate)}</strong>.
        MACforge will attempt to bring it up automatically when a device connects.
        If no packets reach the switch, verify the NIC has a physical/virtual cable attached and a link partner.
      </div>` : ""}
      <table class="iface-table">
        <thead><tr><th>Interface</th><th>State</th><th>IP</th><th>MAC</th><th>Role</th><th></th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
      <div class="iface-panel-hint">To permanently assign interfaces, set <code>MACFORGE_IFACE</code> and <code>MACFORGE_DATA_IFACE</code> env vars.</div>`;
  } catch (err) {
    body.innerHTML = `<div class="iface-error">Failed to load interfaces: ${escapeHtml(err.message)}</div>`;
  }
}

async function setDataInterface(ifaceName) {
  try {
    const data = await fetchJSON("/api/interface/data", {
      method: "PUT",
      body: JSON.stringify({ interface: ifaceName }),
    });
    showToast(`Data interface set to ${ifaceName}`, "success");
    await loadInterface();
    await renderIfacePanel();
  } catch (err) {
    showToast("Cannot change interface: " + err.message, "error");
  }
}

async function loadInterface() {
  try {
    const data = await fetchJSON("/api/interface");
    const badge = document.getElementById("interfaceBadge");
    if (!badge) return;
    if (data.same) {
      badge.textContent = data.data_interface;
      const parts = [data.data_interface];
      if (data.mac) parts.push(`MAC: ${data.mac}`);
      if (data.ip) parts.push(`IP: ${data.ip}`);
      if (data.seed_fingerprint) parts.push(`Seed: ${data.seed_fingerprint}`);
      badge.title = parts.join("\n");
    } else {
      badge.textContent = `▲ ${data.mgmt_interface}  ◆ ${data.data_interface}`;
      const parts = [
        `Management : ${data.mgmt_interface}${data.mgmt?.ip ? " · " + data.mgmt.ip : ""}`,
        `Data / NAD : ${data.data_interface}${data.data?.ip ? " · " + data.data.ip : ""}`,
      ];
      if (data.seed_fingerprint) parts.push(`Seed: ${data.seed_fingerprint}`);
      badge.title = parts.join("\n");
    }
  } catch (err) {
    console.error("Failed to load interface:", err);
  }
}

async function loadSettings() {
  try {
    const data = await fetchJSON("/api/settings");
    document.getElementById("snmpToggle").checked = data.snmp_enabled;
  } catch (err) {
    console.error("Failed to load settings:", err);
  }
}

let _readinessCache = null;
async function loadDot1xReadiness() {
  const btn = document.getElementById("readinessBtn");
  if (btn) { btn.textContent = "⏳ checking…"; btn.className = "readiness-btn"; }
  try {
    // Readiness runs 5 EAP method probes (2s timeout each) + binary checks.
    // Total can easily reach 10-15s — use a longer timeout than the default 6s.
    const data = await fetchJSONWithTimeout("/api/dot1x/readiness", {}, FETCH_TIMEOUT_SLOW_MS);
    _readinessCache = data;
    if (!btn) return;
    if (data.all_ok) {
      btn.textContent = "✅ System Ready";
      btn.className = "readiness-btn readiness-ok";
    } else {
      const allChecks = [
        ...Object.values(data.binaries || {}),
        ...Object.values(data.eap || {}),
        ...Object.values(data.system || {}),
      ];
      const failCount = allChecks.filter(m => !m.ok).length;
      btn.textContent = `⚠️ ${failCount} check${failCount > 1 ? "s" : ""} failed`;
      btn.className = "readiness-btn readiness-warn";
    }
  } catch (err) {
    if (btn) { btn.textContent = "❓ unknown"; btn.className = "readiness-btn"; }
  }
}

function showReadinessDetail() {
  // Toggle dropdown — dismiss if already open
  const existing = document.getElementById("readinessPanel");
  if (existing) { existing.remove(); return; }

  const btn = document.getElementById("readinessBtn");
  if (!btn) return;

  const panel = document.createElement("div");
  panel.id = "readinessPanel";
  panel.className = "readiness-panel";

  if (!_readinessCache) {
    panel.innerHTML = `<div class="rp-loading">⏳ Loading…</div>`;
    document.body.appendChild(panel);
    positionReadinessPanel(btn, panel);
    return;
  }

  const { binaries = {}, eap = {}, system = {} } = _readinessCache;
  const binaryLabels = {
    wpa_supplicant:         "wpa_supplicant (apt)",
    wpa_supplicant_version: "Version ≥ 2.10",
    wpa_supplicant_teap:    "wpa_supplicant_teap (TEAP)",
    sscep:                  "sscep (SCEP/NDES)",
  };
  const eapLabels = {
    PEAP_MSCHAPv2: "PEAP-MSCHAPv2",
    EAP_TLS:       "EAP-TLS",
    EAP_FAST:      "EAP-FAST",
    EAP_TTLS:      "EAP-TTLS",
    TEAP:          "TEAP (RFC 7170)",
  };
  const sysLabels = {
    iproute2: "iproute2 (macvlan)",
    iptables: "iptables (stealth)",
  };

  function rpSection(title, checks, labels) {
    const rows = Object.entries(checks).map(([k, v]) => {
      const icon = v.ok ? "✅" : "❌";
      const label = labels[k] || k;
      const detailCls = v.ok ? "rp-detail" : "rp-detail rp-fail";
      return `<div class="rp-row">${icon} <span class="rp-label">${label}</span><span class="${detailCls}">${escapeHtml(v.detail)}</span></div>`;
    }).join("");
    return `<div class="rp-section"><div class="rp-section-title">${title}</div>${rows}</div>`;
  }

  panel.innerHTML = `
    <div class="rp-header">
      <span>System Readiness</span>
      <div class="rp-actions">
        <button class="rp-recheck" onclick="loadDot1xReadiness().then(()=>{const p=document.getElementById('readinessPanel');if(p)p.remove();showReadinessDetail()})">↻ Re-check</button>
        <button class="rp-close" onclick="document.getElementById('readinessPanel')?.remove()">✕</button>
      </div>
    </div>
    ${rpSection("Binaries", binaries, binaryLabels)}
    ${rpSection("EAP Methods", eap, eapLabels)}
    ${rpSection("System", system, sysLabels)}
  `;

  document.body.appendChild(panel);
  positionReadinessPanel(btn, panel);

  // Dismiss on outside click
  setTimeout(() => {
    document.addEventListener("click", function dismiss(e) {
      if (!panel.contains(e.target) && e.target !== btn) {
        panel.remove();
        document.removeEventListener("click", dismiss);
      }
    });
  }, 0);
}

function positionReadinessPanel(btn, panel) {
  const rect = btn.getBoundingClientRect();
  panel.style.top  = (rect.bottom + window.scrollY + 6) + "px";
  panel.style.left = Math.min(rect.left + window.scrollX, window.innerWidth - 320 - 12) + "px";
}

async function toggleSNMP() {
  const enabled = document.getElementById("snmpToggle").checked;
  try {
    await fetchJSON("/api/settings", {
      method: "POST",
      body: JSON.stringify({ snmp_enabled: enabled }),
    });
  } catch (err) {
    console.error("Failed to toggle SNMP:", err);
    document.getElementById("snmpToggle").checked = !enabled;
  }
}

/* ─── 802.1X Drawer ───────────────────────────────────────────────── */

/**
 * Render the Auth Type field. Behaviour per method:
 *   TEAP Chained  → hidden entirely; badge shows "Machine + User (Chained)"
 *   TEAP non-Chained → static badge (User) + hidden input; scope is unambiguous
 *   EAP-TLS       → dropdown + tooltip about cert subject
 *   PEAP/FAST/TTLS → dropdown + tooltip clarifying it is metadata-only on the wire
 */
function renderAuthTypeField(method, teapInner, auth, inputId) {
  const val = (auth && auth.auth_type) || "user";

  if (method === "teap" && teapInner === "Chained") {
    return `
      <div class="form-group">
        <label class="form-label">Authentication scope</label>
        <div class="auth-scope-badge both">&#9939; Machine + User (Chained)</div>
        <span class="form-hint">Both identities travel inside the TEAP TLS tunnel via TLV objects. ISE evaluates them together using a Compound Condition.</span>
        <input type="hidden" id="${inputId}" value="chained">
      </div>`;
  }

  if (method === "teap") {
    const label = teapInner === "EAP-TLS" ? "User (certificate)" : "User (password)";
    return `
      <div class="form-group">
        <label class="form-label">Authentication scope</label>
        <div class="auth-scope-badge user">&#128100; ${label}</div>
        <span class="form-hint">TEAP sends this identity inside the encrypted TLS tunnel as a user TLV. ISE evaluates it against standard user auth policies.</span>
        <input type="hidden" id="${inputId}" value="user">
      </div>`;
  }

  const tooltip = method === "eap-tls"
    ? "User: authenticates the logged-in user via their personal certificate. Machine: authenticates the device using a machine/computer certificate \u2014 useful for pre-login VLAN access. On the wire, EAP-TLS sends whichever certificate is configured in the cert fields above."
    : "Metadata label only \u2014 does not change what wpa_supplicant sends on the wire. ISE reads the actual identity string and certificate subject to determine machine vs. user context.";

  return `
    <div class="form-group">
      <label class="form-label">Auth type <span class="field-tooltip" title="${escapeHtml(tooltip)}">&#9432;</span></label>
      <select class="form-select" id="${inputId}">
        <option value="user" ${val === "user" ? "selected" : ""}>User</option>
        <option value="machine" ${val === "machine" ? "selected" : ""}>Machine</option>
      </select>
    </div>`;
}

const EAP_METHODS = [
  { value: "peap-mschapv2", label: "PEAP-MSCHAPv2" },
  { value: "eap-tls", label: "EAP-TLS" },
  { value: "eap-fast", label: "EAP-FAST" },
  { value: "eap-ttls", label: "EAP-TTLS" },
  { value: "teap", label: "TEAP (RFC 7170)" },
];

const PHASE2_OPTIONS = ["MSCHAPV2", "GTC", "MD5", "PAP", "CHAP"];

function passwordField(id, label, value, placeholder) {
  const val = value || "";
  return `
    <div class="form-group">
      <label class="form-label">${escapeHtml(label)}</label>
      <div class="password-wrapper">
        <input type="password" class="form-input" id="${id}" value="${escapeHtml(val)}" placeholder="${escapeHtml(placeholder || "")}">
        <button type="button" class="password-toggle" onclick="togglePasswordVis('${id}')" title="Show/hide">${EYE_ICON_SVG}</button>
      </div>
    </div>
  `;
}

function togglePasswordVis(inputId) {
  const input = document.getElementById(inputId);
  if (!input) return;
  input.type = input.type === "password" ? "text" : "password";
}

function filterCertFiles(fileType) {
  if (!fileType || fileType === "any") return certCache;
  if (fileType === "cert") return certCache.filter((c) => /\.(pem|crt|cer|p12|pfx)$/i.test(c.filename) && !/\.key$/i.test(c.filename) && !/\.csr$/i.test(c.filename));
  if (fileType === "key")  return certCache.filter((c) => /\.(key|pem)$/i.test(c.filename));
  if (fileType === "pac")  return certCache.filter((c) => /\.pac$/i.test(c.filename));
  return certCache;
}

function certSelectHtml(id, label, selectedValue, fileType = "any") {
  let files = filterCertFiles(fileType);
  // Always surface the currently-configured file even if it doesn't match the filter
  if (selectedValue && !files.find((c) => c.filename === selectedValue)) {
    files = [...files, { filename: selectedValue }];
  }
  const opts = files.map(
    (c) => `<option value="${escapeHtml(c.filename)}" ${c.filename === selectedValue ? "selected" : ""}>${escapeHtml(c.filename)}</option>`
  );
  return `
    <div class="form-group">
      <label class="form-label">${escapeHtml(label)}</label>
      <div class="cert-select-row">
        <select class="form-select" id="${id}">
          <option value="">-- none --</option>
          ${opts.join("")}
        </select>
        <button type="button" class="btn-cert-action" onclick="goToCertsTab()">Manage</button>
      </div>
    </div>
  `;
}

function goToCertsTab() {
  closeDrawer();
  closeEditDrawer();
  switchTab("certs");
}

/* ─── Inline Cert Provisioning (802.1X Drawers) ────────────────────── */

// Resolve which identity input ID and CA cert select ID belong to a given cert panel prefix
function _prefixIdentityId(prefix) {
  if (prefix === "auth")          return "authIdentity";
  if (prefix === "inline")        return "inlineIdentity";
  if (prefix === "authMachine")   return "authMachineIdentity";
  if (prefix === "inlineMachine") return "inlineMachineIdentity";
  return prefix + "Identity";
}
function _prefixCaCertId(prefix) {
  return prefix.startsWith("auth") ? "authCaCert" : "inlineCaCert";
}

// opts: { existingCert, existingKey, cn } — override what's read from auth
function renderCertSourcePanel(prefix, auth, isFullDrawer, opts = {}) {
  const existingCert = ("existingCert" in opts) ? (opts.existingCert || null) : ((auth && auth.client_cert) || null);
  const existingKey  = ("existingKey"  in opts) ? (opts.existingKey  || null) : ((auth && auth.private_key)  || null);
  const defaultCN    = ("cn" in opts) ? (opts.cn || "") : ((auth && auth.identity) || "");
  const defaultSource = (!existingCert && drawerLabCaExists) ? "labca" : "existing";

  const sources = isFullDrawer
    ? [
        { id: "existing", label: "Select Existing" },
        { id: "labca",    label: "Lab CA" },
        { id: "scep",     label: "SCEP / NDES" },
      ]
    : [
        { id: "existing", label: "Select Existing" },
        { id: "labca",    label: "Lab CA" },
      ];

  let html = `<div class="cert-source-tabs">`;
  sources.forEach((s) => {
    html += `<button type="button" class="cert-source-tab${s.id === defaultSource ? " active" : ""}" id="${prefix}SrcTab${s.id}" onclick="switchCertSource('${prefix}', '${s.id}')">${s.label}</button>`;
  });
  html += `</div>`;

  // Panel: Select Existing
  html += `<div class="cert-source-panel${defaultSource === "existing" ? " active" : ""}" id="${prefix}PanelExisting">`;
  html += certSelectHtml(`${prefix}ClientCert`, "Client certificate", existingCert, "cert");
  html += certSelectHtml(`${prefix}PrivateKey`, "Private key", existingKey, "key");
  html += `</div>`;

  // Panel: Lab CA
  html += `<div class="cert-source-panel${defaultSource === "labca" ? " active" : ""}" id="${prefix}PanelLabca">`;
  if (drawerLabCaExists) {
    html += `
      <div class="form-group">
        <label class="form-label">Common Name (CN)</label>
        <input type="text" class="form-input" id="${prefix}LabcaCN" value="${escapeHtml(defaultCN)}" placeholder="user@example.com">
        <span class="form-hint">Pre-filled from identity. Determines cert filename.</span>
      </div>
      <button type="button" class="btn btn-accent cert-generate-btn" id="${prefix}LabcaBtn" onclick="generateCertFromLabCA('${prefix}')">&#9889; Generate &amp; Select</button>
      <div class="cert-gen-result" id="${prefix}LabcaResult"></div>`;
  } else {
    html += `<div class="cert-source-unavail">No Lab CA found. <button type="button" class="btn-link" onclick="goToCertsTab()">Create one in the Certs tab &rarr;</button></div>`;
  }
  html += `</div>`;

  if (isFullDrawer) {
    const sscepOk = !!(drawerEnrollCaps && drawerEnrollCaps.sscep);
    const stepOk  = !!(drawerEnrollCaps && drawerEnrollCaps.step_cli);

    // Panel: SCEP
    html += `<div class="cert-source-panel${defaultSource === "scep" ? " active" : ""}" id="${prefix}PanelScep">`;
    if (sscepOk) {
      html += `
        <div class="form-group">
          <label class="form-label">NDES URL</label>
          <input type="text" class="form-input" id="${prefix}ScepUrl" placeholder="http://ndes-server/certsrv/mscep/mscep.dll">
        </div>
        <div class="form-group">
          <label class="form-label">Challenge Password</label>
          <div class="password-wrapper">
            <input type="password" class="form-input" id="${prefix}ScepChallenge" placeholder="NDES challenge password">
            <button type="button" class="password-toggle" onclick="togglePasswordVis('${prefix}ScepChallenge')">${EYE_ICON_SVG}</button>
          </div>
        </div>
        <div class="form-group">
          <label class="form-label">Common Name (CN)</label>
          <input type="text" class="form-input" id="${prefix}ScepCN" value="${escapeHtml(defaultCN)}" placeholder="user@corp.local">
        </div>
        <button type="button" class="btn btn-accent cert-generate-btn" id="${prefix}ScepBtn" onclick="generateCertFromSCEP('${prefix}')">&#9889; Enroll via SCEP</button>
        <div class="cert-gen-result" id="${prefix}ScepResult"></div>`;
    } else {
      html += `<div class="cert-source-unavail">&#9888; <strong>sscep</strong> not available in this container. Rebuild with sscep installed to enable SCEP enrollment.</div>`;
    }
    html += `</div>`;

    // Panel: step-ca
    html += `<div class="cert-source-panel${defaultSource === "stepca" ? " active" : ""}" id="${prefix}PanelStepca">`;
    if (stepOk) {
      html += `
        <div class="form-group">
          <label class="form-label">step-ca URL</label>
          <input type="text" class="form-input" id="${prefix}StepUrl" value="https://step-ca:9000" placeholder="https://step-ca:9000">
        </div>
        <div class="form-group">
          <label class="form-label">Provisioner</label>
          <input type="text" class="form-input" id="${prefix}StepProv" value="macforge" placeholder="macforge">
        </div>
        <div class="form-group">
          <label class="form-label">CA Fingerprint <span class="form-hint-inline">(optional)</span></label>
          <input type="text" class="form-input" id="${prefix}StepFP" placeholder="SHA-256 fingerprint">
        </div>
        <div class="form-group">
          <label class="form-label">Token <span class="form-hint-inline">(if required by provisioner)</span></label>
          <div class="password-wrapper">
            <input type="password" class="form-input" id="${prefix}StepToken" placeholder="JWT provisioner token">
            <button type="button" class="password-toggle" onclick="togglePasswordVis('${prefix}StepToken')">${EYE_ICON_SVG}</button>
          </div>
        </div>
        <div class="form-group">
          <label class="form-label">Common Name (CN)</label>
          <input type="text" class="form-input" id="${prefix}StepCN" value="${escapeHtml(defaultCN)}" placeholder="user@lab.local">
        </div>
        <button type="button" class="btn btn-accent cert-generate-btn" id="${prefix}StepBtn" onclick="generateCertFromStepCA('${prefix}')">&#9889; Enroll via step-ca</button>
        <div class="cert-gen-result" id="${prefix}StepResult"></div>`;
    } else {
      html += `<div class="cert-source-unavail">&#9888; <strong>step CLI</strong> not available in this container. Rebuild with step-cli installed to enable step-ca enrollment.</div>`;
    }
    html += `</div>`;
  }

  return html;
}

function switchCertSource(prefix, source) {
  const panelMap = { existing: "Existing", labca: "Labca", scep: "Scep", stepca: "Stepca" };
  Object.keys(panelMap).forEach((s) => {
    const tab   = document.getElementById(`${prefix}SrcTab${s}`);
    const panel = document.getElementById(`${prefix}Panel${panelMap[s]}`);
    if (tab)   tab.classList.toggle("active", s === source);
    if (panel) panel.classList.toggle("active", s === source);
  });
  // Sync CN from identity field when switching to a generate panel
  if (source !== "existing") {
    const identityId = _prefixIdentityId(prefix);
    const identity = document.getElementById(identityId)?.value?.trim() || "";
    if (identity) {
      const cnIdMap = { labca: `${prefix}LabcaCN`, scep: `${prefix}ScepCN`, stepca: `${prefix}StepCN` };
      const cnEl = document.getElementById(cnIdMap[source]);
      if (cnEl && !cnEl.value) cnEl.value = identity;
    }
  }
}

async function _afterCertGenerated(prefix, certFile, keyFile) {
  certCache = await fetchJSON("/api/certs");
  // Re-render existing panel with the new cert pre-selected
  const existingPanel = document.getElementById(`${prefix}PanelExisting`);
  if (existingPanel) {
    existingPanel.innerHTML =
      certSelectHtml(`${prefix}ClientCert`, "Client certificate", certFile, "cert") +
      certSelectHtml(`${prefix}PrivateKey`, "Private key", keyFile, "key");
  }
  // Also refresh the CA cert select in the Server Validation section
  const caCertId = _prefixCaCertId(prefix);
  const caEl = document.getElementById(caCertId);
  if (caEl) {
    const currentVal = caEl.value;
    const certFiles = filterCertFiles("cert");
    const opts = certFiles.map(
      (c) => `<option value="${escapeHtml(c.filename)}" ${c.filename === currentVal ? "selected" : ""}>${escapeHtml(c.filename)}</option>`
    );
    caEl.innerHTML = `<option value="">-- none --</option>${opts.join("")}`;
  }
  switchCertSource(prefix, "existing");
}

async function generateCertFromLabCA(prefix) {
  const cnEl  = document.getElementById(`${prefix}LabcaCN`);
  const btn   = document.getElementById(`${prefix}LabcaBtn`);
  const result = document.getElementById(`${prefix}LabcaResult`);
  const cn = cnEl?.value.trim();
  if (!cn) { showToast("Enter a Common Name (CN) for the certificate.", "error"); return; }
  if (btn) { btn.disabled = true; btn.textContent = "Generating\u2026"; }
  if (result) result.innerHTML = `<span class="cert-gen-loading">Generating certificate\u2026</span>`;
  try {
    const data = await fetchJSON("/api/pki/generate-client", {
      method: "POST",
      body: JSON.stringify({ cn }),
    });
    await _afterCertGenerated(prefix, data.cert_file, data.key_file);
    // Auto-select lab-ca.pem as CA cert since we just signed with it
    const caCertId = _prefixCaCertId(prefix);
    const caEl = document.getElementById(caCertId);
    if (caEl && certCache.some((c) => c.filename === "lab-ca.pem")) {
      caEl.value = "lab-ca.pem";
    }
    showToast(`Generated: ${data.cert_file}`, "success");
  } catch (err) {
    if (result) result.innerHTML = `<div class="cert-gen-error">${escapeHtml(err.message)}</div>`;
    showToast("Generation failed: " + err.message, "error");
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "\u26A1 Generate & Select"; }
  }
}

async function generateCertFromSCEP(prefix) {
  const url       = document.getElementById(`${prefix}ScepUrl`)?.value.trim();
  const challenge = document.getElementById(`${prefix}ScepChallenge`)?.value || "";
  const cn        = document.getElementById(`${prefix}ScepCN`)?.value.trim();
  const btn    = document.getElementById(`${prefix}ScepBtn`);
  const result = document.getElementById(`${prefix}ScepResult`);
  if (!url || !cn) { showToast("NDES URL and CN are required.", "error"); return; }
  if (btn) { btn.disabled = true; btn.textContent = "Enrolling\u2026"; }
  if (result) result.innerHTML = `<span class="cert-gen-loading">Contacting NDES\u2026</span>`;
  try {
    const data = await fetchJSON("/api/pki/enroll-scep", {
      method: "POST",
      body: JSON.stringify({ ndes_url: url, challenge, cn }),
    });
    await _afterCertGenerated(prefix, data.cert_file, data.key_file);
    // Auto-select the SCEP CA cert in Server Validation if returned
    if (data.ca_file) {
      const caCertId = prefix === "auth" ? "authCaCert" : "inlineCaCert";
      const caEl = document.getElementById(caCertId);
      if (caEl) caEl.value = data.ca_file;
    }
    showToast(`SCEP enrolled: ${data.cert_file}`, "success");
  } catch (err) {
    if (result) result.innerHTML = `<div class="cert-gen-error">${escapeHtml(err.message)}</div>`;
    showToast("SCEP enrollment failed: " + err.message, "error");
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "\u26A1 Enroll via SCEP"; }
  }
}

async function generateCertFromStepCA(prefix) {
  const caUrl = document.getElementById(`${prefix}StepUrl`)?.value.trim();
  const prov  = document.getElementById(`${prefix}StepProv`)?.value.trim() || "macforge";
  const fp    = document.getElementById(`${prefix}StepFP`)?.value.trim();
  const token = document.getElementById(`${prefix}StepToken`)?.value;
  const cn    = document.getElementById(`${prefix}StepCN`)?.value.trim();
  const btn    = document.getElementById(`${prefix}StepBtn`);
  const result = document.getElementById(`${prefix}StepResult`);
  if (!caUrl || !cn) { showToast("step-ca URL and CN are required.", "error"); return; }
  if (btn) { btn.disabled = true; btn.textContent = "Enrolling\u2026"; }
  if (result) result.innerHTML = `<span class="cert-gen-loading">Contacting step-ca\u2026</span>`;
  try {
    const data = await fetchJSON("/api/pki/enroll-step-ca", {
      method: "POST",
      body: JSON.stringify({ ca_url: caUrl, cn, provisioner: prov, ca_fingerprint: fp || null, token: token || null }),
    });
    await _afterCertGenerated(prefix, data.cert_file, data.key_file);
    showToast(`Enrolled: ${data.cert_file}`, "success");
  } catch (err) {
    if (result) result.innerHTML = `<div class="cert-gen-error">${escapeHtml(err.message)}</div>`;
    showToast("step-ca enrollment failed: " + err.message, "error");
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "\u26A1 Enroll via step-ca"; }
  }
}

function renderDrawerBody(auth) {
  const method = (auth && auth.method) || "peap-mschapv2";
  const isTeap = method === "teap";
  const teapInner = isTeap ? ((auth && auth.teap_inner_method) || "MSCHAPV2") : "";
  const needsPassword = ["peap-mschapv2", "peap", "eap-fast", "fast", "eap-ttls", "ttls"].includes(method)
    || (isTeap && (teapInner === "MSCHAPV2" || teapInner === "Chained"));
  // Chained uses machine cert (not a user cert) — user side is MSCHAPv2 password
  const needsCerts = method === "eap-tls" || (isTeap && teapInner === "EAP-TLS");
  const isEapFast = ["eap-fast", "fast"].includes(method);
  const isTeapChained = isTeap && teapInner === "Chained";

  let html = "";

  html += '<div class="form-section"><div class="form-section-title">EAP Method</div>';
  html += '<div class="form-group"><label class="form-label">Method</label>';
  html += '<select class="form-select" id="authMethod">';
  EAP_METHODS.forEach((m) => {
    html += `<option value="${m.value}" ${m.value === method ? "selected" : ""}>${m.label}</option>`;
  });
  html += "</select></div>";

  // TEAP warning banner — ISE 3.1+ requirement and security callout
  if (isTeap) {
    html += `<div class="teap-warning-banner">
      <strong>&#9888; Cisco ISE 3.1+ required.</strong>
      TEAP uses TLS 1.3-capable tunnel with TLV objects — more secure than PEAP or EAP-FAST.
      For chained auth, add a Compound Condition in ISE:
      <em>EapChainingResult = User and Machine both Succeeded</em>.
      <button type="button" class="btn-link" onclick="document.getElementById('authMethod').value='peap-mschapv2'; document.getElementById('authMethod').dispatchEvent(new Event('change'))">Use PEAP instead &rarr;</button>
    </div>`;
  }

  // TEAP inner method selector
  if (isTeap) {
    html += '<div class="form-section"><div class="form-section-title">TEAP Inner Method</div>';
    html += '<div class="form-group"><label class="form-label">Inner authentication</label>';
    html += '<select class="form-select" id="authTeapInner">';
    [["MSCHAPV2", "MSCHAPv2 (username + password)"], ["EAP-TLS", "EAP-TLS (user certificate)"], ["Chained", "Chained (machine cert \u2295 user password)"]].forEach(([val, lbl]) => {
      html += `<option value="${val}" ${teapInner === val ? "selected" : ""}>${lbl}</option>`;
    });
    html += '</select></div>';
    html += '<span class="form-hint">PAC-less — no PAC file needed. wpa_supplicant ≥ 2.10 required.</span>';
    html += '</div>';
  }

  html += '</div>';

  html += '<div class="form-section"><div class="form-section-title">Identity</div>';
  html += `<div class="form-group"><label class="form-label">Identity (username)</label>
    <input type="text" class="form-input" id="authIdentity" value="${escapeHtml((auth && auth.identity) || "")}" placeholder="user@example.com"
      title="PEAP/TTLS/FAST: username sent inside the encrypted tunnel.&#10;EAP-TLS: ignored by ISE — the client certificate CN is used as the identity instead. Leave blank or match the cert CN."></div>`;
  html += `<div class="form-group"><label class="form-label">Anonymous identity (outer)</label>
    <input type="text" class="form-input" id="authAnonIdentity" value="${escapeHtml((auth && auth.anonymous_identity) || "")}" placeholder="anonymous@example.com"
      title="Sent unencrypted in the outer EAP-Response/Identity exchange before the TLS tunnel forms. Hides the real username from passive observers. Leave blank in lab environments."></div>`;
  html += renderAuthTypeField(method, teapInner, auth, "authType");
  html += "</div>";

  if (needsPassword) {
    html += '<div class="form-section"><div class="form-section-title">Credentials</div>';
    html += passwordField("authPassword", "Password", auth && auth.password, "Enter password");
    if (!isTeap) {
      html += `<div class="form-group"><label class="form-label">Phase 2 (inner method)</label>
        <select class="form-select" id="authPhase2">`;
      PHASE2_OPTIONS.forEach((p) => {
        html += `<option value="${p}" ${(auth && auth.phase2 === p) ? "selected" : (p === "MSCHAPV2" && !auth ? "selected" : "")}>${p}</option>`;
      });
      html += "</select></div>";

      if (method.startsWith("peap")) {
        html += `<div class="form-group"><label class="form-label">PEAP version</label>
          <select class="form-select" id="authPeapVer">
            <option value="0" ${(!auth || auth.peap_version === 0) ? "selected" : ""}>0 (default)</option>
            <option value="1" ${(auth && auth.peap_version === 1) ? "selected" : ""}>1</option>
          </select></div>`;
      }
    }
    html += "</div>";
  }

  if (needsCerts) {
    const certSectionTitle = isTeapChained ? "User Certificate (Chained)" : "Certificates";
    html += `<div class="form-section"><div class="form-section-title">${certSectionTitle}</div>`;
    html += renderCertSourcePanel("auth", auth, true);
    html += passwordField("authKeyPassword", "Private key password", auth && auth.private_key_password, "Leave blank if unencrypted");
    html += `<span class="form-hint">&#9432; EAP-TLS: ISE validates the <strong>client cert</strong> using whichever CA is in ISE\'s Trusted Certificates store (Administration → System → Certificates → Trusted Certificates). That CA must have <em>Trust for client authentication and Syslog</em> checked, not just <em>Trust for authentication within ISE</em>.</span>`;
    html += "</div>";
  }

  // Machine Identity section — only shown for TEAP Chained
  if (isTeapChained) {
    html += '<div class="form-section teap-machine-section">';
    html += '<div class="form-section-title">&#128274; Machine Certificate (Chained)</div>';
    html += '<span class="form-hint" style="display:block;margin-bottom:10px">The machine cert authenticates the device via the outer TEAP TLS handshake. ISE evaluates both the machine cert and user MSCHAPv2 via a Compound Condition (EapChainingResult). The CN below is used for cert generation only — it is not sent as a separate identity field.</span>';
    html += `<div class="form-group"><label class="form-label">Machine CN <span class="form-hint-inline">(for cert generation)</span></label>
      <input type="text" class="form-input" id="authMachineIdentity" value="${escapeHtml((auth && auth.machine_identity) || "")}" placeholder="WIN11-LAB.example.com"></div>`;
    html += renderCertSourcePanel("authMachine", auth, true, {
      existingCert: auth && auth.machine_cert,
      existingKey:  auth && auth.machine_key,
      cn: (auth && auth.machine_identity) || "",
    });
    html += passwordField("authMachineKeyPass", "Machine key password", auth && auth.machine_key_password, "Leave blank if unencrypted");
    html += "</div>";
  }

  if (isEapFast) {
    html += '<div class="form-section"><div class="form-section-title">EAP-FAST</div>';
    html += `<div class="form-group form-toggle"><label class="form-label">PAC auto-provisioning</label>
      <label class="toggle-switch"><input type="checkbox" id="authPacProv" ${(auth && auth.pac_provisioning) ? "checked" : ""}>
      <span class="toggle-slider"></span></label></div>`;
    html += certSelectHtml("authPacFile", "PAC file", auth && auth.pac_file, "pac");
    html += "</div>";
  }

  html += '<div class="form-section"><div class="form-section-title">Server Validation</div>';
  html += certSelectHtml("authCaCert", "CA certificate", auth && auth.ca_cert, "cert");
  html += `<span class="form-hint">The CA that signed ISE\'s RADIUS server cert. Only needed when Validate server certificate is on. For EAP-TLS this is NOT the CA that signed your client cert — that CA must be in ISE\'s Trusted Certificates with \"Trust for client authentication\" checked.</span>`;
  html += `<div class="form-group form-toggle"><label class="form-label">Validate server certificate</label>
    <label class="toggle-switch"><input type="checkbox" id="authValidateCert" ${(auth && auth.validate_server_cert) ? "checked" : ""}
      title="When on, wpa_supplicant verifies the ISE RADIUS server certificate against the CA cert above. Turn off in lab environments where ISE uses a self-signed cert not issued by your lab CA.">
    <span class="toggle-slider"></span></label></div>`;
  html += "</div>";

  html += '<div class="form-section"><div class="form-section-title">Advanced</div>';
  html += `<div class="form-group"><label class="form-label">EAPOL version</label>
    <select class="form-select" id="authEapolVer">
      <option value="1" ${(auth && auth.eapol_version === 1) ? "selected" : ""}>1</option>
      <option value="2" ${(!auth || auth.eapol_version === 2) ? "selected" : ""}>2 (default)</option>
    </select></div>`;
  html += `<div class="form-group"><label class="form-label">Fragment size</label>
    <input type="number" class="form-input" id="authFragSize" value="${(auth && auth.fragment_size) || 1398}" min="500" max="4096"></div>`;
  html += `<div class="form-group form-toggle"><label class="form-label">Fast reconnect (TLS session cache)</label>
    <label class="toggle-switch"><input type="checkbox" id="authFastReconn" ${(!auth || auth.fast_reconnect) ? "checked" : ""}>
    <span class="toggle-slider"></span></label></div>`;
  html += "</div>";

  return html;
}

function bindMethodChange() {
  // Re-render only the 802.1X panel, NOT the whole configDrawerBody.
  // Replacing configDrawerBody.innerHTML destroys #configDevicePanel and
  // #configDot1xPanel, causing the Device tab button to do nothing.
  const rerenderDot1xPanel = () => {
    const fakeAuth = collectAuthForm();
    const panel = document.getElementById("configDot1xPanel");
    const target = panel || document.getElementById("configDrawerBody");
    if (!target) return;
    target.innerHTML = renderDrawerBody(fakeAuth);
    // Reattach dirty tracking on the freshly rendered inputs
    if (panel) {
      panel.querySelectorAll("input, select, textarea").forEach((el) => {
        el.addEventListener("change", () => { configAuthDirty = true; });
        el.addEventListener("input",  () => { configAuthDirty = true; });
      });
    }
    bindMethodChange(); // re-bind on the new DOM
  };

  const methodSelect = document.getElementById("authMethod");
  if (methodSelect) methodSelect.addEventListener("change", rerenderDot1xPanel);

  // Also listen for TEAP inner method changes so the Machine Identity
  // section appears/disappears when switching e.g. MSCHAPv2 ↔ Chained
  const teapInnerSelect = document.getElementById("authTeapInner");
  if (teapInnerSelect) teapInnerSelect.addEventListener("change", rerenderDot1xPanel);
}

/* ─── Certificates Tab: Inner Tabs ─────────────────────────────────── */

function switchCertTab(tabName) {
  document.querySelectorAll(".cert-tab").forEach((t) => {
    t.classList.toggle("active", t.dataset.certtab === tabName);
  });
  document.querySelectorAll(".cert-tab-pane").forEach((p) => {
    p.classList.toggle("active", p.id === `certtab-${tabName}`);
  });
}

/* ─── Integration Accordion Toggle ─────────────────────────────────── */

function toggleIntegration(id) {
  const body = document.getElementById(id + "Body");
  const chevron = document.getElementById(id + "Chevron");
  if (!body) return;
  const isOpen = body.style.display !== "none";
  body.style.display = isOpen ? "none" : "";
  if (chevron) chevron.classList.toggle("open", !isOpen);
}

/* ─── Certificates Tab: Lab CA ─────────────────────────────────────── */

async function refreshLabCaStatus() {
  const container = document.getElementById("labCaStatus");
  if (!container) return;
  try {
    const data = await fetchJSON("/api/pki/lab-ca");
    if (data.exists && data.info) {
      const i = data.info;
      container.innerHTML = `
        <div class="pki-status-ok">
          <strong>Lab CA Active</strong>
          <div class="pki-status-grid">
            <span class="detail-label">CN</span><span class="detail-value">${escapeHtml(i.cn || "")}</span>
            <span class="detail-label">Expires</span><span class="detail-value">${escapeHtml(i.not_after || "")}</span>
            <span class="detail-label">SHA-256</span><span class="detail-value" style="font-size:10px">${escapeHtml((i.fingerprint || "").substring(0, 40))}...</span>
          </div>
          <div style="display:flex;gap:8px;margin-top:10px">
            <a class="btn btn-sm btn-section-connect" href="/api/certs/lab-ca.pem/download" download>Download CA</a>
            <a class="btn btn-sm btn-section-connect" href="/api/certs/lab-ca.key/download" download>Download Key</a>
          </div>
        </div>`;
      const genBtn = document.getElementById("labCaGenerateBtn");
      if (genBtn) genBtn.textContent = "Regenerate";
    } else {
      container.innerHTML = '<div class="labca-status-empty">No Lab CA generated. Create one below to start issuing client certificates.</div>';
      const genBtn = document.getElementById("labCaGenerateBtn");
      if (genBtn) genBtn.textContent = "Generate Lab CA";
    }
  } catch (err) {
    container.innerHTML = `<div class="pki-status-error">Error: ${escapeHtml(err.message)}</div>`;
  }
}

async function generateLabCA() {
  const cn = document.getElementById("labCaCN")?.value.trim() || "MACforge Lab CA";
  const org = document.getElementById("labCaOrg")?.value.trim() || "MACforge Lab";
  const btn = document.getElementById("labCaGenerateBtn");
  if (btn) btn.disabled = true;
  try {
    const result = await fetchJSON("/api/pki/generate-ca", {
      method: "POST",
      body: JSON.stringify({ cn, org }),
    });
    showToast("Lab CA generated successfully", "success");
    await refreshLabCaStatus();
    await refreshCertTable();
  } catch (err) {
    showToast("CA generation failed: " + err.message, "error");
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function generateClientCert() {
  const cn = document.getElementById("clientCertCN")?.value.trim();
  const san = document.getElementById("clientCertSAN")?.value.trim();
  const resultEl = document.getElementById("clientCertResult");
  if (!cn) { showToast("Enter a CN (identity) for the client cert.", "error"); return; }
  try {
    const data = await fetchJSON("/api/pki/generate-client", {
      method: "POST",
      body: JSON.stringify({ cn, san: san || null }),
    });
    if (resultEl) {
      resultEl.innerHTML = `<div class="pki-result-ok">Created: <strong>${escapeHtml(data.cert_file)}</strong> + <strong>${escapeHtml(data.key_file)}</strong>
        <br>Signed by: ${escapeHtml(data.issuer_cn || "")} &middot; Expires: ${escapeHtml(data.not_after || "")}</div>`;
    }
    showToast("Client certificate generated", "success");
    await refreshCertTable();
  } catch (err) {
    if (resultEl) resultEl.innerHTML = `<div class="pki-result-error">${escapeHtml(err.message)}</div>`;
    showToast("Client cert generation failed: " + err.message, "error");
  }
}

async function generateCSR() {
  const cn = document.getElementById("csrCN")?.value.trim();
  const san = document.getElementById("csrSAN")?.value.trim();
  const resultEl = document.getElementById("csrResult");
  if (!cn) { showToast("Enter a CN (identity) for the CSR.", "error"); return; }
  try {
    const data = await fetchJSON("/api/pki/generate-csr", {
      method: "POST",
      body: JSON.stringify({ cn, san: san || null }),
    });
    if (resultEl) {
      resultEl.innerHTML = `<div class="pki-result-ok">Created: <strong>${escapeHtml(data.csr_file)}</strong> + <strong>${escapeHtml(data.key_file)}</strong>
        <br><a class="btn btn-sm btn-section-connect" href="/api/certs/${encodeURIComponent(data.csr_file)}/download" download>Download CSR</a>
        <span class="form-hint" style="margin-top:6px">Get this CSR signed by your CA, then upload the signed cert via Certificate Store above.</span></div>`;
    }
    showToast("CSR generated", "success");
    await refreshCertTable();
  } catch (err) {
    if (resultEl) resultEl.innerHTML = `<div class="pki-result-error">${escapeHtml(err.message)}</div>`;
    showToast("CSR generation failed: " + err.message, "error");
  }
}

/* ─── Certificates Tab: ISE Integration ────────────────────────────── */

async function loadISEConfig() {
  const hostEl = document.getElementById("iseHostname");
  if (!hostEl) return;
  try {
    const data = await fetchJSON("/api/ise/config");
    hostEl.value = data.hostname || "";
    const userEl = document.getElementById("iseUsername");
    if (userEl) userEl.value = data.username || "";
    const passEl = document.getElementById("isePassword");
    if (passEl) passEl.value = "";
    const tlsEl = document.getElementById("iseVerifyTls");
    if (tlsEl) tlsEl.checked = data.verify_tls || false;
    const statusEl = document.getElementById("iseBarStatus");
    if (statusEl) {
      statusEl.textContent = data.hostname ? `Configured: ${data.hostname}` : "";
    }
    iseConfigured = !!(data.hostname && data.username);

  } catch (_) {}
}

async function saveISEConfig() {
  const hostname = document.getElementById("iseHostname")?.value.trim();
  const username = document.getElementById("iseUsername")?.value.trim();
  const password = document.getElementById("isePassword")?.value;
  const verify = document.getElementById("iseVerifyTls")?.checked || false;
  try {
    await fetchJSON("/api/ise/config", {
      method: "PUT",
      body: JSON.stringify({ hostname, username, password, verify_tls: verify }),
    });
    showToast("ISE settings saved", "success");
    await loadISEConfig();  // refresh iseConfigured so CoA buttons appear immediately
  } catch (err) {
    showToast("Failed to save ISE config: " + err.message, "error");
  }
}

async function testISEConnection() {
  const statusEl = document.getElementById("iseStatus");
  const barStatusEl = document.getElementById("iseBarStatus");
  if (statusEl) statusEl.innerHTML = '<div class="pki-status-loading">Testing connection...</div>';
  showToast("Testing ISE connection...", "info");
  try {
    const data = await fetchJSON("/api/ise/test", { method: "POST" });
    if (data.status === "ok") {
      showToast("ISE connection successful", "success");
      if (statusEl) statusEl.innerHTML = `<div class="pki-result-ok">${escapeHtml(data.message)}</div>`;
      if (barStatusEl) barStatusEl.textContent = "Connected";
    } else {
      showToast("ISE connection failed: " + (data.message || "Unknown error"), "error");
      if (statusEl) statusEl.innerHTML = `<div class="pki-result-error">${escapeHtml(data.message)}${data.detail ? '<br><small>' + escapeHtml(data.detail) + '</small>' : ''}</div>`;
      if (barStatusEl) barStatusEl.textContent = "Connection failed";
    }
  } catch (err) {
    showToast("ISE test failed: " + err.message, "error");
    if (statusEl) statusEl.innerHTML = `<div class="pki-result-error">${escapeHtml(err.message)}</div>`;
    if (barStatusEl) barStatusEl.textContent = "Error";
  }
}

async function pushCAtoISE() {
  const statusEl = document.getElementById("iseStatus");
  if (statusEl) statusEl.innerHTML = '<div class="pki-status-loading">Pushing CA cert to ISE...</div>';
  showToast("Pushing Lab CA to ISE...", "info");
  // Use the actual cert CN as the description so ISE reflects the real CA identity.
  let caCN = "MACforge Lab CA";
  try {
    const caInfo = await fetchJSON("/api/pki/lab-ca");
    if (caInfo.exists && caInfo.info?.cn) caCN = caInfo.info.cn;
  } catch (_) {}
  try {
    const data = await fetchJSON("/api/ise/push-ca", {
      method: "POST",
      body: JSON.stringify({ cert_filename: "lab-ca.pem", description: caCN }),
    });
    if (data.status === "ok") {
      showToast("Lab CA pushed to ISE successfully", "success");
      if (statusEl) statusEl.innerHTML = `<div class="pki-result-ok">${escapeHtml(data.message)}</div>`;
    } else {
      showToast("Push failed: " + (data.message || "Unknown error"), "error");
      if (statusEl) statusEl.innerHTML = `<div class="pki-result-error">${escapeHtml(data.message)}</div>`;
    }
  } catch (err) {
    showToast("Push failed: " + err.message, "error");
    if (statusEl) statusEl.innerHTML = `<div class="pki-result-error">${escapeHtml(err.message)}</div>`;
  }
}

/* ─── Certificates Tab: Enterprise Enrollment ──────────────────────── */

async function loadEnrollmentCaps() {
  const el = document.getElementById("enrollCaps");
  if (!el) return;
  try {
    const caps = await fetchJSON("/api/pki/enrollment-capabilities");
    // sscep + openssl are required for SCEP/NDES. step CLI is only for the step-ca alternative.
    const scepReady = caps.sscep && caps.openssl;
    if (scepReady) {
      el.innerHTML = `<span class="pki-caps-label">\u2705 SCEP/NDES enrollment ready</span>`;
    } else {
      const missing = [!caps.sscep && "sscep", !caps.openssl && "openssl"].filter(Boolean).join(" and ");
      el.innerHTML = `<span class="pki-caps-label">\u26a0\ufe0f <strong>${missing}</strong> not found in this container \u2014 SCEP/NDES enrollment requires both. Rebuild with sscep installed to enable this. The step-ca alternative below does not require sscep.</span>`;
    }
  } catch (_) {
    el.innerHTML = "";
  }
}

async function loadNDESConfig() {
  try {
    const data = await fetchJSON("/api/pki/ndes-config");
    const urlEl = document.getElementById("ndesConfigUrl");
    if (urlEl && data.ndes_url) urlEl.value = data.ndes_url;

    const barStatusEl = document.getElementById("ndesBarStatus");
    if (barStatusEl) {
      barStatusEl.textContent = data.ndes_url
        ? `Configured: ${data.ndes_url}${data.challenge_saved ? " · challenge saved" : ""}`
        : "";
    }

    // Pre-fill the enrollment form fields only when they are currently empty
    if (data.ndes_url) {
      const scepUrlEl = document.getElementById("scepUrl");
      if (scepUrlEl && !scepUrlEl.value) scepUrlEl.value = data.ndes_url;
    }
  } catch (_) {}
}

async function saveNDESConfig() {
  const url = document.getElementById("ndesConfigUrl")?.value.trim();
  const challenge = document.getElementById("ndesConfigChallenge")?.value || "";
  try {
    await fetchJSON("/api/pki/ndes-config", {
      method: "PUT",
      body: JSON.stringify({ ndes_url: url, challenge }),
    });
    showToast("NDES settings saved", "success");
    document.getElementById("ndesConfigChallenge").value = "";  // clear after save
    await loadNDESConfig();
  } catch (err) {
    showToast("Failed to save NDES config: " + err.message, "error");
  }
}

async function testNDESConfig() {
  const url = document.getElementById("ndesConfigUrl")?.value.trim();
  if (!url) { showToast("Enter an NDES URL first.", "error"); return; }
  const resultEl = document.getElementById("ndesConfigResult");
  if (resultEl) resultEl.innerHTML = '<div class="pki-status-loading">Testing NDES…</div>';
  try {
    const data = await fetchJSON("/api/pki/test-ndes", {
      method: "POST",
      body: JSON.stringify({ ndes_url: url }),
    });
    if (resultEl) resultEl.innerHTML = `<div class="pki-result-ok">&#10003; NDES reachable &mdash; ${escapeHtml(data.message)}</div>`;
    showToast("NDES reachable", "success");
  } catch (err) {
    if (resultEl) resultEl.innerHTML = `<div class="pki-result-error">&#10007; ${escapeHtml(err.message)}</div>`;
    showToast("NDES test failed: " + err.message, "error");
  }
}

async function testNDES() {
  const url = document.getElementById("scepUrl")?.value.trim();
  if (!url) { showToast("Enter an NDES URL first.", "error"); return; }
  const resultEl = document.getElementById("scepResult");
  if (resultEl) resultEl.innerHTML = '<div class="pki-status-loading">Testing NDES…</div>';
  try {
    const data = await fetchJSON("/api/pki/test-ndes", {
      method: "POST",
      body: JSON.stringify({ ndes_url: url }),
    });
    if (resultEl) resultEl.innerHTML = `<div class="pki-result-ok">✅ NDES reachable &mdash; ${escapeHtml(data.message)}</div>`;
    showToast("NDES reachable", "success");
  } catch (err) {
    if (resultEl) resultEl.innerHTML = `<div class="pki-result-error">❌ ${escapeHtml(err.message)}</div>`;
    showToast("NDES test failed: " + err.message, "error");
  }
}

async function enrollSCEP() {
  const resultEl = document.getElementById("scepResult");
  const url = document.getElementById("scepUrl")?.value.trim();
  const challenge = document.getElementById("scepChallenge")?.value;
  const cn = document.getElementById("scepCN")?.value.trim();
  const san = document.getElementById("scepSAN")?.value.trim() || null;
  if (!url || !cn) { showToast("NDES URL and CN are required.", "error"); return; }
  if (resultEl) resultEl.innerHTML = '<div class="pki-status-loading">Enrolling via SCEP…</div>';
  showToast("SCEP enrollment in progress...", "info");
  try {
    const data = await fetchJSON("/api/pki/enroll-scep", {
      method: "POST",
      body: JSON.stringify({ ndes_url: url, challenge: challenge || "", cn, san }),
    });
    showToast("SCEP enrollment successful", "success");
    if (resultEl) resultEl.innerHTML = `<div class="pki-result-ok">${escapeHtml(data.message)}<br>Cert: <strong>${escapeHtml(data.cert_file)}</strong></div>`;
    await refreshCertTable();
  } catch (err) {
    showToast("SCEP enrollment failed: " + err.message, "error");
    if (resultEl) resultEl.innerHTML = `<div class="pki-result-error">${escapeHtml(err.message)}</div>`;
  }
}

async function enrollStepCA() {
  const resultEl = document.getElementById("stepCaResult");
  const caUrl = document.getElementById("stepCaUrl")?.value.trim();
  const prov = document.getElementById("stepCaProv")?.value.trim() || "macforge";
  const fp = document.getElementById("stepCaFP")?.value.trim();
  const cn = document.getElementById("stepCaCN")?.value.trim();
  if (!caUrl || !cn) { showToast("step-ca URL and CN are required.", "error"); return; }
  if (resultEl) resultEl.innerHTML = '<div class="pki-status-loading">Enrolling...</div>';
  showToast("step-ca enrollment in progress...", "info");
  try {
    const data = await fetchJSON("/api/pki/enroll-step-ca", {
      method: "POST",
      body: JSON.stringify({
        ca_url: caUrl, cn, provisioner: prov,
        ca_fingerprint: fp || null,
      }),
    });
    showToast("step-ca enrollment successful", "success");
    if (resultEl) resultEl.innerHTML = `<div class="pki-result-ok">${escapeHtml(data.message)}<br>Cert: <strong>${escapeHtml(data.cert_file)}</strong></div>`;
    await refreshCertTable();
  } catch (err) {
    showToast("step-ca enrollment failed: " + err.message, "error");
    if (resultEl) resultEl.innerHTML = `<div class="pki-result-error">${escapeHtml(err.message)}</div>`;
  }
}

/* ─── Certificate Store (file management) ──────────────────────────── */

function certTypeBadgeClass(type) {
  const t = (type || "").toLowerCase();
  if (t.includes("key")) return "key";
  if (t.includes("ca")) return "ca";
  return "";
}

function formatFileSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  return `${(bytes / 1024).toFixed(1)} KB`;
}

async function refreshCertTable() {
  try {
    certCache = await fetchJSON("/api/certs");
  } catch (_) {
    certCache = [];
  }
  const container = document.getElementById("certTableBody");
  const countEl = document.getElementById("tabCertCount");
  if (countEl) countEl.textContent = certCache.length;

  if (!container) return;

  if (certCache.length === 0) {
    container.innerHTML = '<tr><td colspan="4" class="cert-table-empty">No certificates or keys stored yet.</td></tr>';
    return;
  }
  container.innerHTML = certCache
    .map(
      (c) => `<tr>
        <td><span class="cert-filename">${escapeHtml(c.filename)}</span></td>
        <td><span class="cert-type-badge ${certTypeBadgeClass(c.type)}">${escapeHtml(c.type)}</span></td>
        <td class="cert-size">${formatFileSize(c.size)}</td>
        <td class="cert-td-actions">
          <a class="cert-action-link" href="/api/certs/${encodeURIComponent(c.filename)}/download" download title="Download">Download</a>
          <button class="cert-action-link" onclick="showCertInfo('${escapeHtml(c.filename)}')" title="Info">Info</button>
          <button class="cert-action-link danger" onclick="deleteCert('${escapeHtml(c.filename)}')" title="Delete">Delete</button>
        </td>
      </tr>`
    )
    .join("");
}

async function uploadCertFile(file) {
  const formData = new FormData();
  formData.append("file", file);
  try {
    const res = await fetch(API + "/api/certs/upload", { method: "POST", body: formData });
    if (!res.ok) throw new Error("Upload failed");
    showToast(`Uploaded ${file.name}`, "success");
    await refreshCertTable();
  } catch (err) {
    showToast("Upload failed: " + err.message, "error");
  }
}

async function savePastedPem() {
  const content = document.getElementById("pemTextarea").value.trim();
  const filename = document.getElementById("pemFilename").value.trim();
  if (!content) {
    showToast("Paste PEM content into the text area first.", "error");
    return;
  }
  if (!filename) {
    showToast("Enter a filename (e.g. client.pem or my-key.key).", "error");
    return;
  }
  try {
    await fetchJSON("/api/certs/paste", {
      method: "POST",
      body: JSON.stringify({ filename, content }),
    });
    document.getElementById("pemTextarea").value = "";
    document.getElementById("pemFilename").value = "";
    showToast(`Saved ${filename}`, "success");
    await refreshCertTable();
  } catch (err) {
    showToast("Save failed: " + err.message, "error");
  }
}

async function deleteCert(filename) {
  if (!confirm(`Delete ${filename}?`)) return;
  try {
    await fetchJSON(`/api/certs/${encodeURIComponent(filename)}`, { method: "DELETE" });
    await refreshCertTable();
    await refreshLabCaStatus();
    showToast(`Deleted ${filename}`, "success");
  } catch (err) {
    showToast("Delete failed: " + err.message, "error");
  }
}

async function showCertInfo(filename) {
  try {
    const info = await fetchJSON(`/api/certs/${encodeURIComponent(filename)}/info`);
    if (info.type === "not_a_certificate" || info.type === "parse_error") {
      showToast(`${filename}: ${info.detail || "Not a PEM certificate"}`, "info");
      return;
    }
    const lines = [
      `File: ${info.filename}`,
      `Type: ${info.type}`,
      `CN: ${info.cn || "N/A"}`,
      `Issuer: ${info.issuer_cn || "N/A"}`,
      `Valid: ${info.not_before || ""} — ${info.not_after || ""}`,
      `Key Size: ${info.key_size || "N/A"} bits`,
      `Fingerprint (SHA-256): ${info.fingerprint || "N/A"}`,
      `CA: ${info.is_ca ? "Yes" : "No"}`,
      `Self-signed: ${info.is_self_signed ? "Yes" : "No"}`,
    ];
    alert(lines.join("\n"));
  } catch (err) {
    showToast("Could not parse certificate: " + err.message, "error");
  }
}

/* ─── Event Listeners ─────────────────────────────────────────────── */

function bindEl(id, event, handler) {
  const el = document.getElementById(id);
  if (el) el.addEventListener(event, handler);
}

bindEl("connectAllBtn", "click", connectAll);
bindEl("disconnectAllBtn", "click", disconnectAll);
bindEl("snmpToggle", "change", toggleSNMP);

bindEl("configDrawerClose", "click", closeConfigDrawer);
const configOv = document.getElementById("configOverlay");
if (configOv) configOv.addEventListener("click", (e) => { if (e.target === configOv) closeConfigDrawer(); });
bindEl("configDrawerSave", "click", saveConfigDrawer);
bindEl("configDrawerDelete", "click", deleteFromConfigDrawer);

try {
  const dropzone = document.getElementById("certDropzone");
  const fileInput = document.getElementById("certFileInput");
  if (dropzone && fileInput) {
    dropzone.addEventListener("click", () => fileInput.click());
    dropzone.addEventListener("dragover", (e) => { e.preventDefault(); dropzone.classList.add("dragover"); });
    dropzone.addEventListener("dragleave", () => dropzone.classList.remove("dragover"));
    dropzone.addEventListener("drop", (e) => {
      e.preventDefault();
      dropzone.classList.remove("dragover");
      if (e.dataTransfer.files.length > 0) uploadCertFile(e.dataTransfer.files[0]);
    });
    fileInput.addEventListener("change", () => {
      if (fileInput.files.length > 0) uploadCertFile(fileInput.files[0]);
      fileInput.value = "";
    });
  }
} catch (e) {
  console.error("Cert UI init error (non-fatal):", e);
}

/* ─── Device Detail Panel ─────────────────────────────────────────── */

function openDeviceDetail(macDash) {
  // Stop any active capture on the previously-open device before switching
  if (detailMac && detailCaptureActive) {
    const prevDash = detailMac.replace(/:/g, "-");
    fetchJSON(`/api/devices/${prevDash}/capture/stop`, { method: "POST" }).catch(() => {});
  }
  detailMac = macDash.replace(/-/g, ":");
  detailActiveTab = "session";  // overridden below once device type is known
  detailCaptureActive = false;
  detailAuthFlowRendered = false;  // reset so fresh render occurs
  _lastPackets = [];
  _expandedNoiseGroups = new Set();
  // Reset capture button label
  const captureBtn = document.getElementById("ddpCaptureToggleBtn");
  if (captureBtn) {
    captureBtn.textContent = "Start Capture";
    captureBtn.className = "btn btn-sm btn-accent";
  }
  // Hide download button until packets are captured
  const dlBtn = document.getElementById("ddpPcapDownloadBtn");
  if (dlBtn) dlBtn.style.display = "none";

  // Clear ISE tab panes so previous device's data never bleeds through
  const _iseReset = '<div class="ddp-empty">Click Fetch to load from ISE.</div>';
  ["ddpIseSessionContent", "ddpIseEndpointContent", "ddpIseHistoryContent"].forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.innerHTML = _iseReset;
  });
  // Re-enable fetch buttons in case they were disabled mid-request
  ["ddpIseSessionBtn", "ddpIseEndpointBtn", "ddpIseHistoryBtn"].forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.disabled = false;
  });
  // Clear NAD probe results so previous device's data never bleeds through
  const nadContent = document.getElementById("ddpNadContent");
  if (nadContent) nadContent.innerHTML = '<div class="ddp-empty">Click Probe to query the switch for this device.</div>';
  const nadProbeBtn = document.getElementById("ddpNadProbeBtn");
  if (nadProbeBtn) nadProbeBtn.disabled = false;
  // Reset ANC policy select
  const ancSelect = document.getElementById("ddpAncSelect");
  if (ancSelect) { ancSelect.innerHTML = "<option disabled selected>\u2014 select policy \u2014</option>"; ancSelect.disabled = true; }
  const ancApply = document.getElementById("ddpAncApplyBtn");
  if (ancApply) ancApply.disabled = true;

  // Hide tab panes and nav tabs; show detail panel
  document.querySelectorAll(".tab-pane").forEach((p) => p.classList.remove("active"));
  document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
  const panel = document.getElementById("deviceDetailPanel");
  if (panel) panel.style.display = "";

  // Scroll to top
  window.scrollTo(0, 0);

  // Populate header immediately from cached device list
  const mac = detailMac;
  const dev = devices.find((d) => d.mac === mac);
  if (dev) _updateDetailHeader(dev);

  // MAB devices have no auth flow — default to the session tab instead
  switchDetailTab((dev && !dev.auth_method) ? "session" : "auth-flow");

  // Start faster detail-specific poll (1s)
  if (detailPollTimer) clearInterval(detailPollTimer);
  detailPollTimer = setInterval(refreshDetail, 1000);
  refreshDetail();
}

function closeDeviceDetail() {
  // Stop capture if active
  if (detailMac && detailCaptureActive) {
    const macDash = detailMac.replace(/:/g, "-");
    fetchJSON(`/api/devices/${macDash}/capture/stop`, { method: "POST" }).catch(() => {});
    detailCaptureActive = false;
  }
  detailMac = null;
  if (detailPollTimer) { clearInterval(detailPollTimer); detailPollTimer = null; }

  const panel = document.getElementById("deviceDetailPanel");
  if (panel) panel.style.display = "none";

  // Restore the last active tab pane
  const tabPaneId = "pane-" + activeTab;
  const pane = document.getElementById(tabPaneId);
  if (pane) pane.classList.add("active");
  document.querySelectorAll(".tab").forEach((t) => {
    if (t.dataset.tab === activeTab) t.classList.add("active");
  });
}

function switchDetailTab(tabName) {
  detailActiveTab = tabName;
  document.querySelectorAll(".ddp-tab").forEach((t) => {
    t.classList.toggle("active", t.dataset.ddptab === tabName);
  });
  document.querySelectorAll(".ddp-pane").forEach((p) => {
    p.classList.toggle("active", p.id === "ddp-pane-" + tabName);
  });
  // Load NAD config into form fields when the NAD tab is first activated
  if (tabName === "nad-probe") loadNadConfig();
  // Trigger content refresh for active tab
  if (detailMac) refreshDetail();
}

async function refreshDetail() {
  if (!detailMac) return;
  if (detailRefreshInFlight) return;
  detailRefreshInFlight = true;
  try {
    const macDash = detailMac.replace(/:/g, "-");
    const dev = await fetchJSON(`/api/devices/${macDash}`);
    // Update local device cache so card states stay current
    const idx = devices.findIndex((d) => d.mac === detailMac);
    if (idx !== -1) devices[idx] = dev;

    _updateDetailHeader(dev);

    if (detailActiveTab === "auth-flow") await _refreshDetailAuthFlow(dev, macDash);
    else if (detailActiveTab === "session") _renderDetailSession(dev);
    else if (detailActiveTab === "packets" && detailCaptureActive) await _refreshDetailPackets(macDash);
  } catch (err) {
    // silent — panel may be closing
  } finally {
    detailRefreshInFlight = false;
  }
}

function _updateDetailHeader(dev) {
  const nameEl = document.getElementById("ddpDeviceName");
  const macEl = document.getElementById("ddpDeviceMac");
  const badgeEl = document.getElementById("ddpStateBadge");
  const connectBtn = document.getElementById("ddpConnectBtn");
  const disconnectBtn = document.getElementById("ddpDisconnectBtn");
  if (nameEl) nameEl.textContent = dev.name;
  if (macEl) macEl.textContent = dev.mac;
  if (badgeEl) {
    badgeEl.textContent = dev.state;
    badgeEl.className = "ddp-state-badge state-" + dev.state;
    if (dev.status_detail) badgeEl.textContent += " — " + dev.status_detail;
  }
  const macDash = dev.mac.replace(/:/g, "-");
  const canConnect = dev.state === "stopped" || dev.state === "auth_failed";
  const canDisconnect = ["online","connecting","authenticating","authorized","auth_failed"].includes(dev.state);
  if (connectBtn) connectBtn.disabled = !canConnect;
  if (disconnectBtn) disconnectBtn.disabled = !canDisconnect;
  // Show CoA button group when ISE is configured and device has an active session
  const coaGroup = document.getElementById("ddpCoaGroup");
  const isOnline = ["online", "authorized"].includes(dev.state);
  if (coaGroup) coaGroup.style.display = (iseConfigured && isOnline) ? "" : "none";
  // Show/hide 802.1X-only tabs
  const isDot1x = !!dev.auth_method;
  const authTab = document.querySelector(".ddp-tab[data-ddptab='auth-flow']");
  const nadTab  = document.querySelector(".ddp-tab[data-ddptab='nad-probe']");
  if (authTab) authTab.style.display = isDot1x ? "" : "none";
  if (nadTab)  nadTab.style.display  = "";
}

async function _refreshDetailAuthFlow(dev, macDash) {
  const container = document.getElementById("ddpAuthFlowContent");
  if (!container) return;
  if (!dev.auth_method) {
    container.innerHTML = "<div class=\"ddp-empty\">Auth Flow is only available for 802.1X devices.</div>";
    return;
  }
  const isActive = ["authenticating","connecting"].includes(dev.state);
  const isTerminal = ["online","authorized","auth_failed","stopped"].includes(dev.state);

  // Once we've rendered a complete flow for a terminal state, stop re-rendering.
  // This prevents the swimlane and raw log toggle from blinking/collapsing every 1s.
  if (isTerminal && detailAuthFlowRendered) return;

  let events = [];
  try {
    events = await fetchJSON(`/api/devices/${macDash}/auth-flow`);
  } catch (_) { /* 404 = no auth yet */ }

  if (events.length === 0 && !isActive) {
    container.innerHTML = "<div class=\"ddp-empty\">No auth events yet. Connect this device to capture the flow.</div>";
    return;
  }

  // Deduplicate consecutive events with identical raw_log_line
  // (wpa_supplicant emits PEER-CERT twice per cert: receive + verify)
  const deduped = events.filter((evt, i) =>
    i === 0 || evt.raw_log_line !== events[i - 1].raw_log_line
  );

  // Inject confidently-inferred events that wpa_supplicant doesn't log directly
  const enriched = _inferAuthFlowEvents(deduped, dev);

  // Preserve raw log toggle expanded/collapsed state across renders
  const wasExpanded = container.querySelector("details.raw-log-toggle")?.open || false;

  let rawLogHtml = "";
  try {
    const logData = await fetchJSON(`/api/devices/${macDash}/dot1x-log`);
    if (logData && logData.log) {
      rawLogHtml = `
        <details class="raw-log-toggle" ${wasExpanded ? "open" : ""}>
          <summary class="raw-log-summary">&#128195; Raw wpa_supplicant log (${escapeHtml(logData.source)})</summary>
          <pre class="raw-log-pre">${escapeHtml(logData.log)}</pre>
        </details>`;
    }
  } catch (_) {}

  container.innerHTML = _renderAuthFlowSwimlane(dev, enriched, isActive) + rawLogHtml;

  // Mark rendered so we don't re-render on next poll tick
  if (isTerminal && enriched.length > 0) detailAuthFlowRendered = true;
}

/**
 * Inject inferred events that wpa_supplicant doesn't log explicitly but
 * are protocol-guaranteed from context.
 *
 * Rules applied in order:
 * 1. After every "identity" (EAP-STARTED) event, insert a supplicant
 *    EAP-Response/Identity reply + an inferred RADIUS Access-Request relay.
 * 2. NAK detection — observed ("-> NAK" in raw line) or inferred (two
 *    consecutive method_propose with no accept between them).
 * 3. RADIUS relay inference — Access-Accept / Access-Reject cross the NAD
 *    on their way from ISE to the supplicant; inject a relay row on the
 *    authenticator column to make that hop visible.
 *
 * Inferred events carry { _inferred: true }.
 * Reply-injected events carry { _isReply: true } (not inferred — protocol guaranteed).
 * Relay events carry { _direction: { from, to } } for the arrow renderer.
 */
function _inferAuthFlowEvents(events, dev) {
  const EAP_NAMES = {
    "1": "Identity", "4": "MD5", "6": "OTP", "13": "EAP-TLS",
    "17": "LEAP", "21": "EAP-TTLS", "25": "PEAP",
    "43": "EAP-FAST", "55": "TEAP", "254": "EAP-EXPANDED",
  };

  if (!events.length) return events;
  const out = [];
  for (let i = 0; i < events.length; i++) {
    const evt = events[i];
    out.push(evt);

    // Rule 1: supplicant EAP-Response/Identity reply + RADIUS Access-Request relay
    if (evt.event_type === "identity" && evt.actor === "authenticator") {
      const identityStr = dev.auth_identity ? ` "${dev.auth_identity}"` : "";
      out.push({
        ...evt,
        actor: "supplicant",
        event_type: "identity",
        detail: `Supplicant sent EAP-Response/Identity${identityStr}`,
        // Not _inferred: RFC 3748 guarantees this step; identity is from device config.
        _isReply: true,
      });
      // Infer the RADIUS Access-Request the NAD forwards upstream to ISE
      out.push({
        ...evt,
        actor: "authenticator",
        event_type: "radius_relay",
        detail: "RADIUS Access-Request forwarded to ISE",
        _inferred: true,
        _direction: { from: 0, to: 2 },
      });
    }

    // Rule 2: NAK injection
    if (evt.event_type === "method_propose") {
      const rawLine = evt.raw_log_line || "";
      const hasObservedNak = rawLine.includes("-> NAK");
      const nextIsAlsoPropose = !hasObservedNak && events[i + 1]?.event_type === "method_propose";

      if (hasObservedNak || nextIsAlsoPropose) {
        const numMatch = rawLine.match(/method=(\d+)/);
        const num = numMatch ? numMatch[1] : null;
        const name = num ? (EAP_NAMES[num] || `method ${num}`) : "unknown method";
        const numLabel = num ? ` (method ${num})` : "";
        out.push({
          ...evt,
          actor: "supplicant",
          event_type: "nak",
          detail: `Supplicant sent EAP-NAK — rejected ${name}${numLabel}, requesting preferred method`,
          _inferred: !hasObservedNak,
        });
      }
    }

    // Rule 3: RADIUS Access-Accept relay (ISE success → NAD → supplicant)
    if (evt.event_type === "success" && evt.actor === "radius") {
      out.push({
        ...evt,
        actor: "authenticator",
        event_type: "radius_relay",
        detail: "RADIUS Access-Accept → switch port authorized",
        _inferred: true,
        _direction: { from: 2, to: 0 },
      });
    }

    // Rule 4: RADIUS Access-Reject relay (ISE failure → NAD → supplicant)
    if (evt.event_type === "failure" && evt.actor === "radius") {
      out.push({
        ...evt,
        actor: "authenticator",
        event_type: "radius_relay",
        detail: "RADIUS Access-Reject forwarded to supplicant",
        _inferred: true,
        _direction: { from: 2, to: 0 },
      });
    }
  }
  return out;
}

/**
 * Compute phase break descriptors for methods that have distinct phases.
 * Returns an array of { beforeIdx, label, cls } where beforeIdx is the
 * index of the event this separator should appear BEFORE.
 * Emits nothing for methods without TLS (MAB, LEAP, MD5).
 */
function _computePhaseBreaks(events, authMethod) {
  const m = (authMethod || "").toLowerCase();
  const isEapTls   = m === "eap-tls";
  const hasInner   = m === "peap" || m.includes("ttls") || m.includes("fast") || m === "teap";
  const hasPhases  = isEapTls || hasInner;
  if (!hasPhases) return [];

  const breaks = [];
  // Phase 0 banner always at the very top when phases apply
  breaks.push({ beforeIdx: 0, label: "Identity Exchange", cls: "swim-phase-0" });

  let sawTlsStart = false;
  let sawTlsDone  = false;

  for (let i = 0; i < events.length; i++) {
    const t = events[i].event_type;
    if (!sawTlsStart && t === "tls_start") {
      sawTlsStart = true;
      const label = isEapTls ? "Mutual TLS Handshake" : "Phase 1 \u2014 Outer TLS Tunnel";
      breaks.push({ beforeIdx: i, label, cls: "swim-phase-1" });
    }
    if (!sawTlsDone && t === "tls_done" && hasInner) {
      sawTlsDone = true;
      // Insert after tls_done, i.e. before the next event
      breaks.push({ beforeIdx: i + 1, label: "Phase 2 \u2014 Inner Authentication", cls: "swim-phase-2" });
    }
  }
  return breaks;
}

function _renderAuthFlowSwimlane(dev, events, isActive) {
  const method = (dev.auth_method || "").toUpperCase().replace("-", " ");
  const statusClass = isActive ? "swim-status-live" : (
    dev.auth_state === "authorized" || dev.state === "online" ? "swim-status-ok" : "swim-status-fail"
  );
  const statusLabel = isActive ? "&#9679; Live" : (
    dev.auth_state === "authorized" || dev.state === "online" ? "&#10003; Authorized" : "&#10007; Failed"
  );
  const durationMs = (dev.auth_started_at && dev.auth_completed_at)
    ? ((dev.auth_completed_at - dev.auth_started_at) * 1000).toFixed(0)
    : null;
  const durationHtml = durationMs
    ? `<span class="swim-duration">&#9201; ${durationMs} ms</span>`
    : isActive ? `<span class="swim-duration swim-duration-live">&#9203; in progress\u2026</span>` : "";

  // Column headers with role subtitles
  const swimHeader = `
    <div class="swim-header">
      <span class="swim-method">${escapeHtml(method)}</span>
      <span class="swim-status ${statusClass}">${statusLabel}</span>
      ${durationHtml}
    </div>
    <div class="swim-columns">
      <div class="swim-col-label swim-col-supplicant">Supplicant<span class="swim-col-subtitle">wpa_supplicant / 802.1X Client</span></div>
      <div class="swim-col-label swim-col-authenticator">Switch / NAD<span class="swim-col-subtitle">Authenticator / RADIUS Proxy</span></div>
      <div class="swim-col-label swim-col-radius">ISE / RADIUS<span class="swim-col-subtitle">Authentication Server</span></div>
    </div>`;

  if (events.length === 0 && isActive) {
    return swimHeader + `<div class="swim-waiting"><span class="swim-spinner"></span> Waiting for EAP exchange\u2026</div>`;
  }

  const ACTOR_COLS = { supplicant: 0, authenticator: 1, radius: 2 };
  const EVENT_ICONS = {
    identity:      "&#128272;",
    method_propose:"&#128101;",
    method_accept: "&#9989;",
    tls_start:     "&#128274;",
    tls_done:      "&#128275;",
    cert_received: "&#128196;",
    cert_san:      "&#128203;",
    cert_error:    "&#10060;",
    ssl_alert:     "&#128680;",
    inner_auth:    "&#128100;",
    success:       "&#9989;",
    failure:       "&#10060;",
    nak:           "&#10006;",
    radius_relay:  "&#8646;",
    teap_tlv:      "&#128260;",
    connected:     "&#9989;",
    timeout:       "&#9203;",
    info:          "&#8505;",
  };

  // Determine which phase each event index belongs to, for left-border tinting
  // 0 = identity, 1 = outer TLS, 2 = inner auth
  const eventPhase = new Array(events.length).fill(0);
  {
    let phase = 0;
    const m = (dev.auth_method || "").toLowerCase();
    const hasInner = m === "peap" || m.includes("ttls") || m.includes("fast") || m === "teap";
    for (let i = 0; i < events.length; i++) {
      const t = events[i].event_type;
      if (phase < 1 && t === "tls_start") phase = 1;
      if (phase < 2 && t === "tls_done" && hasInner) phase = 2;
      // cert_error / ssl_alert during TLS handshake stay in phase 1
      eventPhase[i] = phase;
    }
  }

  // Find TLS zone boundaries (for the dashed green box around TLS tunnel rows)
  let tlsStart = -1, tlsEnd = -1;
  for (let i = 0; i < events.length; i++) {
    const t = events[i].event_type;
    if (tlsStart < 0 && t === "tls_start") tlsStart = i;
    // Zone ends at tls_done, cert_error, or ssl_alert (handshake abort)
    if (tlsStart >= 0 && tlsEnd < 0 && (t === "tls_done" || t === "cert_error" || t === "ssl_alert")) {
      tlsEnd = i;
    }
  }
  // If tls_start was seen but tls_done never appeared, zone ends at last event
  if (tlsStart >= 0 && tlsEnd < 0) tlsEnd = events.length - 1;

  // Note appended after CONNECTED event
  const connectedNote = `
    <div class="swim-av-note">
      &#9432; RADIUS AV pairs (VLAN, SGT, dACL) assigned in the Access-Accept are visible in the
      <strong>ISE Policy</strong> tab. Events sourced from the wpa_supplicant log; relay hops are inferred.
    </div>`;

  // Phase separator banners — build a lookup: idx → html
  const phaseBreaks = _computePhaseBreaks(events, dev.auth_method);
  const phaseSepAt = {};
  phaseBreaks.forEach(({ beforeIdx, label, cls }) => {
    const html = `<div class="swim-phase-sep ${cls}"><div class="swim-phase-line"></div><span class="swim-phase-label">${escapeHtml(label)}</span><div class="swim-phase-line"></div></div>`;
    phaseSepAt[beforeIdx] = (phaseSepAt[beforeIdx] || "") + html;
  });

  // Build each row
  const rowHtmls = events.map((evt, idx) => {
    const sep = phaseSepAt[idx] || "";
    const col = ACTOR_COLS[evt.actor] ?? 0;
    const icon = EVENT_ICONS[evt.event_type] || "&#9679;";
    const isCertError = evt.event_type === "cert_error";
    const isSslAlert  = evt.event_type === "ssl_alert";
    const isFailure   = evt.event_type === "failure" || evt.event_type === "timeout" || isCertError || isSslAlert;
    const isSuccess   = evt.event_type === "success" || evt.event_type === "connected";
    const isRelay     = evt.event_type === "radius_relay";
    const inferredClass = evt._inferred ? " swim-cell-inferred" : "";
    const phaseRowClass = ` swim-row-phase-${eventPhase[idx]}`;

    // Cell state class
    let cellBase = "swim-cell";
    if (isFailure) cellBase += " swim-cell-fail";
    else if (isSuccess) cellBase += " swim-cell-ok";
    else if (isRelay) cellBase += " swim-cell-relay";
    const cellClass = cellBase + inferredClass;

    // Tags row
    const inferredLabel = evt._inferred ? `<span class="swim-inferred-tag">inferred</span>` : "";
    const replyLabel    = evt._isReply  ? `<span class="swim-reply-tag">\u21a9 reply</span>` : "";

    // Timing badge for the terminal success event
    const timingBadge = (isSuccess && durationMs && !isActive)
      ? `<span class="swim-badge-timing">&#9201; ${durationMs} ms</span>`
      : "";

    // Warning annotation for cert_error
    const certErrorAnnotation = isCertError
      ? `<div class="swim-cert-error-annotation">&#9888; Supplicant aborts TLS &mdash; ISE cert not trusted. Add the ISE CA to MACforge and enable server cert validation, or disable <em>Validate Server Certificate</em> in the auth profile.</div>`
      : "";

    // Relay row: spans the full NAD column with a directional arrow
    if (isRelay) {
      const dir = evt._direction || { from: 1, to: 1 };
      // Arrow direction classes: swim-relay-left (ISE→NAD→Sup) or swim-relay-right (Sup→NAD→ISE)
      const arrowCls = dir.from < dir.to ? "swim-relay-right" : "swim-relay-left";
      const cells = [0, 1, 2].map((c) => {
        if (c !== 1) {
          // Left/right endpoint cells get the endpoint marker
          const isEndpoint = (c === dir.from || c === dir.to);
          const endCls = isEndpoint ? ` swim-relay-endpoint swim-relay-ep-${c === dir.from ? "src" : "dst"}` : "";
          return `<div class="swim-cell swim-cell-empty${endCls}"><div class="swim-line"></div></div>`;
        }
        return `
          <div class="${cellClass}">
            <div class="swim-line"></div>
            <div class="swim-event-card swim-relay-card ${arrowCls}">
              <span class="swim-icon">${icon}</span>
              <div class="swim-event-body">
                <div class="swim-event-detail">${escapeHtml(evt.detail)}</div>
                <div class="swim-event-meta">
                  <span class="swim-ts">${formatTime(evt.timestamp)}</span>
                  <span class="swim-actor swim-actor-authenticator">relay</span>
                  ${inferredLabel}
                </div>
              </div>
            </div>
          </div>`;
      }).join("");
      return sep + `<div class="swim-row${phaseRowClass}">${cells}</div>`;
    }

    // Standard event row
    const cells = [0, 1, 2].map((c) => {
      if (c !== col) return `<div class="swim-cell swim-cell-empty"><div class="swim-line"></div></div>`;
      return `
        <div class="${cellClass}">
          <div class="swim-line"></div>
          <div class="swim-event-card">
            <span class="swim-icon">${icon}</span>
            <div class="swim-event-body">
              <div class="swim-event-detail">${escapeHtml(evt.detail)}${timingBadge}</div>
              ${certErrorAnnotation}
              <div class="swim-event-meta">
                <span class="swim-ts">${formatTime(evt.timestamp)}</span>
                <span class="swim-actor swim-actor-${escapeHtml(evt.actor)}">${escapeHtml(evt.actor)}</span>
                ${inferredLabel}${replyLabel}
              </div>
            </div>
          </div>
        </div>`;
    }).join("");

    return sep + `<div class="swim-row${phaseRowClass}">${cells}</div>`;
  });

  // Wrap TLS zone rows in a dashed-border container
  let gridInner = "";
  if (tlsStart >= 0) {
    // rows before zone
    gridInner += rowHtmls.slice(0, tlsStart).join("");
    // TLS zone wrapper (includes the tls_start and tls_end rows themselves)
    gridInner += `<div class="swim-tls-zone">`;
    gridInner += rowHtmls.slice(tlsStart, tlsEnd + 1).join("");
    gridInner += `</div>`;
    // rows after zone
    gridInner += rowHtmls.slice(tlsEnd + 1).join("");
  } else {
    gridInner = rowHtmls.join("");
  }

  // Tail phase separators (for any break that falls past the last event)
  const tailSeps = Object.entries(phaseSepAt)
    .filter(([i]) => parseInt(i) >= events.length)
    .map(([, html]) => html).join("");

  // Legend
  const legend = `
    <div class="swim-legend">
      <div class="swim-legend-title">Legend</div>
      <div class="swim-legend-row"><span class="swim-legend-swatch swim-legend-outer"></span> Outer EAP (logged)</div>
      <div class="swim-legend-row"><span class="swim-legend-swatch swim-legend-tls"></span> TLS Tunnel</div>
      <div class="swim-legend-row"><span class="swim-legend-swatch swim-legend-inner"></span> Inner Authentication</div>
      <div class="swim-legend-row"><span class="swim-legend-swatch swim-legend-fail"></span> Failure / Error</div>
      <div class="swim-legend-row"><span class="swim-legend-swatch swim-legend-inferred"></span> Inferred (dashed border)</div>
    </div>`;

  return swimHeader
    + `<div class="swim-grid">${gridInner}${tailSeps}</div>`
    + (isActive ? "" : connectedNote)
    + legend;
}

function _renderDetailSession(dev) {
  const container = document.getElementById("ddpSessionContent");
  if (!container) return;

  const connectedAt = dev.connected_at
    ? new Date(dev.connected_at * 1000).toLocaleString()
    : "—";
  const authDuration = (dev.auth_started_at && dev.auth_completed_at)
    ? `${((dev.auth_completed_at - dev.auth_started_at) * 1000).toFixed(0)} ms`
    : "—";
  const leaseHuman = dev.dhcp_lease_time
    ? (dev.dhcp_lease_time >= 3600
        ? `${(dev.dhcp_lease_time / 3600).toFixed(1)}h`
        : `${Math.round(dev.dhcp_lease_time / 60)}m`)
    : "—";
  const dnsText = dev.dhcp_dns && dev.dhcp_dns.length ? dev.dhcp_dns.join(", ") : "—";

  container.innerHTML = `
    <div class="ddp-kv-grid">
      <div class="ddp-section-hdr">Session</div>
      ${_kvRow("State", `<span class="ddp-state-badge state-${escapeHtml(dev.state)}">${escapeHtml(dev.state)}</span>`)}
      ${_kvRow("Connected Since", escapeHtml(connectedAt))}
      ${_kvRow("Uptime", escapeHtml(formatUptime(dev.uptime_sec)))}
      ${dev.auth_method ? _kvRow("Auth Duration", escapeHtml(authDuration)) : ""}
      ${dev.auth_method ? _kvRow("Auth Method", escapeHtml((dev.auth_method || "").toUpperCase())) : ""}
      ${dev.auth_identity ? _kvRow("Identity", escapeHtml(dev.auth_identity)) : ""}
      ${dev.error_message ? _kvRow("Last Error", `<span class="ddp-error-val">${escapeHtml(dev.error_message)}</span>`) : ""}

      <div class="ddp-section-hdr" style="margin-top:20px">Network</div>
      ${_kvRow("IP Address", escapeHtml(dev.assigned_ip || "—"))}
      ${_kvRow("Gateway", escapeHtml(dev.gateway_ip || "—"))}
      ${_kvRow("DHCP Server", escapeHtml(dev.dhcp_server_ip || "—"))}
      ${_kvRow("Subnet Mask", escapeHtml(dev.dhcp_subnet || "—"))}
      ${_kvRow("DNS Servers", escapeHtml(dnsText))}
      ${_kvRow("Lease Time", escapeHtml(leaseHuman))}

      <div class="ddp-section-hdr" style="margin-top:20px">Device Identity</div>
      ${_kvRow("Hostname", escapeHtml(dev.dhcp.hostname || "—"))}
      ${_kvRow("Vendor Class", escapeHtml(dev.dhcp.vendor_class || "—"))}
      ${_kvRow("OS", escapeHtml(dev.personality.os || "—"))}
      ${_kvRow("Category", escapeHtml(dev.personality.category || "—"))}
      ${_kvRow("Device Type", escapeHtml(dev.personality.device_type || "—"))}
      ${_kvRow("Packets Sent", escapeHtml(String(dev.packets_sent)))}
    </div>
    ${dev.last_ping ? `<div class="ddp-section-hdr" style="margin-top:20px">Last Ping</div>${renderPingResult(dev)}` : ""}`;
}

// Cache of last-fetched packets for re-render on filter toggle
let _lastPackets = [];
let _expandedNoiseGroups = new Set();  // indices of noise groups expanded by user

async function _refreshDetailPackets(macDash) {
  const container = document.getElementById("ddpPacketsContent");
  if (!container) return;
  try {
    const packets = await fetchJSON(`/api/devices/${macDash}/packets`);
    _lastPackets = packets || [];
    _reRenderPackets();
  } catch (_) {}
}

function _reRenderPackets() {
  const container = document.getElementById("ddpPacketsContent");
  if (!container) return;
  const hideNoise = document.getElementById("pktHideNoise")?.checked ?? true;
  const packets = _lastPackets;

  if (!packets || packets.length === 0) {
    container.innerHTML = "<div class=\"ddp-empty\">No packets captured yet.</div>";
    return;
  }

  // Classify noise protocols
  const isNoise = (p) => p.protocol === "ARP" || p.protocol === "ICMP";

  // Group consecutive noise packets into collapsed rows
  const groups = [];
  let noiseRun = [];
  for (const p of packets) {
    if (isNoise(p)) {
      noiseRun.push(p);
    } else {
      if (noiseRun.length) {
        groups.push({ type: "noise", items: noiseRun });
        noiseRun = [];
      }
      groups.push({ type: "packet", item: p });
    }
  }
  if (noiseRun.length) groups.push({ type: "noise", items: noiseRun });

  const rows = [];
  let noiseGroupIdx = 0;

  for (const g of groups) {
    if (g.type === "noise") {
      const idx = noiseGroupIdx++;
      if (hideNoise) {
        // Collapsed: single summary row that can be expanded
        const proto_counts = {};
        for (const p of g.items) {
          proto_counts[p.protocol] = (proto_counts[p.protocol] || 0) + 1;
        }
        const label = Object.entries(proto_counts).map(([k, v]) => `${v}× ${k}`).join(", ");
        rows.push(`
          <tr class="pkt-noise-group" onclick="toggleNoiseGroup(${idx})" title="Click to expand">
            <td class="pkt-ts" colspan="5">
              <span class="pkt-noise-label">&#8230; ${escapeHtml(label)} (collapsed)</span>
              <span class="pkt-noise-expand">&#9660; expand</span>
            </td>
          </tr>
          <tbody id="noise-group-${idx}" style="display:none">${g.items.map((p) => _pktRow(p, true)).join("")}</tbody>`);
      } else {
        // Show all noise rows
        rows.push(g.items.map((p) => _pktRow(p, false)).join(""));
      }
    } else {
      rows.push(_pktRow(g.item, false));
    }
  }

  // Show download button once there are packets
  const dlBtn = document.getElementById("ddpPcapDownloadBtn");
  if (dlBtn) dlBtn.style.display = "";

  container.innerHTML = `
    <table class="pkt-table">
      <thead><tr><th>Time</th><th></th><th>Protocol</th><th>Info</th><th>Size</th></tr></thead>
      <tbody>${rows.join("")}</tbody>
    </table>`;

  // Restore previously-expanded noise groups without collapsing them on each refresh
  for (const idx of _expandedNoiseGroups) {
    const tbody = document.getElementById(`noise-group-${idx}`);
    if (tbody) {
      tbody.style.display = "";
      const noiseRows = document.querySelectorAll(".pkt-noise-group");
      if (noiseRows[idx]) {
        const lbl = noiseRows[idx].querySelector(".pkt-noise-expand");
        if (lbl) lbl.textContent = "▲ collapse";
      }
    }
  }
}

function _pktRow(p, inside_noise_tbody) {
  const dirClass = p.direction === "sent" ? "pkt-sent" : "pkt-recv";
  const dirArrow = p.direction === "sent" ? "&#8593;" : "&#8595;";
  const isEapol  = p.protocol === "EAPOL";
  const isNoise  = p.protocol === "ARP" || p.protocol === "ICMP";
  const protoClass = isEapol ? "pkt-proto pkt-proto-eapol"
                   : isNoise ? "pkt-proto pkt-proto-noise"
                   : "pkt-proto";

  const sizeLabel = p.size_bytes ? `${p.size_bytes}B` : "—";

  // Build detail expand for EAPOL packets
  let detailHtml = "";
  if (isEapol && p.detail && Object.keys(p.detail).length > 0) {
    const d = p.detail;
    const items = [];
    if (d.eapol_type)  items.push(`<span class="pkt-detail-tag">${escapeHtml(d.eapol_type)}</span>`);
    if (d.eap_code)    items.push(`<span class="pkt-detail-tag">${escapeHtml(d.eap_code)}</span>`);
    if (d.eap_type)    items.push(`<span class="pkt-detail-tag pkt-tag-method">${escapeHtml(d.eap_type)}</span>`);
    if (d.eap_id !== undefined) items.push(`<span class="pkt-detail-kv">id=${d.eap_id}</span>`);
    if (d.src_mac)     items.push(`<span class="pkt-detail-kv">src=${escapeHtml(d.src_mac)}</span>`);
    if (items.length) detailHtml = `<div class="pkt-detail-row">${items.join(" ")}</div>`;
  }

  // DHCP detail
  if (p.protocol === "DHCP" && p.detail && p.detail.offered_ip) {
    detailHtml = `<div class="pkt-detail-row"><span class="pkt-detail-kv">offered=${escapeHtml(p.detail.offered_ip)}</span>${p.detail.router ? ` <span class="pkt-detail-kv">gw=${escapeHtml(p.detail.router)}</span>` : ""}</div>`;
  }

  const rowClass = isEapol ? "pkt-row-eapol" : isNoise ? "pkt-row-noise" : "";

  return `<tr class="${rowClass}">
    <td class="pkt-ts">${formatTime(p.timestamp)}</td>
    <td class="pkt-dir ${dirClass}">${dirArrow}</td>
    <td class="${protoClass}">${escapeHtml(p.protocol)}</td>
    <td class="pkt-summary">${escapeHtml(p.summary)}${detailHtml}</td>
    <td class="pkt-size">${sizeLabel}</td>
  </tr>`;
}

function toggleNoiseGroup(idx) {
  const tbody = document.getElementById(`noise-group-${idx}`);
  if (!tbody) return;
  const hidden = tbody.style.display === "none";
  tbody.style.display = hidden ? "" : "none";
  if (hidden) {
    _expandedNoiseGroups.add(idx);
  } else {
    _expandedNoiseGroups.delete(idx);
  }
  // Update the expand label in the row above
  const rows = document.querySelectorAll(".pkt-noise-group");
  if (rows[idx]) {
    const label = rows[idx].querySelector(".pkt-noise-expand");
    if (label) label.textContent = hidden ? "▲ collapse" : "▼ expand";
  }
}

function downloadPcap() {
  if (!detailMac) return;
  const macDash = detailMac.replace(/:/g, "-");
  window.location.href = `/api/devices/${macDash}/packets/download`;
}

function _kvRow(label, valueHtml) {
  return `<div class="ddp-kv-row"><span class="ddp-kv-label">${escapeHtml(label)}</span><span class="ddp-kv-value">${valueHtml}</span></div>`;
}

async function ddpConnectDevice() {
  if (!detailMac) return;
  const macDash = detailMac.replace(/:/g, "-");
  try {
    await fetchJSON(`/api/devices/${macDash}/connect`, { method: "POST" });
    showToast("Connecting " + detailMac, "info");
  } catch (err) { showToast(err.message, "error"); }
}

async function ddpDisconnectDevice() {
  if (!detailMac) return;
  const macDash = detailMac.replace(/:/g, "-");
  try {
    await fetchJSON(`/api/devices/${macDash}/disconnect`, { method: "POST" });
    showToast("Disconnecting " + detailMac, "info");
  } catch (err) { showToast(err.message, "error"); }
}

function togglePacketCapture() {
  if (!detailMac) return;
  const macDash = detailMac.replace(/:/g, "-");
  detailCaptureActive = !detailCaptureActive;
  const btn = document.getElementById("ddpCaptureToggleBtn");
  if (btn) {
    btn.textContent = detailCaptureActive ? "Stop Capture" : "Start Capture";
    btn.className = detailCaptureActive ? "btn btn-sm btn-disconnect-all" : "btn btn-sm btn-accent";
  }
  if (detailCaptureActive) {
    fetchJSON(`/api/devices/${macDash}/capture/start`, { method: "POST" })
      .then(() => showToast("Packet capture started", "info"))
      .catch((err) => showToast("Capture start failed: " + err.message, "error"));
  } else {
    fetchJSON(`/api/devices/${macDash}/capture/stop`, { method: "POST" })
      .then(() => showToast("Packet capture stopped", "info"))
      .catch((err) => showToast("Capture stop failed: " + err.message, "error"));
    const container = document.getElementById("ddpPacketsContent");
    if (container && !container.querySelector("table")) {
      container.innerHTML = "<div class=\"ddp-empty\">Capture stopped.</div>";
    }
  }
}

// Phase 2: ISE Policy tab — on-demand fetch functions

async function fetchIseSession() {
  if (!detailMac) return;
  const macDash = detailMac.replace(/:/g, "-");
  const btn = document.getElementById("ddpIseSessionBtn");
  const container = document.getElementById("ddpIseSessionContent");
  if (btn) btn.disabled = true;
  if (container) container.innerHTML = '<div class="ddp-ise-loading">&#8987; Fetching from ISE&hellip;</div>';
  try {
    const data = await fetchJSON(`/api/devices/${macDash}/ise-session`);
    if (!container) return;
    if (data.status === "ok" && data.session) {
      container.innerHTML = _renderIseSessionKV(data.session);
    } else if (data.status === "not_found") {
      container.innerHTML = `<div class="ddp-empty">&#9888; ${escapeHtml(data.message || "No active session found")}</div>`;
    } else {
      container.innerHTML = `<div class="ddp-ise-error">&#10005; ${escapeHtml(data.message || "ISE error")}</div>`;
    }
  } catch (err) {
    if (container) container.innerHTML = `<div class="ddp-ise-error">&#10005; ${escapeHtml(err.message)}</div>`;
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function fetchIseEndpoint() {
  if (!detailMac) return;
  const macDash = detailMac.replace(/:/g, "-");
  const btn = document.getElementById("ddpIseEndpointBtn");
  const container = document.getElementById("ddpIseEndpointContent");
  if (btn) btn.disabled = true;
  if (container) container.innerHTML = '<div class="ddp-ise-loading">&#8987; Fetching from ISE&hellip;</div>';
  try {
    const data = await fetchJSON(`/api/devices/${macDash}/ise-endpoint`);
    if (!container) return;
    if (data.status === "ok" && data.endpoint) {
      container.innerHTML = _renderIseEndpointKV(data.endpoint);
    } else if (data.status === "not_found") {
      container.innerHTML = `<div class="ddp-empty">&#9888; ${escapeHtml(data.message || "Endpoint not found in ISE")}</div>`;
    } else {
      container.innerHTML = `<div class="ddp-ise-error">&#10005; ${escapeHtml(data.message || "ISE error")}</div>`;
    }
  } catch (err) {
    if (container) container.innerHTML = `<div class="ddp-ise-error">&#10005; ${escapeHtml(err.message)}</div>`;
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function fetchIseHistory() {
  if (!detailMac) return;
  const macDash = detailMac.replace(/:/g, "-");
  const btn = document.getElementById("ddpIseHistoryBtn");
  const container = document.getElementById("ddpIseHistoryContent");
  if (btn) btn.disabled = true;
  if (container) container.innerHTML = '<div class="ddp-ise-loading">&#8987; Fetching from ISE&hellip;</div>';
  try {
    const data = await fetchJSON(`/api/devices/${macDash}/ise-history`);
    if (!container) return;
    if (data.status === "ok") {
      const history = data.history || [];
      if (history.length === 0) {
        container.innerHTML = '<div class="ddp-empty">No authentication history found in ISE.</div>';
      } else {
        container.innerHTML = _renderIseHistoryTable(history);
      }
    } else {
      container.innerHTML = `<div class="ddp-ise-error">&#10005; ${escapeHtml(data.message || "ISE error")}</div>`;
    }
  } catch (err) {
    if (container) container.innerHTML = `<div class="ddp-ise-error">&#10005; ${escapeHtml(err.message)}</div>`;
  } finally {
    if (btn) btn.disabled = false;
  }
}


async function sendCoA(action) {
  if (!detailMac) return;
  const macDash = detailMac.replace(/:/g, "-");
  const labels = { reauth: "Re-auth", disconnect: "Terminate", port_bounce: "Port Bounce" };
  const label = labels[action] || action;
  // Disable all CoA buttons while in-flight
  document.querySelectorAll(".btn-coa-reauth, .btn-coa-bounce, .btn-coa-disconnect").forEach((b) => b.disabled = true);
  showToast(`Sending CoA: ${label}…`, "info");
  try {
    const data = await fetchJSON(`/api/devices/${macDash}/coa`, {
      method: "POST",
      body: JSON.stringify({ action }),
    });
    if (data.status === "ok") {
      showToast(`&#10003; ${escapeHtml(data.message || `CoA ${label} sent`)}`, "success");
    } else {
      // Show ISE error detail if available (e.g. HTTP 404 body from ERS)
      const detail = data.detail ? ` — ${data.detail}` : "";
      showToast(`CoA failed: ${escapeHtml((data.message || "Unknown error") + detail)}`, "error");
    }
  } catch (err) {
    // fetchJSON throws on non-2xx HTTP (e.g. FastAPI 404 Device not found)
    showToast(`CoA error: ${escapeHtml(err.message)}`, "error");
  } finally {
    document.querySelectorAll(".btn-coa-reauth, .btn-coa-bounce, .btn-coa-disconnect").forEach((b) => b.disabled = false);
  }
}

/* ── ISE data renderers ─────────────────────────────────────────────── */

// Key fields to surface from ISE MnT session (in display order)
// MnT Session/MACAddress response uses snake_case keys
// Preferred display order for session fields (shown first; everything else follows alphabetically)
const _SESSION_KEY_ORDER = [
  "user_name", "userName",
  "calling_station_id",
  "framed_ip_address", "framedIpAddress",
  "nas_ip_address", "nasIpAddress",
  "nas_port_id", "nasPortId",
  "network_device_name", "networkDeviceName",
  "acct_session_id", "acctSessionId",
  "authentication_method", "authenticationMethod",
  "eap_authentication", "eapAuthentication",
  "eap_tunnel", "eapTunnel",
  "authentication_identity_store",
  "selected_azn_profiles", "selectedAznProfiles",
  "security_group", "securityGroup",
  "vlan",
  "posture_status",
  "session_timeout",
];

function _sessionKeyLabel(key) {
  const map = {
    user_name: "Identity", userName: "Identity",
    calling_station_id: "Calling Station ID",
    framed_ip_address: "IP Address (ISE)", framedIpAddress: "IP Address (ISE)",
    nas_ip_address: "NAS IP", nasIpAddress: "NAS IP",
    nas_port_id: "NAS Port", nasPortId: "NAS Port",
    network_device_name: "Network Device", networkDeviceName: "Network Device",
    acct_session_id: "Session ID", acctSessionId: "Session ID",
    authentication_method: "Auth Method", authenticationMethod: "Auth Method",
    eap_authentication: "EAP Method", eapAuthentication: "EAP Method",
    eap_tunnel: "EAP Tunnel", eapTunnel: "EAP Tunnel",
    authentication_identity_store: "Identity Store",
    selected_azn_profiles: "AuthZ Profile", selectedAznProfiles: "AuthZ Profile",
    security_group: "SGT", securityGroup: "SGT",
    vlan: "VLAN",
    posture_status: "Posture",
    session_timeout: "Session Timeout (s)",
  };
  return map[key] || key.replace(/_/g, " ").replace(/([A-Z])/g, " $1").trim();
}

function _renderIseSessionKV(session) {
  const rendered = new Set();
  const rows = [];

  // Render preferred keys first, deduplicating snake/camel variants by label
  const seenLabels = new Set();
  for (const key of _SESSION_KEY_ORDER) {
    const val = session[key];
    if (val === undefined || val === null || val === "") continue;
    const label = _sessionKeyLabel(key);
    if (seenLabels.has(label)) continue;
    rows.push(_kvRow(label, escapeHtml(String(val))));
    rendered.add(key);
    seenLabels.add(label);
  }
  // Then all remaining fields alphabetically
  for (const key of Object.keys(session).sort()) {
    if (rendered.has(key)) continue;
    const val = session[key];
    if (val === undefined || val === null || val === "") continue;
    if (typeof val === "object") continue;
    rows.push(_kvRow(_sessionKeyLabel(key), escapeHtml(String(val))));
  }

  if (rows.length === 0) {
    return '<div class="ddp-empty">Session found but no recognisable fields.</div>';
  }
  return `<div class="ddp-kv-grid">${rows.join("")}</div>`;
}

// UUID regex — used to suppress raw UUID values in endpoint display
const _UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// Keys in /api/v1/endpoint response that are nested objects (handled separately)
const _EP_NESTED_KEYS = new Set(["mdmAttributes", "customAttributes", "profilerAttributes",
                                  "profilerServerList", "customAttributes2"]);

// Preferred display order for top-level endpoint fields
const _EP_KEY_ORDER = ["mac", "profileName", "endpointGroup", "registrationStatus",
                        "staticProfileAssignment", "staticGroupAssignment",
                        "identityStore", "portalUser", "description"];

function _epKeyLabel(key) {
  const map = {
    mac: "MAC Address", profileName: "Profile", endpointGroup: "Endpoint Group",
    registrationStatus: "Registration", staticProfileAssignment: "Static Profile",
    staticGroupAssignment: "Static Group", identityStore: "Identity Store",
    portalUser: "Portal User", description: "Description",
  };
  return map[key] || key.replace(/([A-Z])/g, " $1").replace(/_/g, " ").trim();
}

function _renderIseEndpointKV(ep) {
  const rows = [];
  const rendered = new Set();

  // Render preferred keys first, in order
  for (const key of _EP_KEY_ORDER) {
    const val = ep[key];
    if (val !== undefined && val !== null && val !== "" && val !== false && !_UUID_RE.test(String(val))) {
      rows.push(_kvRow(_epKeyLabel(key), escapeHtml(String(val))));
      rendered.add(key);
    }
  }
  // Then any remaining top-level scalar fields (skip UUIDs, nested objects, id fields)
  for (const [key, val] of Object.entries(ep)) {
    if (rendered.has(key) || _EP_NESTED_KEYS.has(key)) continue;
    if (key === "id" || key.endsWith("Id") || key.endsWith("_id")) continue;
    if (typeof val === "object" || val === null || val === "") continue;
    if (_UUID_RE.test(String(val))) continue;
    rows.push(_kvRow(_epKeyLabel(key), escapeHtml(String(val))));
  }

  // profilerAttributes — flat KV of collected profiling probe data
  const profiler = ep.profilerAttributes || ep.profilerServerList || {};
  const profEntries = typeof profiler === "object" ? Object.entries(profiler) : [];
  const profHtml = profEntries
    .filter(([, v]) => v !== null && v !== "" && v !== undefined)
    .map(([k, v]) => `${escapeHtml(k)}: ${escapeHtml(String(v))}`)
    .join("<br>");
  if (profHtml) rows.push(`<div class="ddp-kv-row"><span class="ddp-kv-label">Profiler Attrs</span><span class="ddp-kv-value ddp-ise-av">${profHtml}</span></div>`);

  // customAttributes
  const custom = ep.customAttributes || {};
  const custEntries = typeof custom === "object" ? Object.entries(custom) : [];
  const custHtml = custEntries
    .filter(([, v]) => v !== null && v !== "")
    .map(([k, v]) => `${escapeHtml(k)}: ${escapeHtml(String(v))}`)
    .join("<br>");
  if (custHtml) rows.push(`<div class="ddp-kv-row"><span class="ddp-kv-label">Custom Attrs</span><span class="ddp-kv-value ddp-ise-av">${custHtml}</span></div>`);

  // mdmAttributes
  const mdm = ep.mdmAttributes || {};
  if (mdm.mdmServerName) rows.push(_kvRow("MDM Server", escapeHtml(mdm.mdmServerName)));
  if (mdm.mdmRegistered !== undefined) rows.push(_kvRow("MDM Registered", escapeHtml(String(mdm.mdmRegistered))));
  if (mdm.mdmComplianceStatus) rows.push(_kvRow("MDM Compliance", escapeHtml(mdm.mdmComplianceStatus)));

  if (rows.length === 0) {
    return '<div class="ddp-empty">Endpoint found but no displayable fields.</div>';
  }
  return `<div class="ddp-kv-grid">${rows.join("")}</div>`;
}

function _renderIseHistoryTable(records) {
  // Priority columns shown first (in order), then all remaining non-empty fields
  const PRIORITY = [
    ["timestamp",                  "Time"],
    ["passed",                     "Result"],
    ["user_name",                  "Identity"],
    ["policy_set_name",            "Policy Set"],
    ["authorization_rule",         "AuthZ Rule"],
    ["selected_azn_profiles",      "AuthZ Profile"],
    ["authentication_method",      "Auth Method"],
    ["authentication_protocol",    "Protocol"],
    ["framed_ip_address",          "Device IP"],
    ["endpoint_profile",           "Profile"],
    ["endpoint_operating_system",  "OS"],
    ["failure_reason",             "Failure Reason"],
    ["nas_ip_address",             "NAS IP"],
    ["nas_port_id",                "NAS Port"],
  ];
  const priorityKeys = new Set(PRIORITY.map(([k]) => k));

  // Collect all keys that appear in at least one record with a value
  const allKeys = new Set();
  for (const rec of records) {
    for (const [k, v] of Object.entries(rec)) {
      if (v !== undefined && v !== null && v !== "") allKeys.add(k);
    }
  }

  // Build ordered column list: priority first (if present), then extras
  const cols = [];
  for (const [key, label] of PRIORITY) {
    if (allKeys.has(key)) cols.push([key, label]);
  }
  for (const key of allKeys) {
    if (!priorityKeys.has(key)) {
      // convert snake_case / camelCase to readable label
      const label = key.replace(/_/g, " ").replace(/([A-Z])/g, " $1").trim()
                       .replace(/\b\w/g, (c) => c.toUpperCase());
      cols.push([key, label]);
    }
  }

  const headerCells = cols.map(([, label]) => `<th>${escapeHtml(label)}</th>`).join("");

  const bodyRows = records.map((rec) => {
    const passed = rec.passed === true || rec.passed === "true" || rec.passed === "Pass";
    const cells = cols.map(([c]) => {
      let val = rec[c];
      if (val === undefined || val === null) val = "";
      if (c === "timestamp" && val) {
        try { val = new Date(val).toLocaleString(); } catch (_) {}
      } else if (c === "passed") {
        val = passed ? "&#10003; Pass" : "&#10005; Fail";
      }
      const cls = c === "passed" ? (passed ? " class=\"ise-hist-pass\"" : " class=\"ise-hist-fail\"") : "";
      const display = String(val);
      return `<td${cls}>${display ? escapeHtml(display) : "<span class=\"ise-hist-empty\">—</span>"}</td>`;
    }).join("");
    return `<tr>${cells}</tr>`;
  }).join("");

  return `
    <div class="ise-hist-scroll">
      <table class="ise-hist-table">
        <thead><tr>${headerCells}</tr></thead>
        <tbody>${bodyRows}</tbody>
      </table>
    </div>`;
}

// ANC Policy controls

async function fetchAncPolicies() {
  const select = document.getElementById("ddpAncSelect");
  const btn = document.getElementById("ddpAncLoadBtn");
  if (!select || !btn) return;
  btn.disabled = true;
  btn.textContent = "Loading…";
  try {
    const data = await fetchJSON("/api/ise/anc-policies");
    if (data.status === "ok" && data.policies && data.policies.length > 0) {
      select.innerHTML = data.policies.map((p) => `<option value="${escapeHtml(p)}">${escapeHtml(p)}</option>`).join("");
      select.disabled = false;
      document.getElementById("ddpAncApplyBtn").disabled = false;
      showToast(`Loaded ${data.policies.length} ANC policies`, "success");
    } else {
      select.innerHTML = `<option disabled>No policies found</option>`;
      showToast(data.message || "No ANC policies in ISE", "error");
    }
  } catch (err) {
    showToast("Failed to load ANC policies: " + err.message, "error");
  } finally {
    btn.disabled = false;
    btn.textContent = "Load Policies";
  }
}

async function applyAncPolicy() {
  if (!detailMac) return;
  const select = document.getElementById("ddpAncSelect");
  const policy = select?.value;
  if (!policy) { showToast("Select a policy first", "error"); return; }
  const macDash = detailMac.replace(/:/g, "-");
  document.getElementById("ddpAncApplyBtn").disabled = true;
  document.getElementById("ddpAncClearBtn").disabled = true;
  showToast(`Applying ANC: ${escapeHtml(policy)}…`, "info");
  try {
    const data = await fetchJSON(`/api/devices/${macDash}/coa`, {
      method: "POST",
      body: JSON.stringify({ action: `anc:${policy}` }),
    });
    if (data.status === "ok") {
      showToast(`✓ ${escapeHtml(data.message || "ANC applied")}`, "success");
    } else {
      const detail = data.detail ? ` — ${data.detail}` : "";
      showToast(`ANC failed: ${escapeHtml((data.message || "Unknown") + detail)}`, "error");
    }
  } catch (err) {
    showToast("ANC error: " + err.message, "error");
  } finally {
    document.getElementById("ddpAncApplyBtn").disabled = false;
    document.getElementById("ddpAncClearBtn").disabled = false;
  }
}

async function clearAncPolicy() {
  if (!detailMac) return;
  const macDash = detailMac.replace(/:/g, "-");
  document.getElementById("ddpAncApplyBtn").disabled = true;
  document.getElementById("ddpAncClearBtn").disabled = true;
  showToast("Clearing ANC policy…", "info");
  try {
    const data = await fetchJSON(`/api/devices/${macDash}/coa`, {
      method: "POST",
      body: JSON.stringify({ action: "anc-clear" }),
    });
    if (data.status === "ok") {
      showToast(`✓ ${escapeHtml(data.message || "ANC cleared")}`, "success");
    } else {
      const detail = data.detail ? ` — ${data.detail}` : "";
      showToast(`ANC clear failed: ${escapeHtml((data.message || "Unknown") + detail)}`, "error");
    }
  } catch (err) {
    showToast("ANC clear error: " + err.message, "error");
  } finally {
    document.getElementById("ddpAncApplyBtn").disabled = false;
    document.getElementById("ddpAncClearBtn").disabled = false;
  }
}

// Phase 3: NAD Probe

async function loadNadConfig() {
  try {
    const cfg = await fetchJSON("/api/nad/config");
    const set = (id, val) => { const el = document.getElementById(id); if (el) el.value = val || ""; };
    set("nadHost", cfg.host);
    set("nadPort", cfg.port || 22);
    set("nadUser", cfg.username);
    set("nadPass", cfg.password);
    set("nadEnablePass", cfg.enable_password);
    const dtEl = document.getElementById("nadDeviceType");
    if (dtEl) dtEl.value = cfg.device_type || "cisco_ios";
  } catch (_) {}
}

async function saveNadConfig() {
  const get = (id) => { const el = document.getElementById(id); return el ? el.value.trim() : ""; };
  const payload = {
    host: get("nadHost"),
    port: parseInt(get("nadPort") || "22", 10),
    username: get("nadUser"),
    password: get("nadPass"),
    enable_password: get("nadEnablePass"),
    device_type: (document.getElementById("nadDeviceType") || {}).value || "cisco_ios",
  };
  try {
    await fetchJSON("/api/nad/config", { method: "PUT", body: JSON.stringify(payload) });
    showToast("NAD settings saved", "success");
    // Collapse the details pane after saving
    const details = document.getElementById("nadConfigDetails");
    if (details) details.open = false;
  } catch (err) {
    showToast("Save failed: " + err.message, "error");
  }
}

async function probeSwitchNAD() {
  if (!detailMac) return;
  const macDash = detailMac.replace(/:/g, "-");
  const btn = document.getElementById("ddpNadProbeBtn");
  const container = document.getElementById("ddpNadContent");
  if (btn) btn.disabled = true;
  if (container) container.innerHTML = '<div class="ddp-ise-loading">&#8987; Probing switch via SSH&hellip;</div>';
  try {
    const result = await fetchJSONWithTimeout(`/api/devices/${macDash}/nad-probe`, { method: "POST" }, 120000);
    if (container) container.innerHTML = _renderNadResult(result);
  } catch (err) {
    if (container) container.innerHTML = `<div class="ddp-empty ddp-error-val">Probe failed: ${escapeHtml(err.message)}</div>`;
  } finally {
    if (btn) btn.disabled = false;
  }
}

// Helper: render a collapsible accordion section for the NAD probe results panel.
function _nadSection(title, badgeHtml, bodyHtml, isOpen) {
  return `<details class="nad-accordion"${isOpen ? " open" : ""}>
    <summary class="nad-accordion-summary"><span class="nad-acc-title">${title}</span>${badgeHtml ? `<span class="nad-acc-badge">${badgeHtml}</span>` : ""}</summary>
    <div class="nad-accordion-body">${bodyHtml}</div>
  </details>`;
}

function _renderNadResult(r) {
  if (r.status === "error") {
    return `<div class="ddp-empty ddp-error-val">${escapeHtml(r.message || "Unknown error")}</div>`;
  }

  const sections = [];

  // ── Compact header strip ──────────────────────────────────────────────────
  let html = `<div class="nad-header-strip">
    <span class="nad-header-item"><span class="nad-header-label">Switch</span>${escapeHtml(r.switch || "—")}</span>
    <span class="nad-header-sep">·</span>
    <span class="nad-header-item"><span class="nad-header-label">Port</span><span class="nad-header-port">${escapeHtml(r.port || "Not found")}</span></span>
    <span class="nad-header-sep">·</span>
    <span class="nad-header-item"><span class="nad-header-label">MAC</span>${escapeHtml(r.mac || "—")}</span>
  </div>`;
  if (r.warning) html += `<div class="nad-warning">&#9888;&#65039; ${escapeHtml(r.warning)}</div>`;

  const _rawOnly = (raw) =>
    `<details class="nad-raw-details" open><summary class="nad-raw-summary">Raw output</summary><div class="nad-raw-output">${escapeHtml(raw)}</div></details>`;
  const _rawBlock = (raw) =>
    raw ? `<details class="nad-raw-details"><summary class="nad-raw-summary">Raw output</summary><div class="nad-raw-output">${escapeHtml(raw)}</div></details>` : "";

  // ── Auth Session (this device) ────────────────────────────────────────────
  const AUTH_PRIORITY = [
    "Status", "User-Name", "MAC Address", "IPv4 Address", "IPv6 Address",
    "Domain", "Oper host mode", "Session timeout", "Common Session ID",
    "Acct Session ID", "Current Policy",
  ];

  function _renderSessionList(sessions, rawStr, emptyNote) {
    if (sessions.length === 0) {
      return `<div class="nad-empty-note">${escapeHtml(emptyNote)}</div>` + (rawStr ? _rawOnly(rawStr) : "");
    }
    let body = "";
    sessions.forEach((sess, idx) => {
      if (idx > 0) body += `<div class="nad-session-divider"></div>`;
      const shown = new Set();
      const kvs = [];
      for (const k of AUTH_PRIORITY) {
        if (sess[k] === undefined) continue;
        if (k === "Status") {
          const isAuth = sess[k].toLowerCase().includes("authorized");
          kvs.push(_kvRow("Status", `<span class="${isAuth ? "nad-status-ok" : "nad-status-fail"}">${escapeHtml(sess[k])}</span>`));
        } else {
          kvs.push(_kvRow(k, escapeHtml(String(sess[k]))));
        }
        shown.add(k);
      }
      if (Array.isArray(sess._method_states) && sess._method_states.length) {
        const badges = sess._method_states.map(m =>
          `<span class="nad-method-badge">${escapeHtml(m.method)}<span class="nad-method-state-val">${escapeHtml(m.state)}</span></span>`
        ).join(" ");
        kvs.push(_kvRow("Method", badges));
      }
      for (const [k, v] of Object.entries(sess)) {
        if (!shown.has(k) && k !== "_method_states" && typeof v === "string")
          kvs.push(_kvRow(k, escapeHtml(String(v))));
      }
      body += `<div class="ddp-kv-grid nad-session-grid">${kvs.join("")}</div>`;
    });
    body += _rawBlock(rawStr);
    return body;
  }

  // Primary: MAC-specific session (open)
  const macSessions = Array.isArray(r.auth_mac_sessions) ? r.auth_mac_sessions
    : (r.auth_mac_sessions && Object.keys(r.auth_mac_sessions).length ? [r.auth_mac_sessions] : []);
  if (macSessions.length > 0 || r.auth_mac_raw) {
    const s0 = macSessions[0] || {};
    const isAuth = (s0["Status"] || "").toLowerCase().includes("authorized");
    const badge = macSessions.length > 0
      ? `<span class="${isAuth ? "nad-status-ok" : "nad-status-fail"}">${escapeHtml(s0["Status"] || "Unknown")}</span>${s0["User-Name"] ? ` · ${escapeHtml(s0["User-Name"])}` : ""}`
      : `<span class="nad-status-fail">no session</span>`;
    sections.push(_nadSection("🔐 Auth Session", badge,
      _renderSessionList(macSessions, r.auth_mac_raw, "No session found for this MAC"), true));
  }

  // Secondary: all sessions on the port (collapsed for context)
  const portSessions = Array.isArray(r.auth_sessions) ? r.auth_sessions
    : (r.auth_sessions && Object.keys(r.auth_sessions).length ? [r.auth_sessions] : []);
  if (portSessions.length > 0 || r.auth_sessions_raw) {
    const badge = portSessions.length > 0
      ? `${portSessions.length} session${portSessions.length !== 1 ? "s" : ""} on port`
      : "";
    sections.push(_nadSection("🔐 All Port Sessions", badge,
      _renderSessionList(portSessions, r.auth_sessions_raw, "No sessions on this port"), false));
  }

  // ── Interface Configuration ───────────────────────────────────────────────
  if (r.run_interface || r.run_interface_raw) {
    const content = r.run_interface || "";
    const body = content
      ? `<pre class="nad-run-config">${escapeHtml(content)}</pre>`
      : `<div class="nad-empty-note">IOS output present but config could not be parsed — see raw output</div>${_rawOnly(r.run_interface_raw)}`;
    sections.push(_nadSection("⚙️ Interface Config", "", body, true));
  }

  // ── Device Sensor Cache ───────────────────────────────────────────────────
  if ((r.device_sensor && r.device_sensor.length > 0) || r.device_sensor_raw) {
    let body = "";
    if (r.device_sensor && r.device_sensor.length > 0) {
      body = `<table class="nad-sensor-table">
      <thead><tr><th>Proto</th><th>Type : Name</th><th>Data</th></tr></thead>
      <tbody>${r.device_sensor.map(e =>
        `<tr><td class="nad-sensor-proto">${escapeHtml(e.proto)}</td><td class="nad-sensor-type">${escapeHtml(e.type_name)}</td><td class="nad-sensor-data">${escapeHtml(e.data)}</td></tr>`
      ).join("")}</tbody></table>`;
      body += _rawBlock(r.device_sensor_raw);
    } else {
      body = `<div class="nad-empty-note">No sensor entries parsed (device-sensor may not be enabled) — see raw output</div>${_rawOnly(r.device_sensor_raw)}`;
    }
    const badge = r.device_sensor && r.device_sensor.length > 0 ? `${r.device_sensor.length} entries` : "";
    sections.push(_nadSection("📡 Device Sensor", badge, body, true));
  }

  // ── Device Tracking Database ──────────────────────────────────────────────
  if ((r.device_tracking && r.device_tracking.length > 0) || r.device_tracking_raw) {
    let body = "";
    if (r.device_tracking && r.device_tracking.length > 0) {
      body = `<table class="nad-sensor-table">
      <thead><tr><th>Type</th><th>Address</th><th>Interface</th><th>VLAN</th><th>Age</th><th>State</th></tr></thead>
      <tbody>${r.device_tracking.map(e =>
        `<tr>
          <td class="nad-sensor-proto">${escapeHtml(e.type)}</td>
          <td class="nad-sensor-data">${escapeHtml(e.address)}</td>
          <td class="nad-sensor-type">${escapeHtml(e.interface)}</td>
          <td>${escapeHtml(e.vlan)}</td>
          <td>${escapeHtml(e.age)}</td>
          <td class="${(e.state || "").toUpperCase() === "REACHABLE" ? "nad-status-ok" : ""}">${escapeHtml(e.state)}</td>
        </tr>`
      ).join("")}</tbody></table>`;
      body += _rawBlock(r.device_tracking_raw);
    } else {
      body = `<div class="nad-empty-note">No tracking entries parsed — see raw output</div>${_rawOnly(r.device_tracking_raw)}`;
    }
    const badge = r.device_tracking && r.device_tracking.length > 0 ? `${r.device_tracking.length} entries` : "";
    sections.push(_nadSection("🗄️ Device Tracking", badge, body, false));
  }

  // ── dot1x Interface Detail ────────────────────────────────────────────────
  if ((r.dot1x && Object.keys(r.dot1x).length > 0) || r.dot1x_raw) {
    let body = "";
    if (r.dot1x && Object.keys(r.dot1x).length > 0) {
      body = `<div class="ddp-kv-grid">${Object.entries(r.dot1x).map(([k, v]) => _kvRow(k, escapeHtml(String(v)))).join("")}</div>`;
      body += _rawBlock(r.dot1x_raw);
    } else {
      body = `<div class="nad-empty-note">No dot1x fields parsed — see raw output</div>${_rawOnly(r.dot1x_raw)}`;
    }
    sections.push(_nadSection("🔑 dot1x Interface", "", body, false));
  }

  // ── Spanning Tree ─────────────────────────────────────────────────────────
  if (r.spanning_tree && Object.keys(r.spanning_tree).length > 0) {
    const st = r.spanning_tree;
    const badge = [st.stp_vlan, st.stp_role, st.stp_state].filter(Boolean).join(" · ");
    const body = `<div class="ddp-kv-grid">${Object.entries(r.spanning_tree).map(([k, v]) => _kvRow(k, escapeHtml(String(v)))).join("")}</div>`;
    sections.push(_nadSection("🌳 Spanning Tree", badge, body, false));
  }

  // ── MAC Address Table (always collapsed — reference only) ─────────────────
  if (r.mac_table) {
    sections.push(_nadSection("📋 MAC Address Table", "", `<div class="nad-raw-output">${escapeHtml(r.mac_table)}</div>`, false));
  }

  return html + `<div class="nad-sections">${sections.join("")}</div>`;
}


/* ─── Init ────────────────────────────────────────────────────────── */

loadInterface();
loadSettings();
loadISEConfig();
loadNDESConfig();
loadDot1xReadiness();
loadNadConfig();
refreshCertTable();
refreshAll();
setInterval(refreshAll, POLL_INTERVAL);