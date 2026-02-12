async function getJson(url, options) {
  const r = await fetch(url, options || {});
  const text = await r.text();
  let data = {};
  try { data = JSON.parse(text); } catch {}
  if (!r.ok) {
    throw new Error(data.error || `${r.status} ${r.statusText}`);
  }
  return data;
}

let loadedRawConfig = {};
let sessionPasswordHash = "";

function hexToBytes(hex) {
  const normalized = String(hex || "").trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(normalized)) {
    throw new Error("invalid password hash");
  }
  const out = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < normalized.length; i += 2) {
    out[i / 2] = parseInt(normalized.slice(i, i + 2), 16);
  }
  return out;
}

function bytesToBase64(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

async function encryptRelayPublicPem(pemText, passwordHash) {
  if (!window.crypto || !window.crypto.subtle) {
    throw new Error("browser crypto not available");
  }
  const keyBytes = hexToBytes(passwordHash);
  const key = await window.crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM" },
    false,
    ["encrypt"]
  );
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const aad = new TextEncoder().encode("relay_public_upload_v1");
  const plaintext = new TextEncoder().encode(pemText);
  const ciphertext = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aad },
    key,
    plaintext
  );
  return {
    iv_b64: bytesToBase64(iv),
    ciphertext_b64: bytesToBase64(new Uint8Array(ciphertext)),
  };
}

function show(msg) {
  document.getElementById("auth-msg").textContent = msg;
}

async function login() {
  const pwd = document.getElementById("password").value || "";
  const pHash = sha256(pwd);
  const nonceResp = await getJson("/api/nonce");
  const nonce = nonceResp.nonce;
  const response = sha256(pHash + nonce);
  const loginResp = await getJson("/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ nonce, response }),
  });
  sessionPasswordHash = pHash;
  document.getElementById("auth").style.display = "none";
  document.getElementById("panel").style.display = "";
  if (loginResp.force_change_password) {
    show('default password detected, please change password first');
  } else {
    show("");
  }
  await refreshStatus();
}

async function setPasswordFirstBoot() {
  const pwd = document.getElementById("password").value || "";
  if (!pwd) {
    show("password required");
    return;
  }
  const newHash = sha256(pwd);
  await getJson("/api/password", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ new_password_hash: newHash }),
  });
  show("password updated, now click Login");
}

async function refreshStatus() {
  const data = await getJson("/api/status");
  document.getElementById("status").textContent = JSON.stringify(data, null, 2);
  if (data.agent_id) {
    document.getElementById("agent-name").value = data.agent_id;
  }
  document.getElementById("relay-config-path").value = data.relay_config_path || "";
  const running = Boolean(data.agent_process && data.agent_process.running);
  const forceChange = Boolean(data.force_change_password);
  const startBtn = document.getElementById("start-btn");
  const stopBtn = document.getElementById("stop-btn");
  const restartBtn = document.getElementById("restart-btn");
  startBtn.style.display = running ? "none" : "";
  stopBtn.style.display = running ? "" : "none";
  restartBtn.style.display = running ? "" : "none";
  if (forceChange) {
    startBtn.style.display = "none";
    stopBtn.style.display = "none";
    restartBtn.style.display = "none";
  }
}

function renderSelfCheck(data) {
  const out = document.getElementById("self-check-result");
  if (!data || typeof data !== "object") {
    out.textContent = "self check failed: invalid response";
    return;
  }
  const lines = [];
  lines.push("Self-check initiator: Agent side (Agent Web Console)");
  lines.push(`Overall: ${data.ok ? "OK" : "HAS ISSUES"}`);
  lines.push(`Agent: ${data.agent_id || "-"}`);
  lines.push(`Errors: ${Number(data.issue_count || 0)}, Warnings: ${Number(data.warning_count || 0)}`);
  const checks = Array.isArray(data.checks) ? data.checks : [];
  for (const c of checks) {
    if (c.ok) continue;
    const level = (c.level || "error").toUpperCase();
    lines.push("");
    lines.push(`[${level}] ${c.name || "unknown_check"}`);
    if (c.reason) lines.push(`Reason: ${c.reason}`);
    if (c.suggestion) lines.push(`Suggestion: ${c.suggestion}`);
  }
  if (checks.every((c) => c && c.ok)) {
    lines.push("");
    lines.push("No problems detected.");
  }
  out.textContent = lines.join("\n");
}

async function loadAgentConfig() {
  const data = await getJson("/api/config");
  const cfg = data.config || {};
  loadedRawConfig = (data.raw_config && typeof data.raw_config === "object") ? { ...data.raw_config } : {};
  document.getElementById("cfg-relay-host").value = cfg.relay_host || "";
  document.getElementById("cfg-relay-port").value = cfg.relay_port_agent || 8080;
  document.getElementById("cfg-heartbeat").value = cfg.heartbeat_interval || 100;
  document.getElementById("cfg-log-level").value = cfg.log_level || "info";
  document.getElementById("cfg-auto-restart").checked = Boolean(cfg.auto_restart);
}

document.getElementById("login-btn").addEventListener("click", () => {
  login().catch((e) => show(String(e.message || e)));
});

document.getElementById("set-btn").addEventListener("click", () => {
  setPasswordFirstBoot().catch((e) => show(String(e.message || e)));
});

document.getElementById("refresh-btn").addEventListener("click", () => {
  Promise.all([refreshStatus(), loadAgentConfig()]).catch(console.error);
});

document.getElementById("self-check-btn").addEventListener("click", async () => {
  try {
    const data = await getJson("/api/self-check");
    renderSelfCheck(data);
  } catch (e) {
    document.getElementById("self-check-result").textContent = `self check failed: ${String(e.message || e)}`;
  }
});

document.getElementById("start-btn").addEventListener("click", async () => {
  await getJson("/api/start", { method: "POST" });
  await refreshStatus();
});

document.getElementById("stop-btn").addEventListener("click", async () => {
  await getJson("/api/stop", { method: "POST" });
  await refreshStatus();
});

document.getElementById("restart-btn").addEventListener("click", async () => {
  await getJson("/api/restart", { method: "POST" });
  await refreshStatus();
});

document.getElementById("load-config-btn").addEventListener("click", async () => {
  await loadAgentConfig();
  show("config loaded");
});

document.getElementById("save-config-btn").addEventListener("click", async () => {
  const payload = (loadedRawConfig && typeof loadedRawConfig === "object") ? { ...loadedRawConfig } : {};
  payload.relay_host = (document.getElementById("cfg-relay-host").value || "").trim();
  payload.relay_port_agent = Number(document.getElementById("cfg-relay-port").value || 0);
  payload.heartbeat_interval = Number(document.getElementById("cfg-heartbeat").value || 0);
  payload.log_level = document.getElementById("cfg-log-level").value || "info";
  payload.auto_restart = Boolean(document.getElementById("cfg-auto-restart").checked);
  const res = await getJson("/api/config", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ config: payload }),
  });
  if (res.hot_reload_applied) {
    show("config saved and hot reloaded");
  } else if (res.hot_reload_attempted && res.hot_reload_error) {
    show(`config saved, hot reload failed: ${res.hot_reload_error}`);
  } else if (res.restart_required) {
    show("config saved, restart required");
  } else {
    show("config saved");
  }
  await Promise.all([refreshStatus(), loadAgentConfig()]);
});

document.getElementById("change-password-btn").addEventListener("click", async () => {
  const pwd = document.getElementById("new-password").value || "";
  if (!pwd) {
    show("new password required");
    return;
  }
  await getJson("/api/password", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ new_password_hash: sha256(pwd) }),
  });
  sessionPasswordHash = sha256(pwd);
  show("password changed");
  document.getElementById("new-password").value = "";
  await refreshStatus();
});

document.getElementById("rename-agent-btn").addEventListener("click", async () => {
  const agentId = (document.getElementById("agent-name").value || "").trim();
  if (!agentId) {
    show("agent name required");
    return;
  }
  await getJson("/api/agent_name", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ agent_id: agentId }),
  });
  show("agent renamed, restart required");
  await refreshStatus();
});

async function scheduleAction(mode, action) {
  const body = { mode, action };
  if (mode === "after") {
    const seconds = Number(document.getElementById("schedule-after").value || 0);
    if (!Number.isFinite(seconds) || seconds <= 0) {
      show("after seconds must be > 0");
      return;
    }
    body.after_seconds = seconds;
  } else {
    const at = (document.getElementById("schedule-at").value || "").trim();
    if (!at) {
      show("at time required (HH:MM:SS)");
      return;
    }
    body.at_time = at;
  }
  await getJson("/api/schedule", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  show(`scheduled ${action} (${mode})`);
  await refreshStatus();
}

document.getElementById("schedule-connect-after-btn").addEventListener("click", () => {
  scheduleAction("after", "connect").catch((e) => show(String(e.message || e)));
});
document.getElementById("schedule-disconnect-after-btn").addEventListener("click", () => {
  scheduleAction("after", "disconnect").catch((e) => show(String(e.message || e)));
});
document.getElementById("schedule-connect-at-btn").addEventListener("click", () => {
  scheduleAction("at", "connect").catch((e) => show(String(e.message || e)));
});
document.getElementById("schedule-disconnect-at-btn").addEventListener("click", () => {
  scheduleAction("at", "disconnect").catch((e) => show(String(e.message || e)));
});

document.getElementById("regen-cert-btn").addEventListener("click", async () => {
  const ok = window.confirm(
    "Regenerate Cert Pair will overwrite existing agent private/public keys. Continue?\n\nNew cert pair takes effect only after Agent restart."
  );
  if (!ok) {
    return;
  }
  const data = await getJson("/api/certs/regenerate", { method: "POST" });
  const relayInfo = data.relay_trust || {};
  show("cert pair regenerated (old keys overwritten). Restart Agent to apply.");
  document.getElementById("relay-check-result").textContent = relayInfo.details
    ? `Relay trust: ${relayInfo.details}. ${relayInfo.suggestion || ""}`
    : "";
});

document.getElementById("upload-relay-pub-btn").addEventListener("click", async () => {
  try {
    const fileInput = document.getElementById("relay-pub-file");
    const passwordInput = document.getElementById("relay-pub-password");
    const file = fileInput && fileInput.files && fileInput.files[0];
    if (!file) {
      show("select relay public key file first");
      return;
    }
    const pem = await file.text();
    if (!pem.includes("BEGIN PUBLIC KEY") && !pem.includes("BEGIN RSA PUBLIC KEY")) {
      show("invalid relay public key file");
      return;
    }
    const uploadPassword = (passwordInput.value || "").trim();
    const passwordHash = uploadPassword ? sha256(uploadPassword) : sessionPasswordHash;
    if (!passwordHash) {
      show("console password required for encrypted upload");
      return;
    }
    const encrypted = await encryptRelayPublicPem(pem, passwordHash);
    const res = await getJson("/api/certs/relay_public", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(encrypted),
    });
    passwordInput.value = "";
    fileInput.value = "";
    if (res.hot_reload_applied) {
      show(`relay public key uploaded to ${res.relay_public_key_path}, hot reloaded`);
    } else if (res.hot_reload_attempted && res.hot_reload_error) {
      show(`relay public key uploaded, hot reload failed: ${res.hot_reload_error}`);
    } else if (res.restart_required) {
      show(`relay public key uploaded to ${res.relay_public_key_path}, restart required`);
    } else {
      show(`relay public key uploaded to ${res.relay_public_key_path}`);
    }
    await Promise.all([refreshStatus(), loadAgentConfig()]);
  } catch (e) {
    const msg = String((e && e.message) || e || "");
    if (msg.includes("incorrect_password")) {
      const tip = "密码错误，请重新输入后再试";
      show(tip);
      window.alert(tip);
      return;
    }
    show(msg || "upload failed");
  }
});

document.getElementById("pubkey-link-btn").addEventListener("click", async () => {
  const data = await getJson("/api/certs/public_link");
  const el = document.getElementById("pubkey-link");
  const safeUrl = String(data.url || "");
  el.innerHTML = `<a href="${safeUrl}" target="_blank" rel="noopener noreferrer">Download Public Key</a>`;
});

document.getElementById("relay-check-btn").addEventListener("click", async () => {
  const data = await getJson("/api/certs/relay_check");
  const relay = data.relay_trust || {};
  const text = relay.details
    ? `Relay trust: ${relay.details}. ${relay.suggestion || ""}`
    : "relay trust check unavailable";
  document.getElementById("relay-check-result").textContent = text;
});

document.getElementById("save-relay-path-btn").addEventListener("click", async () => {
  const path = (document.getElementById("relay-config-path").value || "").trim();
  const data = await getJson("/api/relay_config_path", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ relay_config_path: path }),
  });
  const relay = data.relay_trust || {};
  const text = relay.details
    ? `Relay trust: ${relay.details}. ${relay.suggestion || ""}`
    : "relay config path saved";
  document.getElementById("relay-check-result").textContent = text;
  await refreshStatus();
});

document.getElementById("new-shell-btn").addEventListener("click", async () => {
  const resp = await getJson("/api/terminal/new", { method: "POST" });
  window.open(`/terminal?session_id=${encodeURIComponent(resp.session_id)}&encoding=auto`, "_blank");
});

document.getElementById("logout-btn").addEventListener("click", async () => {
  await getJson("/api/logout");
  sessionPasswordHash = "";
  document.getElementById("panel").style.display = "none";
  document.getElementById("auth").style.display = "";
  document.getElementById("pubkey-link").textContent = "";
  document.getElementById("pubkey-link").innerHTML = "";
  document.getElementById("relay-check-result").textContent = "";
  document.getElementById("self-check-result").textContent = "";
});

loadAgentConfig().catch(() => {});

