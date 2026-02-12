async function getJson(url, options) {
  const r = await fetch(url, options || {});
  if (!r.ok) {
    throw new Error(`${r.status} ${r.statusText}`);
  }
  return r.json();
}

let currentServices = null;
let currentAgentId = "";
let knownAgents = [];

function withAgent(url) {
  if (!currentAgentId) return url;
  const sep = url.includes("?") ? "&" : "?";
  return `${url}${sep}agent_id=${encodeURIComponent(currentAgentId)}`;
}

async function refreshAgents(keepSelection = true) {
  const agentsResp = await getJson("/api/agents");
  knownAgents = agentsResp.agents || [];
  const sel = document.getElementById("agent-select");
  const prev = keepSelection ? sel.value : "";
  sel.innerHTML = "";
  for (const a of knownAgents) {
    const opt = document.createElement("option");
    opt.value = a.agent_id;
    opt.textContent = `${a.agent_id} (${a.connected ? "connected" : "disconnected"})`;
    sel.appendChild(opt);
  }
  const preferred = prev || agentsResp.current_agent_id || (knownAgents[0] && knownAgents[0].agent_id) || "";
  if (preferred) {
    sel.value = preferred;
    currentAgentId = preferred;
  }
  document.getElementById("agent-list").textContent = JSON.stringify(agentsResp, null, 2);
}

async function refresh() {
  await refreshAgents();
  const status = await getJson(withAgent("/api/status"));
  const services = await getJson(withAgent("/api/services"));
  currentServices = services;
  const connected = Boolean(status.connected);
  document.getElementById("status").textContent = JSON.stringify(status, null, 2);
  document.getElementById("directed-rules").textContent = JSON.stringify(services.directed, null, 2);
  const generalEnabled = Boolean(services.general?.enabled);
  const generalBind = services.general?.bind || "127.0.0.1";
  const generalPort = services.general?.local_port || 3000;
  document.getElementById("general-bind-port").textContent = `Local bind: ${generalBind}:${generalPort}`;
  document.getElementById("toggle-general-btn").textContent = generalEnabled
    ? "Disable General Proxy"
    : "Enable General Proxy";
  const resetBtn = document.getElementById("agent-password-btn");
  const restartAgentBtn = document.getElementById("agent-restart-btn");
  const restartRelayBtn = document.getElementById("relay-reload-btn");
  resetBtn.disabled = !connected;
  restartAgentBtn.disabled = !connected;
  restartRelayBtn.disabled = !connected;
  if (!connected) {
    document.getElementById("agent-password-result").textContent = "Agent is not connected.";
  }
}

function renderSelfCheck(data) {
  const out = document.getElementById("self-check");
  if (!data || typeof data !== "object") {
    out.textContent = "self check failed: invalid response";
    return;
  }
  const lines = [];
  lines.push("Self-check initiator: Client side (Client Dashboard)");
  lines.push(`Overall: ${data.ok ? "OK" : "HAS ISSUES"}`);
  lines.push(`Agent: ${data.agent_id || "-"}`);
  lines.push(`Errors: ${Number(data.issue_count || 0)}, Warnings: ${Number(data.warning_count || 0)}`);
  const checks = Array.isArray(data.checks) ? data.checks : [];
  for (const c of checks) {
    if (c.ok) continue;
    const level = (c.level || "error").toUpperCase();
    lines.push("");
    lines.push(`[${level}] ${c.name || "unknown_check"}`);
    if (Object.prototype.hasOwnProperty.call(c, "latency_ms") && c.latency_ms !== null) {
      lines.push(`Latency(ms): ${Number(c.latency_ms)}`);
    }
    if (Object.prototype.hasOwnProperty.call(c, "skipped")) {
      lines.push(`Skipped: ${Boolean(c.skipped) ? "yes" : "no"}`);
    }
    if (c.reason) lines.push(`Reason: ${c.reason}`);
    if (c.suggestion) lines.push(`Suggestion: ${c.suggestion}`);
  }
  if (checks.every((c) => c && c.ok)) {
    lines.push("");
    lines.push("No problems detected.");
  }
  out.textContent = lines.join("\n");
}

async function runSelfCheck() {
  const data = await getJson(withAgent("/api/self-check"));
  renderSelfCheck(data);
}

document.getElementById("new-shell-btn").addEventListener("click", async () => {
  const resp = await getJson(withAgent("/api/terminal/new"), { method: "POST" });
  const aid = encodeURIComponent(currentAgentId);
  window.open(`/terminal?session_id=${resp.session_id}&agent_id=${aid}`, "_blank");
});

document.getElementById("add-rule-btn").addEventListener("click", async () => {
  const id = prompt("Rule ID", `rule-${Date.now()}`);
  const port = prompt("Local Port", "3005");
  const target = prompt("Target URL", "http://example.com:80");
  if (!id || !port || !target) return;
  await getJson(withAgent("/api/services/directed"), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id, local_port: Number(port), target_url: target, enabled: true }),
  });
  await refresh();
});

document.getElementById("toggle-general-btn").addEventListener("click", async () => {
  const nextEnabled = !(currentServices?.general?.enabled ?? true);
  await getJson(withAgent("/api/services/general/toggle"), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ enabled: nextEnabled }),
  });
  await refresh();
});

document.getElementById("agent-password-btn").addEventListener("click", async () => {
  const pwdInput = document.getElementById("agent-password");
  const msg = document.getElementById("agent-password-result");
  const pwd = pwdInput.value || "";
  if (!pwd) {
    msg.textContent = "password required";
    return;
  }
  if (pwd.length < 8) {
    msg.textContent = "password too short (at least 8 chars)";
    return;
  }
  try {
    await getJson(withAgent("/api/agent/password"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ new_password_hash: sha256(pwd) }),
    });
    pwdInput.value = "";
    msg.textContent = "agent password updated";
  } catch (e) {
    msg.textContent = `update failed: ${String(e.message || e)}`;
  }
});

document.getElementById("agent-restart-btn").addEventListener("click", async () => {
  const msg = document.getElementById("agent-password-result");
  try {
    await getJson(withAgent("/api/agent/restart"), { method: "POST" });
    msg.textContent = "agent restart requested";
  } catch (e) {
    msg.textContent = `agent restart failed: ${String(e.message || e)}`;
  }
});

document.getElementById("relay-reload-btn").addEventListener("click", async () => {
  const msg = document.getElementById("agent-password-result");
  try {
    await getJson(withAgent("/api/relay/reload-certs"), { method: "POST" });
    msg.textContent = "relay certs reloaded";
  } catch (e) {
    msg.textContent = `relay cert reload failed: ${String(e.message || e)}`;
  }
});

document.getElementById("agent-select").addEventListener("change", async (ev) => {
  currentAgentId = ev.target.value || "";
  if (currentAgentId) {
    await getJson("/api/agents/select", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ agent_id: currentAgentId }),
    });
  }
  await refresh();
});

document.getElementById("refresh-agents-btn").addEventListener("click", async () => {
  await refresh();
});

document.getElementById("self-check-btn").addEventListener("click", async () => {
  try {
    await runSelfCheck();
  } catch (e) {
    document.getElementById("self-check").textContent = `self check failed: ${String(e.message || e)}`;
  }
});

setInterval(refresh, 3000);
refresh().catch(console.error);

