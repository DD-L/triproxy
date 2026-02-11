async function getJson(url, options) {
  const r = await fetch(url, options || {});
  if (!r.ok) {
    throw new Error(`${r.status} ${r.statusText}`);
  }
  return r.json();
}

let currentServices = null;

async function refresh() {
  const status = await getJson("/api/status");
  const services = await getJson("/api/services");
  currentServices = services;
  document.getElementById("status").textContent = JSON.stringify(status, null, 2);
  document.getElementById("directed-rules").textContent = JSON.stringify(services.directed, null, 2);
  const generalEnabled = Boolean(services.general?.enabled);
  document.getElementById("toggle-general-btn").textContent = generalEnabled
    ? "Disable General Proxy"
    : "Enable General Proxy";
}

document.getElementById("new-shell-btn").addEventListener("click", async () => {
  const resp = await getJson("/api/terminal/new", { method: "POST" });
  window.open(`/terminal?session_id=${resp.session_id}`, "_blank");
});

document.getElementById("add-rule-btn").addEventListener("click", async () => {
  const id = prompt("Rule ID", `rule-${Date.now()}`);
  const port = prompt("Local Port", "3005");
  const target = prompt("Target URL", "http://example.com:80");
  if (!id || !port || !target) return;
  await getJson("/api/services/directed", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id, local_port: Number(port), target_url: target, enabled: true }),
  });
  await refresh();
});

document.getElementById("toggle-general-btn").addEventListener("click", async () => {
  const nextEnabled = !(currentServices?.general?.enabled ?? true);
  await getJson("/api/services/general/toggle", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ enabled: nextEnabled }),
  });
  await refresh();
});

setInterval(refresh, 3000);
refresh().catch(console.error);

