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

function show(msg) {
  document.getElementById("auth-msg").textContent = msg;
}

async function login() {
  const pwd = document.getElementById("password").value || "";
  const pHash = sha256(pwd);
  const nonceResp = await getJson("/api/nonce");
  const nonce = nonceResp.nonce;
  const response = sha256(pHash + nonce);
  await getJson("/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ nonce, response }),
  });
  document.getElementById("auth").style.display = "none";
  document.getElementById("panel").style.display = "";
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
}

document.getElementById("login-btn").addEventListener("click", () => {
  login().catch((e) => show(String(e.message || e)));
});

document.getElementById("set-btn").addEventListener("click", () => {
  setPasswordFirstBoot().catch((e) => show(String(e.message || e)));
});

document.getElementById("refresh-btn").addEventListener("click", () => {
  refreshStatus().catch(console.error);
});

document.getElementById("connect-btn").addEventListener("click", async () => {
  await getJson("/api/connect", { method: "POST" });
  await refreshStatus();
});

document.getElementById("disconnect-btn").addEventListener("click", async () => {
  await getJson("/api/disconnect", { method: "POST" });
  await refreshStatus();
});

document.getElementById("logout-btn").addEventListener("click", async () => {
  await getJson("/api/logout");
  document.getElementById("panel").style.display = "none";
  document.getElementById("auth").style.display = "";
});

