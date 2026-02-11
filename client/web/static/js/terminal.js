(async () => {
  const term = new Terminal({ convertEol: true, cursorBlink: true });
  const fitAddon = new FitAddon.FitAddon();
  term.loadAddon(fitAddon);
  term.open(document.getElementById("terminal"));
  fitAddon.fit();

  const params = new URLSearchParams(window.location.search);
  let sessionId = params.get("session_id");
  const agentId = params.get("agent_id");
  if (!sessionId) {
    const api = agentId ? `/api/terminal/new?agent_id=${encodeURIComponent(agentId)}` : "/api/terminal/new";
    const resp = await fetch(api, { method: "POST" });
    const json = await resp.json();
    sessionId = json.session_id;
  }
  const wsProto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${wsProto}://${location.host}/ws/terminal/${sessionId}`);
  ws.binaryType = "arraybuffer";

  term.onData((data) => {
    ws.send(JSON.stringify({ type: "data", data }));
  });

  ws.onmessage = (ev) => {
    if (typeof ev.data === "string") {
      term.write(ev.data);
      return;
    }
    const txt = new TextDecoder().decode(ev.data);
    term.write(txt);
  };

  window.addEventListener("resize", () => {
    fitAddon.fit();
    ws.send(JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows }));
  });
})();

