(async () => {
  const term = new Terminal({ convertEol: true, cursorBlink: true });
  const fitAddon = new FitAddon.FitAddon();
  term.loadAddon(fitAddon);
  term.open(document.getElementById("terminal"));
  fitAddon.fit();

  const params = new URLSearchParams(window.location.search);
  let sessionId = params.get("session_id");
  const agentId = params.get("agent_id");
  const outputEncoding = (params.get("encoding") || "auto").trim().toLowerCase() || "auto";
  let utf8Decoder;
  let gbDecoder;
  let utf16leDecoder;
  try {
    utf8Decoder = new TextDecoder("utf-8");
  } catch {
    utf8Decoder = new TextDecoder();
  }
  try {
    gbDecoder = new TextDecoder("gb18030");
  } catch {
    gbDecoder = utf8Decoder;
  }
  try {
    utf16leDecoder = new TextDecoder("utf-16le");
  } catch {
    utf16leDecoder = utf8Decoder;
  }

  function decodeChunk(data) {
    if (typeof data === "string") return data;
    const bytes = new Uint8Array(data);
    if (outputEncoding && outputEncoding !== "auto") {
      try {
        return new TextDecoder(outputEncoding).decode(bytes);
      } catch {
        return utf8Decoder.decode(bytes);
      }
    }
    // Heuristic: PowerShell redirected output can be UTF-16LE.
    if (bytes.length >= 2) {
      let zeroOdd = 0;
      let zeroEven = 0;
      for (let i = 0; i < bytes.length; i++) {
        if (bytes[i] === 0) {
          if (i % 2 === 0) zeroEven++;
          else zeroOdd++;
        }
      }
      const half = Math.max(1, Math.floor(bytes.length / 2));
      if (zeroOdd > half / 2 || zeroEven > half / 2) {
        return utf16leDecoder.decode(bytes);
      }
    }
    try {
      const s = utf8Decoder.decode(bytes);
      // If replacement chars are too many, likely not UTF-8.
      const bad = (s.match(/\uFFFD/g) || []).length;
      if (bad <= Math.max(2, Math.floor(s.length / 20))) {
        return s;
      }
    } catch {}
    return gbDecoder.decode(bytes);
  }
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
    const txt = decodeChunk(ev.data);
    term.write(txt);
  };

  window.addEventListener("resize", () => {
    fitAddon.fit();
    ws.send(JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows }));
  });
})();
