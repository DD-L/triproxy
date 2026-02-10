# TriProxy

TriProxy is a cross-platform encrypted tunnel proxy system with three components:

- `agent/` (A): runs in internal network near target services
- `relay/` (B): public relay with dual ports (agent/client separated)
- `client/` (C): local controller, dashboard, and terminal entry

The implementation follows `thoughts/design.md` as the primary design source.

## Quick Start (Single-Machine Debug)

1. Create environment and install deps:

```bash
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
```

2. Generate keys:

```bash
.venv\Scripts\python certs/generate_keys.py --output certs/
```

3. Start services in separate terminals:

```bash
.venv\Scripts\python -m relay.main config/relay.yaml
.venv\Scripts\python -m agent.main config/agent.yaml
.venv\Scripts\python -m client.main config/client.yaml
```

4. Open:

- C dashboard: `http://127.0.0.1:3001/dashboard`
- C terminal: `http://127.0.0.1:3001/terminal`
- A console: `http://127.0.0.1:3002`

## Notes

- All control/pool/session network messages use AES-GCM over public network.
- Relay remains byte-transparent for session payload bridging.
- The current repository includes local static vendor placeholders for terminal UI libraries; replace them with full upstream bundles for production-grade terminal UX.
- On Windows agent shell, `shell_windows_backend` supports `auto|conpty|subprocess` and defaults to `auto` with ConPTY probe + fallback.

