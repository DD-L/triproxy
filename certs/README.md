# TriProxy Certs

Generate RSA keys:

```bash
python certs/generate_keys.py --output certs/
```

This creates:

- `agent_private.pem`, `agent_public.pem`
- `relay_private.pem`, `relay_public.pem`
- `client_private.pem`, `client_public.pem`

Use the printed SHA256 fingerprints in `relay.yaml` for `allowed_agents` and `allowed_clients`.

