# Ploinky Wormhole Server

Public rendezvous and signaling server for `did:wormhole`.

## Quick start

```bash
npm test
npm start
```

For production-like use, set at least:

```bash
export BOOTSTRAP_TOKEN="$(openssl rand -base64 32)"
export ADMIN_TOKEN="$(openssl rand -base64 32)"
export FORWARD_PROTOCOL=https
export ALLOW_INSECURE_FORWARDING=false
```

## Documentation

- `docs/index.html`
- `docs/specsLoader.html?spec=matrix.md`
- `docs/operations.html`
- `docs/deployment.html`
