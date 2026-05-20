---
id: DS002
title: Runtime Architecture
status: accepted
owner: repository
summary: Describes runtime components, state partitions, trusted-proxy IP resolution, forwarding, observability, admin state, and cleanup lifecycle.
---

# DS002 Runtime Architecture

## Introduction

This specification defines runtime architecture constraints for the Ploinky Wormhole server implementation. The runtime remains a small Node.js HTTP service, but it now includes explicit operational surfaces for readiness, admin observability, manual blocklist persistence, and bounded abuse automation.

## Core Content

### Process Model

The runtime exposes a single HTTP service process built on Node.js `http` module. It handles request parsing, endpoint routing, validation, signature verification, forwarding, queue management, admin surfaces, and bounded abuse monitoring without external runtime dependencies.

Server-level timeouts are mandatory. Request timeout, header timeout, socket timeout, keep-alive timeout, and max-requests-per-socket limits must all remain configurable and enabled.

### Module Separation

Runtime code is organized into focused modules under `src/`:

| Module | Responsibility |
| --- | --- |
| `server.mjs` | HTTP server bootstrap, lifecycle management, timeout configuration. |
| `app.mjs` | Request handler, endpoint routing, validation, forwarding, queue management, admin APIs. |
| `config.mjs` | Configuration defaults, environment variable loading, limits response builder. |
| `did.mjs` | DID parsing, validation, fingerprint computation, HTTP error creation. |
| `signatures.mjs` | Canonical payload construction, signature verification, replay key building, clock skew checking. |
| `storage.mjs` | DID state persistence with atomic JSON writes. |
| `admin-state.mjs` | Persistent manual blocklist storage with atomic JSON writes. |
| `observability.mjs` | Request metrics, bounded security-event ring buffer, offense tracking, attack-level inference, auto-block TTL state. |
| `rate-limit.mjs` | Fixed-window rate limiting with penalty backoff. |

### State Partitions

The runtime partitions state into durable and temporary segments.

| Segment | Structure | Lifetime |
| --- | --- | --- |
| DID state | Local JSON file via `storage.mjs`. | Persistent until update, disable, or revocation. |
| Manual admin blocklists | Local JSON file via `admin-state.mjs`. | Persistent until removed by operator. |
| Visible intents | `Map<to_did, Map<intent_id, intent>>`. | `available` and `seen` intents only, until response finalization or expiry. |
| Canonical local intent status | `Map<intent_id, intent>`. | Local recipient-side status until expiry. |
| Intent responses | `Map<to_did, Map<intent_id, response>>`. | Temporary until response expiry. |
| Signals | `Map<to_did, Map<intent_id, signal[]>>`. | Temporary until signal expiry. |
| Replay cache | `Map<replay_key, expiry_timestamp>`. | Temporary, TTL-bounded and entry-count bounded. |
| Relay cache | `Map<relay_id, expiry_timestamp>`. | Temporary, TTL-bounded and entry-count bounded. |
| Observability event buffer | Array ring buffer. | Temporary, fixed-size. |
| Offender / auto-block tracking | `Map<principal, offense state>`. | Temporary, TTL/decay-bounded. |

### DID Parsing and Validation

DID strings follow the pattern `did:wormhole:<domain>:<identifier>[:<fingerprint>]`. The domain component may include a port (`host:port` or `[ipv6]:port`). The optional fingerprint suffix is validated against the SHA-256 hex digest of `current_public_key` when present.

Valid DID statuses are `active`, `disabled`, and `revoked`.

### Signature Verification

DID-protected operations require signature verification against the signer's current public key. The canonical payload format is:

```
METHOD + "\n" + PATH_WITH_QUERY + "\n" + TIMESTAMP + "\n" + NONCE + "\n" + SHA256(BODY_RAW)
```

Headers required: `x-did`, `x-signature`, `x-timestamp`. Optional: `x-nonce`.

Verification steps:
1. Extract DID, signature, timestamp, and nonce from headers.
2. Validate timestamp is within `signatureSkewMs` of current time.
3. Resolve the DID state locally or remotely via `GET /did-state` on the signer's domain server.
4. Confirm the DID status is `active`.
5. Reject replayed signatures inside `replayWindowMs`.
6. Verify the cryptographic signature.
7. Record the replay key in the bounded replay cache.

### Cross-Server Forwarding

When `to_did` belongs to a different server domain, the object is forwarded via HTTPS by default. HTTP forwarding is blocked unless `allowInsecureForwarding` is explicitly enabled, and even then only for loopback domains used in local testing.

Relay metadata is mandatory for forwarded writes:

| Header | Purpose |
| --- | --- |
| `x-wormhole-relay-id` | Deduplicates forwarded objects. |
| `x-wormhole-hop` | Prevents relay loops through a bounded hop count. |

Signed forwarded objects preserve DID signature headers so the destination server can re-verify them.

### Local Submission Boundaries

For local agent submissions without relay headers:

- `POST /intent` requires `from_did` to belong to this server domain.
- `POST /intent-response` requires `from_did` to belong to this server domain.
- `POST /signal` requires `from_did` to belong to this server domain.

Forwarded requests bypass this local-domain check because they originate from another server's validated submission path.

### Intent and Signaling Lifecycle

Recipient-side local intents are canonical for response and signaling enforcement:

- Intents enter visible storage as `available`.
- `POST /intent/{id}/seen` changes the visible state to `seen`.
- Local intent responses are allowed only while the canonical local intent remains `available` or `seen`.
- Final responses (`accepted`, `rejected`, `later`) remove the intent from the visible queue immediately while keeping the canonical status record until expiry.
- Signals may be accepted only when the server has a canonical local intent record in `accepted` state and the `from_did` / `to_did` pair matches that intent.
- If the server owns `to_did` for a signal but lacks a canonical local intent record, it rejects the signal because it is the authoritative recipient-side server and cannot prove acceptance.
- Forwarded signal paths that do not carry a local canonical record rely on the peer server that owns the recipient-side intent record to enforce the acceptance gate.

### Trusted Proxy and Client IP Resolution

Client IP resolution uses `request.socket.remoteAddress` by default. `x-forwarded-for` is only honored when:

1. `trustProxy` is explicitly enabled, and
2. the immediate remote address is loopback or appears in `trustedProxyIps`.

This prevents direct internet clients from spoofing source IPs. Deployments behind a reverse proxy must enable trusted-proxy mode and ensure the proxy rewrites `x-forwarded-for`.

### Observability and Abuse Automation

The runtime maintains bounded operational telemetry:

- request totals and per-route status counters,
- a fixed-size recent security-event buffer,
- a bounded offender map with score decay,
- active auto-block records with TTL,
- derived `attack_level` values (`normal`, `elevated`, `under_attack`).

Manual blocklists are persistent. Auto-blocks are temporary and in-memory.

### Cleanup Lifecycle

A periodic cleanup interval removes expired or stale entries from:

1. replay cache,
2. relay cache,
3. rate limiter buckets,
4. visible intents past `expires_at`,
5. canonical local intent status records past `expires_at`,
6. intent responses past `expires_at`,
7. signal queues past `expires_at`,
8. expired auto-blocks and stale offender scores.

### Configuration

All defaults live in `config.mjs` and can be overridden via environment variables. In addition to protocol TTL and rate settings, configuration covers:

- trusted proxy mode,
- manual admin-state file path,
- event-buffer and offender-map bounds,
- auto-block thresholds and TTLs,
- server request/connection timeouts,
- replay-cache and relay-cache maximum entry counts.

## Decisions & Questions

### Question #1: Why is manual blocklist state persisted separately from DID state?

Response: DID state is protocol data owned by DIDs, while manual blocklists are operator policy for abuse handling. Keeping them separate preserves semantic neutrality and lets operators back up or rotate policy data independently.

### Question #2: Why does signaling enforcement depend on the local canonical intent record?

Response: In cross-server flows, only the server that stores the recipient-side intent can reliably know whether acceptance happened. Enforcing acceptance wherever that canonical record exists keeps the guarantee real without inventing unsupported cross-server state replication.

### Question #3: Why is trusted-proxy mode opt-in?

Response: Honoring `x-forwarded-for` unconditionally would let direct clients spoof their IP address and bypass IP-based controls. An explicit trusted-proxy gate makes deployments choose between direct-mode safety and reverse-proxy awareness.

### Question #4: Why are observability structures bounded?

Response: Abuse telemetry must not become a memory-exhaustion vector during an attack. Fixed-size event buffers, bounded offender maps, and capped replay/relay caches preserve visibility without sacrificing availability.

## Conclusion

The architecture remains intentionally small: one process, explicit state partitions, atomic JSON persistence for durable operator and DID data, bounded forwarding behavior, and bounded observability. The runtime now carries production-oriented control surfaces without changing the protocol's semantic boundaries.
