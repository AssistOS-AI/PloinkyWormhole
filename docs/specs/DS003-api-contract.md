---
id: DS003
title: API Contract
status: accepted
owner: repository
summary: Defines endpoint behaviors, signature and admin-token requirements, request and response formats, forwarding semantics, and lifecycle constraints for the Ploinky Wormhole server.
---

# DS003 API Contract

## Introduction

This specification defines normative API behavior for public reads, DID-protected reads, DID state updates, intent management, response handling, signaling transport, readiness, and admin observability. All endpoints share a common request handling pipeline: bounded body reading, JSON parsing, IP rate limiting, relay header processing, and bounded abuse monitoring.

## Core Content

### Endpoint Summary

| Method | Endpoint | Purpose | Authentication |
| --- | --- | --- | --- |
| GET | `/health` | Liveness and attack-level summary | None |
| GET | `/ready` | Production-readiness checks | None |
| GET | `/limits` | Published operational limits | None |
| GET | `/did-state?did=...` | Read public DID state | None |
| PUT | `/did-state` | Create or update DID state | Bootstrap token, DID signature, or admin token |
| POST | `/intent` | Submit intent (local or forwarded) | None |
| GET | `/intents?to_did=...` | Read visible intents for a DID | DID signature from `to_did` |
| POST | `/intent/{intent_id}/seen` | Mark intent as seen | DID signature from `to_did` |
| POST | `/intent-response` | Submit response to an intent | DID signature from responding `from_did` |
| GET | `/intent-responses?to_did=...` | Read responses addressed to a DID | DID signature from `to_did` |
| POST | `/signal` | Submit signaling message | DID signature from sending `from_did` |
| GET | `/signals?to_did=...&intent_id=...` | Read signaling for a DID and intent | DID signature from `to_did` |
| GET | `/admin/dashboard` | Token-driven HTML dashboard shell | None for shell, no data embedded |
| GET | `/admin/metrics` | Read metrics, readiness, attack level, queue sizes, offenders | `x-admin-token` |
| GET | `/admin/events?limit=...` | Read recent security events | `x-admin-token` |
| GET | `/admin/blocklist` | Read configured, manual, and auto blocklists | `x-admin-token` |
| POST | `/admin/blocklist` | Add manual blocklist entry | `x-admin-token` |
| DELETE | `/admin/blocklist` | Remove manual or auto blocklist entry | `x-admin-token` |

### Public Endpoints

**GET /health** returns liveness metadata:

```json
{
  "status": "ok",
  "server_domain": "example.org",
  "did_states": 12,
  "uptime_ms": 12345,
  "attack_level": "normal"
}
```

**GET /ready** returns production-readiness checks. The endpoint returns 200 when all checks pass and 503 when status is `degraded`.

**GET /limits** returns the active public limits and hardening knobs, including TTLs, payload limits, cache caps, request timeouts, trusted-proxy mode, and auto-block thresholds.

**GET /did-state?did=...** returns the full DID state document including `did`, `did_identifier`, `current_public_key`, `current_fingerprint`, `status`, `updated_at`, and `key_history`. DID state remains public contact information and is readable without signature.

### DID State Publication

**PUT /did-state** creates or updates a DID state record.

Request body:

```json
{
  "did": "did:wormhole:example.org:alice",
  "current_public_key": "-----BEGIN PUBLIC KEY-----...",
  "status": "active",
  "rotation_proof": "optional"
}
```

Rules:

- First publication requires `x-bootstrap-token`.
- Updates require a DID signature from the DID being updated, or `x-admin-token` for recovery.
- DID domain must match the local server domain.
- Optional fingerprint suffix in the DID must match `current_public_key`.
- DID status changes without key rotation update `status` and `updated_at` but do not append a new history entry.

### Intent Submission

**POST /intent** submits a communication intent.

Request body:

```json
{
  "intent_id": "optional",
  "from_did": "did:wormhole:sender.example:alice",
  "to_did": "did:wormhole:recipient.example:bob",
  "created_at": "optional ISO timestamp",
  "expires_at": "optional ISO timestamp",
  "nonce": "optional",
  "agent_envelope": {}
}
```

Rules:

- `from_did` and `to_did` must be valid DIDs.
- For local submissions without relay headers, `from_did` must belong to the local server domain.
- `expires_at` must be in the future and no later than `intentTtlMs`.
- `agent_envelope` must remain within `maxIntentEnvelopeBytes`.
- IP, DID, and domain blocklists may reject the request.
- Local intents for a local `to_did` are stored as `available`.
- Cross-domain intents are forwarded and not stored in the local visible queue.

No DID signature is required for intent submission. The agent envelope remains opaque and agent-validated.

### Intent Retrieval and Acknowledgment

**GET /intents?to_did=...** returns only visible intents for the destination DID. Only `available` and `seen` intents appear. Final states (`accepted`, `rejected`, `later`) are removed from the visible queue immediately.

**POST /intent/{intent_id}/seen** requires:

- request body `{ "to_did": "..." }`,
- DID signature from that `to_did`,
- existing visible intent in `available` or `seen` state.

The call is idempotent once the intent is already `seen`.

### Intent Response

**POST /intent-response** submits an intent response.

Request body:

```json
{
  "intent_id": "required",
  "from_did": "did:wormhole:recipient.example:bob",
  "to_did": "did:wormhole:sender.example:alice",
  "response": "accept",
  "created_at": "optional ISO timestamp",
  "expires_at": "optional ISO timestamp",
  "agent_envelope": {}
}
```

Rules:

- `response` must be one of `accept`, `reject`, `later`.
- For local submissions without relay headers, `from_did` must belong to the local server domain.
- `expires_at` must be in the future and no later than `responseTtlMs`.
- `agent_envelope` must remain within `maxIntentEnvelopeBytes`.
- DID signature must come from `from_did`.
- When `from_did` is local, the server must already hold the canonical local intent for `intent_id`, the DID pair must match, and the local intent state must still be `available` or `seen`.
- Final local responses remove the intent from the visible queue immediately and move the canonical local intent state to `accepted`, `rejected`, or `later`.
- If `to_did` is remote, the response is forwarded with original DID signature headers preserved.

### Response Retrieval

**GET /intent-responses?to_did=...** returns all stored responses addressed to `to_did`. Retrieval requires a DID signature from `to_did`.

### Signaling

**POST /signal** submits a technical signaling message.

Request body:

```json
{
  "intent_id": "required",
  "from_did": "did:wormhole:sender.example:alice",
  "to_did": "did:wormhole:recipient.example:bob",
  "signal_type": "offer",
  "payload": {},
  "created_at": "optional ISO timestamp",
  "expires_at": "optional ISO timestamp"
}
```

Rules:

- `signal_type` must be one of `offer`, `answer`, `ice_candidate`.
- For local submissions without relay headers, `from_did` must belong to the local server domain.
- `expires_at` must be in the future and no later than `signalTtlMs`.
- `payload` must remain within `maxSignalPayloadBytes`.
- DID signature must come from `from_did`.
- If the server holds the canonical local intent record for `intent_id`, that intent must match the DID pair and already be `accepted`.
- If `to_did` belongs to this server and the server lacks a canonical local intent record for `intent_id`, the request is rejected because the recipient-side acceptance cannot be proven locally.
- Local signal queues are capped by `maxSignalsPerIntent`.
- Cross-domain signals are forwarded with original DID signature headers preserved.

### Admin API Contract

Admin APIs use `x-admin-token` header only. The token must never be supplied via query parameters.

**GET /admin/dashboard** returns an HTML shell that contains no embedded secrets or privileged data. The user enters the admin token locally in the browser, and the page uses headers to call the JSON admin APIs.

**GET /admin/metrics** returns:

- readiness checks,
- attack level,
- request totals and per-route metrics,
- queue sizes,
- replay and relay cache sizes,
- configured/manual/auto blocklist counts,
- active auto-blocks,
- top offenders.

**GET /admin/events** returns the bounded recent security-event buffer.

**GET /admin/blocklist** returns configured, manual, and auto blocklist views.

**POST /admin/blocklist** accepts `{ type, value, reason? }` for `ip`, `did`, or `domain` entries and persists manual entries.

**DELETE /admin/blocklist** accepts `{ type, value }` and removes matching manual and auto entries when present.

### Canonical Signature Format

DID-protected operations require the canonical payload:

```
METHOD + "\n" + PATH_WITH_QUERY + "\n" + TIMESTAMP + "\n" + NONCE + "\n" + SHA256(BODY_RAW)
```

Required headers: `x-did`, `x-signature`, `x-timestamp`. Optional: `x-nonce`.

The server verifies timestamp skew, DID existence, active DID status, replay absence, and cryptographic validity before accepting the operation.

### Forwarding Semantics

All write endpoints accept both local and forwarded objects. Relay headers distinguish forwarded requests:

- `x-wormhole-relay-id` identifies the forwarded object.
- `x-wormhole-hop` counts relay hops and is bounded by `maxRelayHops`.

Signed forwarded objects preserve body and DID signature headers unchanged. Destination servers re-verify signatures.

### DID Status Requirements

Protected DID operations require the authenticated DID to have `active` status. `disabled` and `revoked` DIDs remain publicly readable through `GET /did-state`, but they cannot authorize protected reads or writes.

### Error Responses

All errors return JSON of the form `{ "error": "message" }`.

| Status | Meaning |
| --- | --- |
| 400 | Invalid request format, invalid TTL, invalid payload constraints, or invalid local submission boundary. |
| 401 | Missing or invalid DID signature, bootstrap failure, or admin token failure. |
| 403 | DID mismatch, inactive DID, or blocklist rejection. |
| 404 | Resource not found (DID state, local intent, blocklist entry). |
| 409 | Replay detected or invalid lifecycle transition (for example signaling before accept). |
| 413 | Request body or field exceeds size limit. |
| 429 | Rate limit exceeded or signal queue full. |
| 500 | Internal policy failure such as forbidden insecure forwarding. |
| 502 | Forwarding failed. |
| 503 | Admin endpoints disabled or readiness degraded. |
| 508 | Relay hop limit exceeded. |

## Decisions & Questions

### Question #1: Why does the dashboard shell remain public while the JSON admin APIs are protected?

Response: The shell contains no privileged data and only serves as a convenience UI. Keeping the actual data behind `x-admin-token` preserves browser usability without leaking secrets in URLs or HTML.

### Question #2: Why are final intents removed from `/intents` instead of merely filtered?

Response: Removing final states from the visible queue keeps the queue semantically aligned with "items still awaiting recipient action" and reduces stale-memory pressure. Canonical status records still retain the local lifecycle until expiry.

### Question #3: Why are local response and signaling submissions constrained to local `from_did` values?

Response: Agents should speak only to their own server. Enforcing local ownership on unforwarded writes prevents a server from being used as a generic public ingress for identities that belong elsewhere.

### Question #4: Why does the admin contract forbid URL-based token transport?

Response: Query-string secrets leak into browser history, reverse-proxy logs, and `Referer` headers. Header-only transport is the simplest safe baseline for this runtime.

## Conclusion

The API contract preserves the original public rendezvous model while adding clear operational surfaces for readiness and administration. Public DID state remains open, sensitive DID queues remain DID-protected, and admin observability remains explicitly separate from protocol semantics.
