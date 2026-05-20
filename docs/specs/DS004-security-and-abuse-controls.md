---
id: DS004
title: Security and Abuse Controls
status: accepted
owner: repository
summary: Defines mandatory anti-abuse controls, trusted-proxy handling, bounded observability, blocklist management, cache caps, and operational hardening limits for public server operation.
---

# DS004 Security and Abuse Controls

## Introduction

This specification defines transport-security and anti-abuse obligations for public server operation. The server is public infrastructure and can be attacked. Protection is operational, not semantic: controls protect availability without deciding trust.

## Core Content

### Payload and Queue Limits

The runtime enforces strict size and queue boundaries:

| Limit | Default | Scope |
| --- | --- | --- |
| `maxBodyBytes` | 64 KB | Total HTTP request body. |
| `maxIntentEnvelopeBytes` | 4 KB | `agent_envelope` field in intents and responses. |
| `maxSignalPayloadBytes` | 16 KB | `payload` field in signaling messages. |
| `maxSignalsPerIntent` | 64 | Maximum local signaling messages per `intent_id`. |
| `maxReplayEntries` | 4096 | Maximum replay-cache entries before oldest eviction. |
| `maxRelayEntries` | 4096 | Maximum relay-cache entries before oldest eviction. |
| `securityEventBufferSize` | 500 | Maximum recent security events retained in memory. |
| `maxTrackedOffenders` | 2048 | Maximum offender keys retained in memory. |

These limits prevent the server from being used as a content transport or unbounded memory sink.

### Rate Limiting

Three fixed-window rate limiters remain mandatory:

| Limiter | Default Limit | Window | Purpose |
| --- | --- | --- | --- |
| Per IP | 120 requests | 60 seconds | Reduces brute-force or volumetric flooding. |
| Per `from_did` | 120 requests | 60 seconds | Reduces repeated writes attributed to the same sender DID. |
| Per `to_did` | 240 requests | 60 seconds | Protects targeted DIDs from excessive valid writes. |

Rules:

- The IP limiter applies to every request.
- DID-keyed limiters apply to DID-to-DID write flows.
- For signed response and signaling writes, DID-keyed rate limits are applied only after signature verification succeeds.
- For unsigned intent submission, DID-keyed rate limits operate on claimed DID values as best-effort operational controls.
- Exceeded limits trigger penalty backoff and 429 responses with `retry-after`.

### Blocklists

The server combines three blocklist sources:

| Source | Persistence | Types |
| --- | --- | --- |
| Configured blocklists | Environment variables | IP, DID, domain |
| Manual admin blocklists | Persistent JSON admin state | IP, DID, domain |
| Automated temporary blocks | In-memory TTL state | IP, verified DID |

Configured and manual domain blocklists apply to DID domains observed in both `from_did` and `to_did`.

### Automated Abuse Detection

The runtime maintains a bounded recent security-event buffer and offense scores per principal. Repeated violations increase offense scores and can raise `attack_level` from `normal` to `elevated` or `under_attack`.

Typical offense inputs include:

- malformed JSON or relay headers,
- missing or invalid signatures,
- replay attempts,
- oversized payloads,
- repeated rate-limit violations,
- signaling before acceptance,
- repeated queue-flood attempts.

Auto-block rules:

- IPs may be auto-blocked when offense score reaches `autoBlockThreshold`.
- DIDs may be auto-blocked only when the offending request was already cryptographically verified as that DID.
- Unsigned `POST /intent` traffic must never create DID auto-blocks for claimed `from_did` values.
- Auto-blocks expire after `autoBlockTtlMs`.

### Replay Protection

The replay cache is keyed by `${did}:${signature}` and expires entries after `replayWindowMs`. The cache is both TTL-bounded and entry-count bounded. When the cache reaches `maxReplayEntries`, the oldest entries are evicted before new ones are inserted.

### Relay Loop Prevention

Cross-server forwarding uses:

1. `x-wormhole-relay-id` deduplication with TTL and `maxRelayEntries`,
2. `x-wormhole-hop` enforcement bounded by `maxRelayHops`.

Both checks occur before business processing.

### Trusted Proxy Model

Source-IP trust is explicit:

- `trustProxy=false` means the server uses only `socket.remoteAddress`.
- `trustProxy=true` means the server may use `x-forwarded-for`, but only if the immediate remote address is loopback or listed in `trustedProxyIps`.
- Directly exposed servers must keep `trustProxy=false`.
- Reverse-proxy deployments must ensure the proxy rewrites `x-forwarded-for` and prevents client-controlled spoofing.

### Request and Connection Hardening

The runtime must enforce:

- request timeout,
- header timeout,
- socket timeout,
- keep-alive timeout,
- max requests per socket.

These limits reduce the impact of slowloris-style and connection-hoarding attacks.

### Security Headers and Admin Token Handling

Responses must apply:

- `X-Content-Type-Options: nosniff`,
- `X-Frame-Options: DENY`,
- `Referrer-Policy: no-referrer`,
- restrictive `Content-Security-Policy`,
- `Cache-Control: no-store`.

Admin APIs require `x-admin-token`. Tokens must never be transported in query parameters.

### Bootstrap and Admin Secret Posture

Operators must:

- replace the default bootstrap token before production,
- use at least 32 random characters for bootstrap and admin tokens,
- rotate both secrets periodically,
- treat admin token exposure as an incident because it protects recovery and admin-control APIs.

### What Anti-Abuse Controls Do Not Do

| Not Done by Controls | Reason |
| --- | --- |
| Classify senders as trusted or untrusted | Semantic decision belongs to the agent. |
| Inspect `agent_envelope` or signaling application meaning | Payloads remain opaque. |
| Infer chat, mail, file, or task semantics | The server remains neutral. |
| Permanently auto-ban arbitrary claimed DIDs from unsigned intents | That would let attackers forge identities and weaponize the control plane. |

## Decisions & Questions

### Question #1: Why are DID auto-blocks limited to verified signed abuse?

Response: Unsigned intent submission can claim any `from_did`, so auto-blocking claimed identities there would let attackers DoS legitimate DIDs. Limiting DID auto-blocks to already-verified identities removes that abuse vector.

### Question #2: Why are replay and relay caches capped in addition to TTL cleanup?

Response: TTL alone does not prevent short bursts from forcing unbounded memory growth before cleanup runs. Entry-count caps provide a deterministic memory ceiling during floods.

### Question #3: Why is trusted-proxy mode not enabled automatically?

Response: Automatically trusting `x-forwarded-for` would be unsafe for direct deployments. Explicit operator intent is required because the reverse proxy becomes part of the security boundary.

### Question #4: Should proof-of-work or external CAPTCHA be added later for unsigned intent submission?

Options:
1. Keep current model with IP limits, auto-blocks, proxy edge controls, and manual blocklists.
2. Add optional proof-of-work for abusive unsigned intent traffic if operational data shows rate limits are insufficient.

## Conclusion

Security posture is based on bounded resources, explicit trust boundaries, authenticated admin control, signed DID-protected operations, and automated but carefully scoped abuse handling. The server protects its own availability while remaining semantically neutral.
