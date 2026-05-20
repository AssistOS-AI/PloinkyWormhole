---
id: DS005
title: Operations and Admin Observability
status: accepted
owner: repository
summary: Defines readiness, metrics, dashboard, recent security events, attack-level reporting, and operator blocklist workflows.
---

# DS005 Operations and Admin Observability

## Introduction

This specification defines the server's operational visibility surfaces. The goal is to give operators enough telemetry to diagnose abuse, understand queue pressure, and manage manual blocklists without adding application semantics to the protocol layer.

## Core Content

### Public Operational Reads

The runtime exposes two public operational summaries:

- `/health` for liveness and coarse attack-level status,
- `/ready` for deployment-readiness checks and operator warnings.

`/health` is intentionally small and safe for load balancers. `/ready` is richer and may return 503 with warnings when production posture is degraded.

### Admin Authentication Model

Admin JSON APIs require `x-admin-token`. The admin token protects:

- metrics,
- recent security events,
- effective blocklist views,
- manual blocklist mutation.

The token must only travel in headers. The server does not provide cookie-based sessions or query-string token transport.

### Dashboard Shell

`GET /admin/dashboard` serves a static HTML shell with:

- no embedded secrets,
- no embedded privileged data,
- JavaScript that waits for the operator to enter the admin token locally,
- requests to `/admin/metrics`, `/admin/events`, and `/admin/blocklist` using header-based admin authentication.

The shell must remain safe to serve publicly because it reveals interface shape only, not live operational data.

### Metrics Contract

`GET /admin/metrics` must provide:

- readiness status,
- uptime,
- attack level,
- request totals by status family,
- per-route counters and response-time summaries,
- DID-state count,
- queue sizes for visible intents, canonical intent statuses, responses, and signals,
- replay and relay cache sizes,
- effective blocklist counts,
- active auto-blocks,
- top offenders by current score.

Metrics are runtime-local and reset on process restart unless they are derived from durable stores such as DID state count or manual blocklists.

### Recent Security Events

`GET /admin/events` exposes a bounded, recent-first event buffer containing operationally relevant entries such as:

- blocked requests,
- manual blocklist changes,
- offense classifications,
- replay detections,
- malformed relay attempts.

The event buffer is bounded in memory and is not intended to be a durable audit log.

### Blocklist Operations

`GET /admin/blocklist` returns three views:

1. configured environment-driven entries,
2. persistent manual entries,
3. active temporary auto-blocks.

`POST /admin/blocklist` and `DELETE /admin/blocklist` let operators add or remove manual blocklist entries. Removing a matching auto-block should also clear the temporary entry when present.

### Attack-Level Reporting

The runtime exposes an `attack_level` derived from recent offense activity and active auto-blocks:

- `normal`,
- `elevated`,
- `under_attack`.

This field is operational guidance, not a cryptographic truth claim.

## Decisions & Questions

### Question #1: Why is the dashboard shell public instead of fully admin-gated?

Response: The shell contains no privileged data and is easier to use from browsers if it can load without custom navigation headers. The actual operational data remains behind the admin token.

### Question #2: Why are recent security events not persisted?

Response: Persistence would turn the runtime into a logging product and increase local storage and privacy obligations. The bounded in-memory buffer gives immediate situational awareness while leaving durable logging to surrounding infrastructure.

### Question #3: Why does `/ready` expose warnings publicly?

Response: Readiness is primarily for orchestration and operator checks. The endpoint avoids secrets and reports only posture warnings such as weak tokens or unsafe forwarding configuration, which are acceptable to reveal for deployment health purposes.

## Conclusion

Operational observability is now a first-class contract surface. The server exposes enough runtime telemetry and control for safe operation while keeping protocol semantics and operator tooling clearly separated.
