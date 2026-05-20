---
id: DS006
title: Production Deployment and Hardening
status: accepted
owner: repository
summary: Defines reverse-proxy topology, secret posture, persistence expectations, timeout policy, and deployment guidance for production use.
---

# DS006 Production Deployment and Hardening

## Introduction

This specification defines the production deployment posture for the Ploinky Wormhole server. The runtime itself remains a small HTTP process, so safe production use depends on explicit reverse-proxy, secret-management, persistence, and hardening practices.

## Core Content

### Recommended Topology

Production deployment should use:

1. a reverse proxy or edge load balancer terminating TLS,
2. the Wormhole runtime bound to loopback or a private network address,
3. `TRUST_PROXY=true` only when the proxy is trusted and rewrites `x-forwarded-for`,
4. `TRUSTED_PROXY_IPS` populated for non-loopback proxies.

The runtime should not be exposed directly to the public internet with trusted-proxy mode enabled.

### Mandatory Production Configuration

Before production:

- set a non-default `BOOTSTRAP_TOKEN`,
- set an `ADMIN_TOKEN`,
- keep both tokens at 32+ random characters,
- keep `FORWARD_PROTOCOL=https`,
- keep `ALLOW_INSECURE_FORWARDING=false`,
- keep request and connection timeouts enabled,
- persist DID state and admin state on durable storage.

### Persistence and Backup

Two local JSON stores must survive restart:

- DID state file,
- admin-state file for manual blocklists.

Operators must back up both files and protect them with filesystem permissions appropriate for infrastructure secrets and policy data.

### Reverse-Proxy Requirements

The reverse proxy should:

- enforce TLS and HSTS,
- overwrite `x-forwarded-for` rather than append untrusted values from clients,
- cap request body size consistently with or below the runtime's `maxBodyBytes`,
- enforce connection and header timeouts at the edge,
- optionally add coarse IP rate limiting before traffic reaches the runtime,
- prevent caching of admin surfaces.

### Operational Readiness Expectations

The service is not considered production-ready when `/ready` reports `degraded` due to:

- weak or default bootstrap token,
- missing or weak admin token,
- insecure forwarding configuration,
- unsafe trusted-proxy configuration,
- disabled auto-blocking or disabled timeouts.

### Dashboard and Admin Exposure

Admin APIs and the dashboard shell should be reachable only from trusted operator networks, VPNs, or bastion paths even though the shell itself carries no live privileged data. The admin token remains the last line of defense, not the only one.

### Incident Response Expectations

Production operators should treat the following as incidents:

- admin token exposure,
- unexpected growth in attack level or auto-block count,
- repeated relay-loop or replay events,
- unexplained readiness degradation,
- corruption or loss of DID/admin state files.

## Decisions & Questions

### Question #1: Why is TLS termination delegated to the reverse proxy instead of the runtime?

Response: The runtime is intentionally dependency-light and focused on protocol behavior. A dedicated proxy is better suited to certificate rotation, HSTS, TLS policy, and edge request shaping.

### Question #2: Why is `/ready` allowed to fail even when `/health` remains healthy?

Response: Liveness and production posture are different concerns. A process can be alive while still being unsafe to expose, for example when tokens are weak or forwarding policy is insecure.

### Question #3: Why should admin APIs be network-restricted if they already require an admin token?

Response: The token is necessary but should not be the only control. Layering network controls reduces exposure to brute-force, phishing, token leakage, and browser misuse.

## Conclusion

Production readiness for this server depends on explicit deployment discipline: trusted proxying, strong secrets, durable state, bounded timeouts, and restricted admin exposure. The runtime now exposes the controls and signals needed for that posture, but operators must still wire them correctly.
