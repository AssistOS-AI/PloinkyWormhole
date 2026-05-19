---
id: DS004
title: Security and Abuse Controls
status: accepted
owner: repository
summary: Defines mandatory anti-abuse controls, TTL behavior, and operational safeguards.
---

# DS004 Security and Abuse Controls

## Introduction

This specification defines transport-security and anti-abuse obligations for public server operation.

## Core Content

The server must enforce bounded request body size, bounded `agent_envelope` size, bounded signaling payload size, and bounded signaling messages per `intent_id`.

The server must enforce rate limits by source IP, `from_did`, and `to_did`, with temporary backoff on repeated violations. It must support administrative blocklists for IP, DID, and destination server domains. These controls apply to all DID-to-DID write flows (`/intent`, `/intent-response`, and `/signal`).

Temporary state objects must expire by TTL and be removed during periodic cleanup. DID state persists until update, disable, or revocation.

Signaling data must be treated as technical transport metadata only. Access to signaling queues must be DID-protected and limited to the addressed recipient DID.

Cross-server forwarding must rely on HTTPS transport, not server-to-server signature PKI, and must apply loop prevention and deduplication.

First DID publication bootstrap tokens must be configurable by environment and treated as operational secrets that must be rotated by operators before production.

## Decisions & Questions

### Question #1: Why are anti-abuse decisions operational and not semantic?

Response: Operational controls protect service availability without introducing policy coupling. Trust and semantic filtering remain agent-level concerns.

### Question #2: Should server-side quarantine queues be added for suspicious intents?

Options:
1. Keep current strict-reject model for simplicity and deterministic behavior.
2. Add quarantine queues with manual review in a future release if operational evidence requires it.

## Conclusion

Security posture is based on bounded resources, signed DID-protected metadata reads, and forwarding safeguards while preserving semantic neutrality.
