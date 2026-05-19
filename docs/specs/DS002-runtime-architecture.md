---
id: DS002
title: Runtime Architecture
status: accepted
owner: repository
summary: Describes server runtime components, state partitions, and forwarding model.
---

# DS002 Runtime Architecture

## Introduction

This specification defines runtime architecture constraints for the Ploinky Wormhole server implementation.

## Core Content

The runtime must expose a single HTTP service process that handles request parsing, endpoint routing, validation, and forwarding. It must partition state into one durable segment and multiple temporary segments.

The durable segment must store DID state records with key history and update timestamps in a local JSON file. Writes must be atomic to prevent truncation or partial-state corruption.

If a DID string includes the optional key-fingerprint segment, runtime validation must enforce equality between that suffix and the computed fingerprint of `current_public_key`.

Temporary segments must include communication intents, intent responses, signaling queues, replay cache entries, and relay deduplication entries. Temporary segments must be cleaned periodically and TTL bounded.

Cross-domain forwarding must route based on `to_did` domain and must attach relay metadata for loop control. Relay hop limits and deduplication are required to avoid forwarding amplification.

The runtime default Node.js version must be `>=20`, where native `fetch`, Web Crypto-compatible primitives, and `node:test` are available without dependency extensions.

## Decisions & Questions

### Question #1: Why is DID state persisted while transport objects are temporary?

Response: DID state is public contact material that must remain available across restarts, while intents/responses/signals are time-sensitive transport metadata that should expire rapidly.

### Question #2: Why is relay deduplication mandatory?

Response: Cross-server forwarding can reintroduce the same object through retries or loops. Deduplication and hop limits reduce amplification and storage abuse risks.

## Conclusion

The architecture is intentionally small and defensive: one process, explicit state partitions, atomic durable writes, and bounded forwarding behavior.
