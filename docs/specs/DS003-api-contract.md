---
id: DS003
title: API Contract
status: accepted
owner: repository
summary: Defines endpoint-level obligations for DID state, intents, responses, and signaling.
---

# DS003 API Contract

## Introduction

This specification defines normative API behavior for public reads, DID-protected reads, state updates, and temporary transport objects.

## Core Content

The server must provide these endpoints: `GET /did-state`, `PUT /did-state`, `POST /intent`, `GET /intents`, `POST /intent/{intent_id}/seen`, `POST /intent-response`, `GET /intent-responses`, `POST /signal`, `GET /signals`, `GET /health`, and `GET /limits`.

`GET /did-state` must be public. `GET /intents`, `POST /intent/{intent_id}/seen`, `GET /intent-responses`, and `GET /signals` must require DID signatures proving control of the addressed `to_did`. `POST /intent-response` and `POST /signal` must require DID signatures from `from_did`.

Canonical signed payload format must be:

`METHOD + "\n" + PATH_WITH_QUERY + "\n" + TIMESTAMP + "\n" + NONCE + "\n" + SHA256(BODY_RAW)`

Headers must include `x-did`, `x-signature`, and `x-timestamp`; `x-nonce` is optional but recommended. Server verification must reject invalid signatures, out-of-skew timestamps, DID mismatches, and replayed signatures inside replay window.

`PUT /did-state` must require bootstrap proof for first publication and signed proof by current DID key for updates, except explicit administrative recovery mode.

When `/intent-response` or `/signal` are forwarded cross-server, the forwarding server must preserve the original DID signature headers and exact signed request body. Destination servers may accept forwarded objects without local sender-key verification, while receiving agents remain responsible for cryptographic validation.

## Decisions & Questions

### Question #1: Why is path-with-query part of signature payload?

Response: Including query parameters binds DID authorization to exact resource scopes such as `to_did` and `intent_id`, preventing signature reuse for a different retrieval target.

### Question #2: Why are request bodies hashed instead of raw embedded in signature payload?

Response: Hashing provides a stable canonical payload representation, avoids ambiguity from large payload encoding details, and keeps signature string bounded.

## Conclusion

The API contract enforces open DID state discovery and strict DID-controlled access to sensitive metadata queues, with deterministic signature verification rules.
