---
id: DS000
title: Ploinky Wormhole Server Vision
status: accepted
owner: repository
summary: Defines the server scope as a neutral public rendezvous and signaling service for did:wormhole.
---

# DS000 Vision

## Introduction

This specification defines the product boundary for the Ploinky Wormhole server. The server exists to publish minimal DID state, transport temporary communication intents and intent responses, and relay technical signaling data needed for peer-to-peer session establishment.

## Core Content

The server must remain semantically neutral. It must not classify contacts as trusted or untrusted, must not apply workspace policy, and must not interpret application-level meaning of payload content. It must operate as public infrastructure where HTTPS is the transport baseline and anti-abuse controls protect availability.

The server must expose DID state operations for DIDs in its own domain and must retain key history for rotations. It must support cross-server forwarding for intents, intent responses, and signaling messages by extracting destination domain from `to_did`.

The server must not become a final-content transport system. Mail, chat, file transfer, and agent task payload semantics must remain peer-to-peer agent responsibilities after channel establishment.

## Decisions & Questions

### Question #1: Why is semantic neutrality mandatory?

Response: Semantic neutrality keeps the server interoperable and domain-agnostic. It allows agents and workspace policy engines to evolve trust logic independently while the server remains a stable transport substrate.

### Question #2: Why does the server keep only minimal durable state?

Response: Durable state is restricted to DID public-contact material and key rotation history. Temporary communication metadata uses TTL to reduce long-term privacy exposure and storage abuse.

## Conclusion

The vision is a public, minimal, and operationally hardened rendezvous/signaling service that supports `did:wormhole` interoperability without inheriting application semantics.
