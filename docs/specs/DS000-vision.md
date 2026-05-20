---
id: DS000
title: Ploinky Wormhole Server Vision
status: accepted
owner: repository
summary: Defines the server scope as a neutral public rendezvous and signaling service for did:wormhole, covering three core concepts: DID state, communication intent, and signaling.
---

# DS000 Vision

## Introduction

This specification defines the product boundary for the Ploinky Wormhole server. The server is a public rendezvous and signaling infrastructure for the `did:wormhole` protocol. It enables a DID to publish minimal public state, declare intent to communicate with another DID, and transport technical signaling messages needed to establish WebRTC or compatible P2P channels.

The server does not implement Mail, Chat, File Transfer, or Agent Task. The server does not decide whether a sender is known, unknown, blocked, or trusted. The server does not apply workspace policies. The server does not store final content. These responsibilities belong to the Wormhole agent.

## Core Content

### Three Core Concepts

The server operates on exactly three persistent or temporary concepts:

| Concept | Role | Lifetime |
| --- | --- | --- |
| DID State | Public key, status, and key rotation history for a DID in the server's domain. | Persistent until update, disable, or revocation. |
| Communication Intent | Temporary declaration that `from_did` wants to communicate with `to_did`. | Temporary, expires at `expires_at`. |
| Signaling | Temporary technical messages for WebRTC/P2P session establishment. | Temporary, short TTL. |

No mailbox, contact, trust, project, tag, policy, chat, mail, file, or task concepts exist at the server level.

### Semantic Neutrality

The server must remain semantically neutral. It must not classify contacts as trusted or untrusted, must not apply workspace policy, and must not interpret application-level meaning of payload content. It operates as public infrastructure where HTTPS is the transport baseline and anti-abuse controls protect availability.

### Operational Control Surfaces

The runtime may expose readiness checks, admin observability endpoints, a token-driven dashboard shell, persistent manual blocklists, and bounded automated abuse controls. These are operational surfaces only. They do not introduce new protocol-level concepts beyond DID state, communication intent, and signaling, and they must not reinterpret payload semantics.

### DID Format

The DID form is:

```
did:wormhole:<server-domain>:<did-identifier>
did:wormhole:<server-domain>:<did-identifier>:<key-fingerprint>
```

- `server-domain` indicates the Ploinky Wormhole server where the DID state is published.
- `did-identifier` is the public identifier within the server's domain. It may be a human alias, a generated ID, an agent ID, a project ID, or a pseudonymous ID. The server must not interpret what this identifier semantically represents.
- `key-fingerprint` is optional and binds the DID to the public key. The Wormhole agent verifies the fingerprint. The server only publishes the data.

### DID State

A DID state contains: `did`, `did_identifier`, `current_public_key`, `current_fingerprint`, `status` (active, disabled, revoked), `updated_at`, and `key_history`.

Key history entries contain: `public_key`, `fingerprint`, `valid_from`, `valid_until`, and optional `rotation_proof`.

The server does not decide whether a key change is legitimate for an existing contact. It preserves history and rotation proof if present. The Wormhole agent decides whether to accept the new key, request reconfirmation, or block communication.

### Communication Intent

An intent expresses only that one DID wants to talk to another. It contains: `intent_id`, `from_did`, `to_did`, `created_at`, `expires_at`, `nonce`, and optional `agent_envelope`.

The `agent_envelope` is transported, not interpreted. It may contain signed or encrypted data for the destination agent, but the server does not know what it represents.

The intent does not contain communication type. It does not contain mail, chat, file, agent_task, subject, filename, file size, or project metadata. These are negotiated P2P between agents after acceptance.

### Intent Response

The destination agent can respond to an intent with `accept`, `reject`, or `later`. A response contains: `intent_id`, `from_did`, `to_did`, `response`, `created_at`, `expires_at`, and optional `agent_envelope`.

### Signaling

After acceptance, the server transports signaling messages. Signaling is technical and temporary. It allows agents to establish a WebRTC or other P2P channel.

A signaling message contains: `intent_id`, `from_did`, `to_did`, `signal_type` (offer, answer, ice_candidate), `payload`, `created_at`, and `expires_at`.

For WebRTC, payload may contain SDP offer, SDP answer, and ICE candidates. These data may expose network information: local or public IP addresses, NAT types, relay/TURN candidates, and other connectivity details. Signaling must be kept with short TTL, read only by the destination DID, and removed after expiration or channel establishment.

The server does not interpret SDP or ICE from an application perspective. It only forwards them.

### Agent Polling Model

Each agent periodically checks only the servers of its own DIDs. An agent serving multiple DIDs may query the corresponding servers. It does not periodically poll the servers of its contacts.

| Situation | Server Contacted |
| --- | --- |
| Agent wants to see who wants to talk to it | Its own DID's server. |
| Agent wants to see responses to its intents | Its own DID's server. |
| Agent wants to receive signaling | Its own DID's server. |
| Agent wants to initiate communication | Sends intent to its own DID's server; may punctually read the destination DID's state. |

### What Does Not Belong to the Server

| Excluded from Server | Reason |
| --- | --- |
| Known/unknown contact | Agent-local state. |
| Blocked/trusted contact | Agent or workspace-level decision. |
| Workspace policies | Belongs to Ploinky Workspace and the agent. |
| Mail/Chat/File/Agent Task | Negotiated and transferred P2P. |
| Inboxes/mailboxes | Organized by the agent. |
| Content interpretation | Server is semantically neutral. |
| Server signatures | HTTPS is sufficient for server-to-server transport. |
| Semantic authorization | Agent decides whether to accept communication. |

## Decisions & Questions

### Question #1: Why is semantic neutrality mandatory?

Response: Semantic neutrality keeps the server interoperable and domain-agnostic. It allows agents and workspace policy engines to evolve trust logic independently while the server remains a stable transport substrate.

### Question #2: Why does the server keep only minimal durable state?

Response: Durable state is restricted to DID public-contact material and key rotation history. Temporary communication metadata uses TTL to reduce long-term privacy exposure and storage abuse.

### Question #3: Why is the agent_envelope opaque to the server?

Response: The envelope carries agent-level cryptographic proofs and metadata that only the destination agent can interpret. Keeping it opaque preserves semantic neutrality and prevents the server from becoming a content-aware intermediary.

### Question #4: Why does the server not implement server-to-server signatures?

Response: HTTPS provides transport security between servers. Adding a separate server signature PKI would increase complexity without meaningful security benefit, since the destination server treats forwarded objects as untrusted temporary data and the destination agent performs all cryptographic verification.

### Question #5: Why are admin dashboard and observability surfaces not treated as protocol concepts?

Response: These surfaces help operators run and harden the service, but they are not part of the DID-to-DID rendezvous contract. Keeping them operational prevents the server from drifting into workspace semantics or application content handling.

## Conclusion

The vision is a public, minimal, and operationally hardened rendezvous/signaling service that supports `did:wormhole` interoperability without inheriting application semantics. The server publishes DID state, transports temporary intents and responses, and relays technical signaling for P2P channel establishment. All trust decisions, policy enforcement, and content handling belong to the Wormhole agent.
