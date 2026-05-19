---
id: DS001
title: Coding Style and Repository Layout
status: accepted
owner: repository
summary: Defines coding conventions, module boundaries, and test organization for the Node.js ESM server.
---

# DS001 Coding Style

## Introduction

This specification is the coding-style authority for this repository. All code changes, tests, and documentation updates must follow this contract.

## Core Content

Source code must use Node.js ESM modules with `.mjs` extension and no external runtime dependencies. Runtime code belongs in `src/`, test code belongs in `test/`, and documentation tooling belongs in `scripts/`.

Modules must keep explicit responsibilities and avoid hidden global state. Request handling, DID parsing, signature verification, persistence, and rate limiting must remain separated by concern. Functions should validate input early and return explicit errors rather than silently ignoring invalid states.

Tests must use built-in `node:test` and run without third-party frameworks. New behavior must include request-level tests when endpoints or protocol constraints change.

Documentation and specification files must remain in English. Any change that modifies runtime behavior, API contract, constraints, or architecture must update relevant HTML pages and DS specs in the same change set.

`fileSizesCheck.sh` is the standard checker for file-size and line-length hygiene when repository maintainers need a quick portability audit.

## Decisions & Questions

### Question #1: Why are external runtime dependencies forbidden?

Response: Zero-dependency runtime keeps deployment and audit surfaces small for public infrastructure software and reduces supply-chain risk.

### Question #2: How should large logic blocks be organized?

Response: Split by functional boundaries into focused modules under `src/` and keep endpoint contract rules in DS files instead of scattering implicit assumptions across handlers.

## Conclusion

The repository prioritizes deterministic Node.js ESM code, explicit boundaries, and testable endpoint behavior with synchronized documentation updates.
