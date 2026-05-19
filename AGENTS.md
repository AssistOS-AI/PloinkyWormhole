# AGENTS

## Scope

This repository implements the Ploinky Wormhole host project: a Node.js ESM rendezvous and signaling server for `did:wormhole`. DS specifications under `docs/specs/` are the source of truth for behavior and boundaries.

## Mandatory Reading Order

1. `docs/specs/DS000-vision.md`
2. `docs/specs/DS001-coding-style.md`
3. `docs/specs/matrix.md` through `docs/specsLoader.html?spec=matrix.md`
4. `docs/index.html`, then topic pages (`architecture.html`, `api.html`, `security.html`)
5. Relevant DS files for changed behavior before editing code or docs

## Current Skill Catalog

Current local skills under `.agents/skills/` are:
- `achilles_specs`
- `antropic_skill_build`
- `article_build`
- `cskill_build`
- `dgskill_build`
- `gamp_specs`
- `oskill_build`
- `review_specs`

`AGENTS.md`, `docs/index.html`, and `docs/specs/matrix.md` must be updated when this list changes.

## Repository Rules

All persistent documentation, specifications, and code comments must be in English. `DS001-coding-style.md` is the coding-style authority for module structure, naming, and test organization rules. Every ordinary DS file must keep the `Introduction`, `Core Content`, `Decisions & Questions`, and `Conclusion` sections. In `Decisions & Questions`, use numbered subchapters (`### Question #N: ...`) with `Response:` or `Options:`.

DS numbering must remain contiguous with no gaps. Rationale, tradeoffs, and unresolved alternatives live in the affected DS files, not in a separate decision log.

When source code changes alter behavior, interfaces, constraints, workflows, or architecture, update both HTML docs and DS specs in the same change set.

Downstream consumer projects must keep imported-skill documentation inside local skill folders and must not create imported-skill DS files or skill pages in the host `docs/` tree.

The `gamp_specs` skill must be updated whenever new skill families, coding-style rules, or bootstrap rules are introduced.

## Runtime Defaults

Default runtime uses Node.js `>=20`, ESM modules (`.mjs`), no external runtime dependencies, and JSON file persistence for DID state plus in-memory TTL queues for intents/responses/signals. HTTP transport is plain Node `http` with optional HTTPS forwarding to peer servers.

## Key Paths

- Documentation entry point: `docs/index.html`
- Specs entry point: `docs/specsLoader.html?spec=matrix.md`
- Specs directory: `docs/specs/`
- Coding style spec: `docs/specs/DS001-coding-style.md`
- Server runtime: `src/`
- Tests: `test/`
- Docs tooling: `scripts/`
