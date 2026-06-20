# ADR-0003: Self-host-first sequencing; keep @json-editor/json-editor (not RJSF)

- **Status:** Accepted
- **Date:** 2026-06-20
- **Deciders:** SauceTaster (maintainer)
- **Amends:** [ADR-0001](./0001-modern-typescript-stack.md) (editor decision §2.3)
- **Re-scopes:** [ADR-0002](./0002-auth-and-mcp-authorization.md) → Deferred

## Context

A deliberate smell-test of the plan, grounded in the actual repo, surfaced three
things that change the *sequencing* (not the destination):

1. **The product surface on the new stack was ~0.** ~300 LOC of new code doing one
   read-only thing (validate), against ~17.5k LOC of legacy app still being the
   entire product — with 5.5k LOC of tests and 1.1k lines of docs around it. We had
   built the easy greenfield parts and circled the hard one (the editor).
2. **The deployment model is self-host-first** (single-org now; SaaS later). That
   removes the near-term justification for the entire multi-tenant auth stack in
   ADR-0002 (OAuth 2.1 AS, orgs/teams, RBAC, RLS).
3. **The editor library is alive.** The app runs on `@json-editor/json-editor`
   (the maintained community fork) — latest release days ago, MIT, ~4.9k stars. The
   premise behind ADR-0001's RJSF rewrite ("the editor lib is dead, we must replace
   it") was simply wrong.

The decision to pursue the modern TypeScript stack still stands, and for sound
reasons beyond aesthetics: **getting off MongoDB** (Postgres is the durable default;
"Mongo is web scale" is over) and **long-term maintainability under AI-assisted
development** — a mainstream, typed, well-documented stack is far more tractable for
both humans and AI than the legacy app's `eval`'d templates, `Function.toString`
serialization, and untyped global CommonJS.

## Decision

**Destination unchanged (modern TS stack); execution is a disciplined strangler,
not a big-bang.** Concretely:

1. **Self-host single-org first.** The data layer is **single-tenant** (`@vulndesk/db`:
   `users`, `documents`, `comments`, `files` — no `org_id`/RLS yet). Auth stays as the
   existing login for now. The multi-tenant org/team/RBAC + OAuth-2.1-AS design
   (ADR-0002) is **deferred** until there is SaaS demand; `org_id` columns + RLS are a
   clean additive change when that day comes.

2. **Keep `@json-editor/json-editor`; do not reimplement the editor in RJSF.** It is a
   framework-agnostic vanilla-JS library; when the React frontend is built it is
   **embedded in a thin React wrapper, reusing the existing CVE5 editor config**
   (the ~195 keywords / uiSchema-equivalent already encoded). This retires the single
   largest rewrite risk and preserves editor parity nearly for free. *This supersedes
   ADR-0001 §2.3's choice of `@rjsf/core`.* RJSF stays on file as the fallback if
   embedding proves insufficient (e.g. for the eval'd-template behaviors, which must
   still be re-expressed declaratively for security).

3. **Data layer first** (it's the explicit "off Mongo" win and the foundation): build
   `@vulndesk/db` (Drizzle + Postgres, JSONB body + GIN + promoted columns) and the
   idempotent **Mongo→Postgres migrator**, validated on PGlite. ✅ Done in this ADR's
   commit.

4. **The characterization + e2e test net (638 tests) is the guardrail.** It is what
   makes an AI-driven, fast-moving migration *safe*: generated code that regresses
   legacy behavior fails loudly. Building it first was the right call.

## Consequences

- Much lower stall risk: every step ships and keeps the working app intact; nothing
  depends on a months-long editor rewrite landing before anything is usable.
- The new stack grows additively (`@vulndesk/core` → `@vulndesk/api` →
  `@vulndesk/db` → frontend) rather than as a from-scratch parallel app.
- Multi-tenancy and the full auth stack become a well-scoped *later* increment, not a
  tax paid up front.
- Some earlier work (the DocumentDB detour; the full multi-tenant auth ADR) was
  planning ahead of need — kept as records, but the operating rule now is: **ship
  cheap high-value increments on the modern packages; don't scaffold the SaaS layer
  until something pulls for it.**

## Status of the build after this ADR

`@vulndesk/core` (validation, TS) · `@vulndesk/api` (Hono + OpenAPI 3.1) ·
`@vulndesk/mcp-server` (stdio) · **`@vulndesk/db` (Drizzle/Postgres single-tenant +
Mongo→PG migrator)** — beside the legacy Express app, behind 638 tests. Next:
incremental front-end work (React shell embedding `@json-editor/json-editor`) and
wiring the API/migrator against a real Postgres, on the self-host path.
