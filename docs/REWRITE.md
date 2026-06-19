# Vulndesk — Target Architecture & Rewrite Strategy

> This is the north star. `MODERNIZATION.md` was an *in-place upgrade* plan for
> the inherited v0.6.0 codebase; the parts that upgrade Express/Mongoose/Pug are
> now **superseded** — those layers are being **replaced**, not upgraded. The
> safety-net, hygiene, and headless-core work (Phases 0–2) still stand and feed
> the rewrite.

## Prime directive

**Be at least as good as Vulnogram pre-fork.** The whole point of the fork is to
carry forward the trust Vulnogram earned with PSIRT teams and CNAs. Every rewrite
step is gated on **behavioral + UX parity** with the Vulnogram people already
know. The characterization test suite and the running v0.6.0 app are the
executable spec for "as good as."

## Decided stack (the "core")

| Concern | Choice | Notes |
|---|---|---|
| Language | **TypeScript** | strict; whole codebase |
| Backend / API | **Hono** | tiny, fast, standards-based; runs Node/Bun/Cloudflare Workers — fits the API + MCP + automation + edge goals |
| Frontend | **React + TanStack** (Router, Query, Table) | SPA consuming the Hono API |
| Styling | **TailwindCSS** | replaces the hand-written CSS + `csso` pipeline |
| Domain validation | **Zod** | app models, API request/response I/O |
| CVE5 conformance | **AJV** | CVE5 *is* a canonical JSON Schema; keep spec-accurate validation in `@vulndesk/core` |
| ORM / DB | **Drizzle + PostgreSQL** | JSONB for CVE records, relational for orgs/teams/users; pgvector for search later |
| Auth | **BetterAuth** | replaces passport-local + express-session + csurf; has a Drizzle/Postgres adapter |

## Strategy: strangler-fig, not big-bang

1. **Keep the v0.6.0 app running** as the reference implementation and parity oracle.
2. **`@vulndesk/core`** (already created) is the shared, framework-agnostic kernel:
   CVE5 validation + transforms. It gets ported to TS and grows the Zod domain
   models. Both the old app and the new stack depend on it, so they can't diverge.
3. **Stand up the new Hono + React app beside the old one**, porting feature by
   feature. Each ported feature must pass the characterization tests and a parity
   checklist item before it replaces the old path.
4. **The Mongo → Postgres migration is the big lift** (acknowledged): design the
   relational + JSONB schema in Drizzle, write a one-way migrator from the Mongo
   documents, and dual-read/verify against the old store during cutover.

## Sequence (foundations first)

- [x] Phase 0–1 — safety net, hygiene, latent-bug fixes
- [x] Phase 2 (start) — headless `@vulndesk/core` with AJV CVE5 validation
- [~] **Characterization test suite** — lock current behavior (in progress)
- [ ] Port `@vulndesk/core` to TypeScript; add Zod domain models
- [ ] Drizzle + Postgres schema + Mongo→PG migrator (the lift)
- [ ] BetterAuth (orgs/teams/users) on Postgres
- [ ] Hono API exposing the core + auth + CRUD; OpenAPI from Zod
- [ ] React + TanStack + Tailwind SPA — port the CVE editor to parity
- [ ] Ecosystem: automation APIs, skills, MCP server (wraps `@vulndesk/core`)

## Parity checklist (seed — expand against the real app)

The new app is not "done" until these match the Vulnogram experience:
- CVE5 editor: every field, validation, required-field UX, problem types/impacts
- CVSS v2 / v3.0 / v3.1 / v4.0 calculators
- Open / import / download / preview (Source, Preview, CVE Portal tabs)
- Post to CVE.org (CVE Services API) + Seaview CVE search
- JSON-Schema "plugin" sections (cve5, cve, nvd, cvss4, …) and custom overrides
- Server mode: auth, save/version/audit-trail, comments, attachments, dashboards
- The offline standalone browser bundle (air-gapped PSIRT/CNA use)
