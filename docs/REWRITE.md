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

> **The concrete, version-verified package choices, rationale, rejected
> alternatives, risks, and build sequencing now live in
> [ADR-0001](./adr/0001-modern-typescript-stack.md)** (backed by the current-docs
> research in [`research/2026-06-stack-research.md`](./research/2026-06-stack-research.md)).
> The table below is the high-level summary; the ADR is the source of record.

| Concern | Choice | Key packages (see ADR-0001) |
|---|---|---|
| Language | **TypeScript** (strict) | `typescript`, `@tsconfig/strictest` |
| Backend / API | **Hono + `@hono/zod-openapi`** | OpenAPI 3.1 from Zod; Scalar docs; Hono RPC client |
| Frontend | **Vite SPA: React + TanStack Router/Query/Table** (not Start) | `@tanstack/react-*`, Tailwind v4, shadcn/ui |
| CVE5 editor | **`@rjsf/core` v6 (hybrid) + official schema + custom widgets** | `@rjsf/*`, `ae-cvss-calculator`, `vite-plugin-singlefile` |
| Domain validation | **Zod** (4.x) | one source of truth → validation + OpenAPI + types |
| CVE5 conformance | **AJV** in `@vulndesk/core` | spec-accurate; the editor + API + MCP all defer to it |
| ORM / DB | **Drizzle on `postgres.js`** | JSONB body + RLS + generated-`tsvector` FTS; PGlite tests |
| Auth (AS) | **BetterAuth = OAuth 2.1 authorization server** | `@better-auth/oauth-provider` + `jwt()` + `organization` (teams) |
| AuthZ | **org-plugin RBAC + Postgres RLS** | owner/admin/member/viewer over orgs → teams → members |
| MCP auth | **MCP server = OAuth 2.1 resource server** | RFC 9728 PRM + RFC 8707 audience-bound JWT vs BetterAuth JWKS |
| Tooling | **pnpm + Turborepo + ESLint/Prettier + Changesets** | keep tsup/vitest; add `typescript-eslint` |

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
