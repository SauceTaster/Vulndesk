# Architecture Decision Records

These ADRs capture the significant architecture/technology decisions for the
Vulndesk rebuild, with enough context that a reader (or future us) understands
**why** — not just what. We follow the lightweight
[MADR](https://adr.github.io/madr/)-ish format: Status, Context, Decision,
Consequences.

## Process

- One ADR per significant, hard-to-reverse decision. Number them sequentially.
- Status is `Proposed` → `Accepted` → (later) `Superseded by ADR-XXXX` or
  `Deprecated`. Don't edit the decision of an accepted ADR; supersede it with a
  new one so the history stays honest.
- Keep evidence (research, benchmarks, citations) alongside under
  [`../research/`](../research) and link it from the ADR.

## Index

| ADR | Title | Status |
|---|---|---|
| [0001](./0001-modern-typescript-stack.md) | Modern TypeScript + React stack & target architecture | Accepted (editor §2.3 amended by 0003) |
| [0002](./0002-auth-and-mcp-authorization.md) | Authentication, authorization & MCP token validation | **Deferred** (SaaS phase) |
| [0003](./0003-self-host-first-and-editor.md) | Self-host-first sequencing; keep @json-editor/json-editor | Accepted |

### Decisions locked by ADR-0001 (quick reference)

- **API:** Hono + `@hono/zod-openapi` (Zod 4 → OpenAPI 3.1 single source of truth) · Scalar docs · Hono RPC (`hc<AppType>`) for the in-repo SPA.
- **Auth:** BetterAuth as the **OAuth 2.1 authorization server** (`@better-auth/oauth-provider` + `jwt()` + `organization` plugin with teams) — *not* the legacy `mcp()`/`oidcProvider()`.
- **AuthZ:** organization-plugin RBAC (`createAccessControl` → owner/admin/member/viewer over orgs → teams → members); Postgres **RLS** as defense-in-depth.
- **MCP auth:** the MCP server is an **OAuth 2.1 resource server** — RFC 9728 Protected Resource Metadata + RFC 8707 audience-bound JWT validation against BetterAuth's JWKS. Enterprise-Managed-Auth (ID-JAG / Okta XAA) is a kept-open seam, not v1.
- **Data:** Drizzle on `postgres.js`, `generate`+`migrate` (committed SQL), JSONB `body` + promoted columns + GIN, generated-`tsvector` FTS, PGlite for tests, one-way Mongo→PG ETL.
- **Frontend:** Vite SPA (TanStack Router + Query, **not** Start) · Tailwind v4 · shadcn/ui · TanStack Table.
- **CVE5 editor:** hybrid `@rjsf/core` v6 driven by the official CVE5 schema + custom widgets · `ae-cvss-calculator` replaces hand-rolled `cvssjs` · `vite-plugin-singlefile` for the offline bundle.
- **Tooling:** pnpm workspaces + catalogs · Turborepo · keep ESLint(flat)+Prettier and add `typescript-eslint` · stay on tsup/vitest · Changesets.

See [ADR-0001](./0001-modern-typescript-stack.md) for full rationale, rejected
alternatives, verified versions, risks, and the build sequencing.
