<!-- Output of the stack-research workflow (7 agents, current-docs-grounded), 2026-06-20. Evidence for ADR-0001. -->

## 1. Decision Summary

| Concern | Choice | Key packages (verified versions) | One-line why |
|---|---|---|---|
| API framework + OpenAPI | **Hono + @hono/zod-openapi** (`OpenAPIHono` + `createRoute`, emit 3.1 via `doc31`) | `hono@4.12.26`, `@hono/zod-openapi@1.4.0` | One Zod schema drives runtime validation, OpenAPI 3.1, and TS types — single source of truth. |
| Request validation | **Inside `createRoute`** (no standalone validator on OpenAPI routes) | `@hono/zod-validator@0.8.0` (transitive) | Spec and runtime validator never drift; no double-validation. |
| API docs UI | **Scalar** | `@scalar/hono-api-reference@0.11.4` | First-party Hono integration, modern UI + built-in try-it client, consumes the same `/doc`. |
| Internal SPA → API | **Hono RPC (`hc<AppType>`)** + publish OpenAPI for external consumers | `hono/client` (ships with hono) | Zero-codegen end-to-end types in-repo; spec covers third parties + MCP HTTP. |
| Frontend shell | **Vite SPA: TanStack Router + Query** (NOT Start) | `@tanstack/react-router@1.170.16`, `@tanstack/react-query@5.101.0` | Authenticated PSIRT tool needs no SSR; smaller, fully-stable surface on the existing Hono API. |
| CSS engine | **Tailwind v4 via `@tailwindcss/vite`**, CSS-first `@theme` | `tailwindcss@4.3.1`, `@tailwindcss/vite@4.3.1` | Fastest, lowest-config; token-driven theming for a dense data app. |
| Component layer | **shadcn/ui** (Radix today, Base UI optional later) | `shadcn` CLI, `@radix-ui/react-*`, `class-variance-authority`, `tailwind-merge`, `lucide-react` | Own the source, Tailwind-v4/React-19 ready, fastest path to parity; primitive layer is swappable. |
| **CVE5 editor engine** | **HYBRID: `@rjsf/core` v6 + official CVE5 schema + uiSchema + ~6 custom widgets** | `@rjsf/core@6.6.2`, `@rjsf/utils@6.6.2`, `@rjsf/shadcn@6.6.2`, `@rjsf/validator-ajv8@6.6.2` | RJSF owns oneOf/array/conditional/AJV plumbing; we own only the parity-critical widgets. |
| Editor validation | **`@rjsf/validator-ajv8` configured to match `@vulndesk/core`; core is final authority** | `@rjsf/validator-ajv8@6.6.2`, `ajv@8.17.1`, `ajv-formats@3.0.1` | One schema everywhere — form-says-valid / API-rejects bug is structurally impossible. |
| CVSS calculators | **`ae-cvss-calculator`** (v2/v3.0/v3.1/v4.0) wrapped in a custom widget | `ae-cvss-calculator@1.0.12` | One audited, zero-dep TS lib replaces hand-rolled `cvssjs` + vendored FIRST `cvss40.js`. |
| Data tables | **TanStack Table v8** (headless) | `@tanstack/react-table@8.21.3` | Headless, TS-first, composes with shadcn/Tailwind; virtualization-ready for dense data. |
| Offline standalone bundle | **Vite + `vite-plugin-singlefile`** | `vite-plugin-singlefile@2.3.3` | One self-contained `index.html`; retires the Pug+Makefile+terser/csso pipeline. |
| Auth / Authorization Server | **BetterAuth + `@better-auth/oauth-provider`** (NOT legacy `mcp()`/`oidcProvider()`) | `better-auth@1.6.19`, `@better-auth/oauth-provider@1.6.19` | New, maintained, OAuth 2.1 + MCP-enabled AS; legacy `@better-auth/mcp` is frozen at 1.4.17. |
| Access-token format | **JWT via BetterAuth `jwt()` plugin** | `better-auth/plugins` (`jwt()`) | JWKS-verifiable offline tokens so the separate MCP resource server validates statelessly. |
| RBAC model | **organization plugin: `createAccessControl` + static roles, teams enabled** | `better-auth/plugins`, `better-auth/plugins/access` | Typed resource-action roles (owner/admin/member/viewer) over orgs→teams→members; defer dynamic roles. |
| MCP resource server | **RFC 9728 PRM + RFC 8707 audience-bound JWT validation against BetterAuth JWKS** | `@better-auth/oauth-provider@1.6.19`, `@modelcontextprotocol/sdk@1.22.0` | Standards-correct, stateless, decoupled from the AS DB/process. |
| ORM + DB | **Drizzle ORM on postgres.js** | `drizzle-orm@0.45.2`, `postgres@3.4.9` | Consensus 2026 greenfield default; faster, TS-first, simpler API than `pg`. |
| Migrations | **`generate`→`migrate` (committed SQL); `push` dev-only** | `drizzle-kit@0.31.10` | Auditable, reviewable history — non-negotiable for a security tool. |
| Multi-tenant isolation | **`org_id` FK + Postgres RLS via transaction-scoped `set_config(...,true)`** | `drizzle-orm` (`pgPolicy`, `pgRole`) | DB-level defense-in-depth; one forgotten `WHERE` can't cross tenants. |
| CVE storage | **JSONB `body` + promoted btree columns (`cve_id`,`state`) + GIN `jsonb_path_ops`** | `drizzle-orm` (`jsonb`, `index`) | Lossless canonical record, indexed containment + fast hot-field equality. |
| Full-text search | **STORED generated `tsvector` column + GIN, `websearch_to_tsquery`** | `drizzle-orm` (`customType`, `generatedAlwaysAs`) | Auto-maintained, weighted, end-user-safe parser; replaces Mongo `$**`. |
| Semantic search | **Defer pgvector; design for it (HNSW + `vector_cosine_ops`)** | `drizzle-orm` (`vector`), `pgvector` ext, `@electric-sql/pglite-pgvector` (tests) | Standard in-Postgres vector store; keep RLS/test uniformity when needed. |
| DB testing | **PGlite (WASM Postgres) + Vitest**, same migrations as prod | `@electric-sql/pglite@0.5.3`, `vitest@4` | Real Postgres semantics (JSONB/FTS/RLS) in ms, no Docker. |
| Mongo→PG migration | **One-way batch ETL** to relational+JSONB, Zod-validated, `legacy_mongo_id` keyed | `drizzle-orm`, existing `mongoose@6`, `@vulndesk/core` Zod | Small dataset; avoids the #1 failure (whole-doc → single JSONB blob). |
| Package manager | **pnpm workspaces + catalogs**, `workspace:*` internal deps | `pnpm@10` | Strict node_modules kills phantom deps; catalogs pin shared versions across packages. |
| Task orchestration | **Turborepo** | `turbo` | Hash-based local/remote caching, graph-aware (core→mcp-server) rebuilds. |
| Lint + format | **Keep ESLint flat + Prettier; add `typescript-eslint`** | `eslint@10`, `typescript-eslint`, `prettier@3`, `eslint-config-prettier@10` | Type-aware `no-floating-promises`/`no-misused-promises` are essential and where Biome is weakest. |
| Library build | **Stay on tsup; track tsdown for 1.0** | `tsup@8`, (watch `tsdown`) | Single-entry packages already build fast; tsdown is sub-1.0 today. |
| Shared TS config | **`@tsconfig/strictest` + Node base, `moduleResolution: bundler`** | `@tsconfig/strictest`, `@tsconfig/node-lts`, `typescript@6` | Hardens/de-dupes config; forward-compatible with TS 7.0 (tsgo). |
| Versioning/release | **Changesets** | `@changesets/cli`, `changesets/action` | You publish `@vulndesk/*`; auto inter-package bumps + changelogs + release PR. |
| Test runner | **Vitest with `projects`** (not the deprecated workspace file) | `vitest@4` | Already in use; one process, isolated projects per package. |

---

## 2. Per-Area Decisions

### 2.1 Hono API + OpenAPI + typed client

**Final decision.** Build the API on **`@hono/zod-openapi`** (`OpenAPIHono` class + `createRoute`). Define request/response schemas *inside* `createRoute({ request, responses })` — do not bolt a standalone `zValidator` onto OpenAPI routes (use `@hono/zod-validator` directly only for the handful of routes you deliberately exclude from the public spec, e.g. internal webhooks). Emit **OpenAPI 3.1** explicitly via `app.doc31('/doc', …)` / `getOpenAPI31Document()` — `app.doc()` emits 3.0.0 and loses Zod 4's richer JSON-Schema fidelity. Serve docs with **Scalar** (`@scalar/hono-api-reference`) pointed at `/doc`. The in-repo React SPA consumes the API via the **Hono RPC client** (`hc<AppType>` from `hono/client`) — zero codegen, compile-time end-to-end types — while the same `/doc` spec is published for external/automation consumers and the MCP server's HTTP surface.

**Why this is coherent with the rest of the system.** `@hono/zod-openapi@1.4.0` made `zod` a **peer dep at `^4.0.0`** (via `@asteasolutions/zod-to-openapi ^8.5.0`), so it natively consumes the repo's `zod@4.4.3` and the `@vulndesk/core` Zod models with no bundled-zod conflict — the historical pain point is gone. This is the keystone that lets *one* Zod definition flow from `@vulndesk/core` → API validation → OpenAPI doc → RPC client types.

**Versions (verified npm 2026-06-19):** `hono@4.12.26`, `@hono/zod-openapi@1.4.0` (peer `hono>=4.10.0`, `zod ^4.0.0`), `@hono/zod-validator@0.8.0`, `@scalar/hono-api-reference@0.11.4`. Fallback: `@hono/swagger-ui@0.6.1`.

**Rejected.** `hono-openapi@1.3.0` (still self-labeled "in development"; validator-agnosticism is dead weight in an all-Zod repo). `paolostyle/hono-zod-openapi` (built for retrofitting existing apps; ours is greenfield). Hono's bare `describeRoute`/Standard-Schema generator (weakest inference). OpenAPI-codegen-only client for the internal app (adds a build step that can lag the server). tRPC (redundant — Hono RPC already gives typed clients).

**Mandatory guardrails (RPC compiler-performance cliff).** A large `@hono/zod-openapi` route graph can trigger *"Type instantiation is excessively deep and possibly infinite"* and slow tsserver. Mitigate from day one: pin **one** Hono version (`4.12.26`) across the whole workspace via the pnpm catalog; `strict: true` in every tsconfig; split routes into feature sub-routers exported through a single `AppType` barrel; use **TS project references** to pre-compile server types. Validate the generated 3.1 spec against the CVE5 models early — `@asteasolutions/zod-to-openapi` may not cleanly translate every advanced Zod 4 construct (discriminated-union edge cases, recursive/lazy schemas, refinements); add `.openapi()`/`.meta()` overrides where auto-mapping is imperfect.

*Cites:* https://hono.dev/examples/zod-openapi · https://www.npmjs.com/package/@hono/zod-openapi · https://hono.dev/docs/guides/rpc · https://hono.dev/examples/scalar · https://github.com/honojs/middleware/issues/1134

---

### 2.2 React frontend (TanStack + Tailwind v4 SPA)

**Final decision.** A **Vite SPA** with **TanStack Router + TanStack Query** — explicitly **not TanStack Start** (a full-stack meta-framework still at v1 RC; it would duplicate the Hono backend we already own, and an authenticated PSIRT tool needs no SSR/SEO). Style with **Tailwind v4** through the first-party `@tailwindcss/vite` plugin and **CSS-first `@theme`** config (no `tailwind.config.js`, no PostCSS). Components from **shadcn/ui** (copy-in, new-york style, `data-slot`), updated for Tailwind v4 + React 19, keeping the option to flip primitives to Base UI later. Dense collections (affected products, references, CVE lists) render with **TanStack Table v8**. The SPA talks to the API through the **`hc<AppType>` typed client wrapped in hand-written `queryOptions`/`mutationOptions`** (the Hono-RPC ↔ TanStack-Query bridge is manual but fully type-safe).

**Versions (verified):** `@tanstack/react-router@1.170.16`, `@tanstack/react-query@5.101.0`, `@tanstack/react-table@8.21.3`, `tailwindcss & @tailwindcss/vite@4.3.1`, `react@19.2.7`. Build with `@tanstack/router-plugin` (file-based routes) + `@vitejs/plugin-react`(`-swc`).

**Rejected.** TanStack Start (RC, adds a Nitro server to deploy). Next.js / React Router 7 framework mode (SSR-centric, wrong fit for a separate-API SPA). Tailwind v3 + PostCSS + JS config (legacy, slower). CSS-in-JS (runtime cost). Panda CSS / Ark UI / Park UI (pair best with Panda and diverge from the shadcn mainstream). React Aria Components (deepest a11y but most code-per-component; overkill unless a11y certification becomes a hard requirement). AG Grid / MUI DataGrid / Ant Table (heavy, license/styling friction with Tailwind+shadcn).

**Risks.** `hc` inference can pressure tsserver on a large router (same mitigation as §2.1: single `AppType` barrel, sub-routers, optional OpenAPI client if the SPA team diverges from the API team). Radix's update cadence slowed post-WorkOS acquisition — mitigated because shadcn now also supports Base UI as the primitive layer, so you can migrate primitives without rewriting your component API. Pin and dedupe **all `@tanstack/*` packages on a single matching release line** via the catalog — mismatched versions cause subtle type/runtime issues.

*Cites:* https://tanstack.com/start/latest/docs/framework/react/guide/spa-mode · https://tanstack.com/router/latest · https://tailwindcss.com/docs/installation/using-vite · https://ui.shadcn.com/docs/tailwind-v4 · https://tanstack.com/table/latest/docs/introduction

---

### 2.3 The CVE5 editor + CVSS + offline bundle (parity-critical)

This is the highest-effort, parity-defining surface, and it produced the one genuine **cross-area conflict** in the research. See §6 for the resolution; the decision below is the resolved position.

**Final decision — HYBRID RJSF.** Adopt **`@rjsf/core` v6** as the form engine, driven by the **official CVE5 JSON Schema** (`packages/core/schema/CVE_Record_Format.json`, already wired in `@vulndesk/core`) plus a **hand-authored uiSchema**, and override the ~6 parity-critical interactions with **custom RJSF widgets/fields** registered through the `@rjsf/shadcn` theme. RJSF natively handles the CVE5 shape — heavy `oneOf`/`anyOf`/`$ref`, `if/then/else`, arrays-of-arrays — which is exactly the plumbing a from-scratch renderer would have to reinvent.

**The real parity finding (presentation, not validation).** The *current* editor is **not** driven by the official CVE5 schema — it runs on a bespoke `@json-editor` dialect (`default/cve5/cve5.schema.json`) carrying **195 `options`, 107 `format`, 16 `watch`, 18 `template` (eval'd JS)** custom keywords that encode the entire layout, conditional logic, grid sizing, icons, and ordering. **None** of these survive automatically. The migration cost is hand-authoring an equivalent **uiSchema + ~6 custom widgets**, driven from a field-by-field parity checklist against the live tool. AJV validation is the *easy* part — it's already done in `@vulndesk/core`. The eval'd `template` watchers must be re-expressed as declarative uiSchema/`oneOf` or small typed widget logic (a security improvement — removes arbitrary `eval` from the editor — but every dynamic behavior must be inventoried so none is silently dropped).

**Validation — one validator everywhere.** Use `@rjsf/validator-ajv8` for live field-level UX, but configure its AJV instance to match `@vulndesk/core` exactly (same `CVE_Record_Format.json`, same offline `$ref` registration for CVSS sub-schemas + tag files, `allErrors:true`, `strict:false`). Treat **`@vulndesk/core`'s `validateRecord()` as the single source of truth** for final/publish-time validation across server + MCP + standalone. ⚠️ **Version-skew to pin:** `@rjsf/validator-ajv8` declares `ajv-formats ^2.1.1` while `@vulndesk/core` uses `ajv-formats ^3.0.1` — behaviorally equivalent for CVE5's formats, but pin/dedupe deliberately and **add a cross-validator agreement test** over a corpus of real CVE records so the form and the API can never disagree.

**CVSS.** Replace both the hand-rolled `cvssjs` (`public/js/util.js`) **and** the vendored FIRST `cvss40.js` with **one** maintained TS library, **`ae-cvss-calculator@1.0.12`** (Apache-2.0, zero runtime deps; exports `Cvss2/Cvss3P0/Cvss3P1/Cvss4P0` + `fromVector()` auto-detect + per-metric component definitions for building the picker UI). Wrap it in a custom RJSF widget that writes the canonical `vectorString` + `baseScore` back into the record's metrics block. ⚠️ **Could not verify from docs** that `ae-cvss-calculator` passes the FIRST official v4.0 test vectors — **before shipping, run the FIRST CVSS v4.0 example vectors as a regression suite** and keep the existing `test/cvss.test.js` snapshots as a guard during the swap.

**CWE/CAPEC autocomplete + array editors.** Custom RJSF widgets registered in the theme, selected per-field via `ui:widget` + `ui:options`. Build a shadcn **Combobox on `cmdk`** (already a `@rjsf/shadcn` dep) that loads the existing `cwe-*.json` / `capec.json` datasets shipped as static assets. This drops three legacy deps (Tagify, the eval'd template engine, `@json-editor`).

**Offline standalone bundle.** Replace the **Pug + Makefile + terser/csso** pipeline with a second **Vite** build target using **`vite-plugin-singlefile@2.3.3`**, emitting one self-contained `dist/index.html` with the `@vulndesk/core` validator and all CWE/CAPEC/CVSS datasets **inlined, not fetched** (the bundle runs from `file://` — `allowAjax:false` today; a fetched dataset would silently kill offline autocomplete/validation).

**Versions (verified):** `@rjsf/core@6.6.2` (+ `utils`/`shadcn`/`validator-ajv8` at `6.6.2`, published 2026-06-06), `ajv@8.17.1`, `ajv-formats@3.0.1`, `cmdk@1.1.1`, `ae-cvss-calculator@1.0.12` (published 2026-03-30), `vite-plugin-singlefile@2.3.3`.

**Rejected.** Lifting the legacy `@json-editor` schema verbatim (non-standard draft-04 dialect with eval'd templates; a security/maintenance liability). A 100% custom renderer as the *primary* engine (months reinventing oneOf/array/conditional/AJV plumbing RJSF already ships and tests). TanStack Form / react-hook-form as the *primary* editor engine (field-state libs, not JSON-Schema renderers — fine *inside* a custom widget). `@neuralegion/cvss` (no v2/v4 — parity regression), `@pandatix/js-cvss` (stale, 0.x), re-vendoring FIRST's calculator (not a package, no v2/v3). Keeping the Makefile/Pug/terser pipeline (two rendering stacks to maintain).

**License note.** `@rjsf/core`/`utils`/`validator-ajv8` are Apache-2.0 (NOTICE/attribution obligations); `@rjsf/shadcn`, `ae-cvss-calculator`, `vite-plugin-singlefile` are MIT/Apache-2.0 — all compatible with the project's MIT license; record Apache-2.0 attributions in the distribution.

⚠️ **React 19:** RJSF v6 officially guarantees React 18; React 19 support is "in progress" per the v6 upgrade guide. Since the SPA targets `react@19.2.7`, validate the chosen `@rjsf/*` widgets under React 19 **early** rather than assuming parity.

*Cites:* https://rjsf-team.github.io/react-jsonschema-form/docs/migration-guides/v6.x%20upgrade%20guide/ · https://rjsf-team.github.io/react-jsonschema-form/docs/advanced-customization/custom-widgets-fields/ · https://www.npmjs.com/package/ae-cvss-calculator · https://github.com/richardtallent/vite-plugin-singlefile

---

### 2.4 Data layer — Drizzle + PostgreSQL

**Final decision.** **`drizzle-orm` on postgres.js** (`drizzle-orm/postgres-js`). Migrations are **two-track**: `drizzle-kit push` for local iteration only; **`generate` → commit SQL (+ `meta/_journal.json`) → `migrate`** for every database you care about (CI/staging/prod). Tests run against **PGlite** (real Postgres-in-WASM) via `drizzle-orm/pglite` with Vitest, applying the **same committed migrations** so test schema == prod schema.

**Multi-tenancy.** Shared-database/shared-schema with `org_id uuid NOT NULL` FK on every tenant-owned table, enforced in **two layers**: (1) app-level `where(eq(table.orgId, ctx.orgId))`, and (2) Postgres **RLS** (`pgPolicy` + `pgRole`) driven by a **transaction-scoped** `set_config('app.current_org_id', $orgId, true)` inside `db.transaction(...)`, with policies `USING (org_id = current_setting('app.current_org_id')::uuid)`. The `true` (= `SET LOCAL`) flag ties the setting to the transaction so it cannot leak across pooled connections.

**CVE storage + indexing.** Store the record as a single **`jsonb` `body`** column (`jsonb('body').$type<CveRecord>()`, typed via the `@vulndesk/core` Zod model). Promote the 2–3 always-queried fields (`cve_id`, `state`, `assigner`) to real/generated columns with **btree** indexes, and add a **GIN `jsonb_path_ops`** index for `@>` containment. (GIN does *not* accelerate `->>` equality or `?` key-existence — that's why the hot scalars are promoted.)

**Full-text search.** A **STORED generated `tsvector` column** (Drizzle `customType` + `generatedAlwaysAs(setweight(...)||setweight(...))`) with a GIN index, queried via **`websearch_to_tsquery('english', …)`** and `@@`, ranked with `ts_rank_cd`. Replaces Mongo's `$**` index; Postgres auto-maintains it on write (no triggers).

**Semantic search.** **Deferred but designed for**: when needed, `CREATE EXTENSION vector` in a migration, add `vector('embedding', { dimensions: N })` + an **HNSW** index with `vector_cosine_ops`, query via `cosineDistance()`/`<=>`. Keep it testable via `@electric-sql/pglite-pgvector`.

**Mongo→PG migration.** A **one-way batch ETL** (Node, maintenance window): stream each Mongo doc → validate/normalize with the existing `@vulndesk/core` `DocumentEnvelopeSchema` (Zod, `strict:false`, preserves unknown keys) → map `doc → documents` (`org_id`, `author`, `body jsonb`, slugs, timestamps), `comments[] → comments`, `files[] → files` (FK `document_id`, `org_id`). Carry Mongo `_id` into **`legacy_mongo_id`** for idempotent re-runs; backfill the generated `tsvector` automatically; verify row counts + JSONB round-trips. Take a **full Mongo backup first** (one-way).

**Versions (verified):** `drizzle-orm@0.45.2`, `drizzle-kit@0.31.10`, `postgres@3.4.9`, `@electric-sql/pglite@0.5.3`, `vitest@4`. (`pg@8.22.0` available as fallback.)

**Rejected.** `pg`/node-postgres as default (solid fallback, but edged out on throughput + clunkier API). `push`-everywhere (no audit history, destructive diffs — unacceptable for a security tool). Atlas/Flyway (extra tooling drizzle-kit covers). Testcontainers/Docker for unit/integration (slow; keep for a thin e2e tier only). SQLite/mocks for tests (loses JSONB/FTS/RLS/pgvector semantics). DB-/schema-per-tenant (operational + migration cost). App-level filtering only (one missed `WHERE` leaks data). Session-level `SET` (leaks across pooled connections). Fully normalizing the CVE record (huge churn against an evolving schema, lossy). Whole-document → single JSONB blob (the #1 migration failure mode). CDC/Debezium (overkill for a small one-way cutover).

**Risks.** **RLS pool-safety:** always `SET LOCAL`/`set_config(...,true)` inside a transaction, ensure the app role lacks `BYPASSRLS` (owners/superusers silently bypass RLS), and add a CI test proving cross-tenant queries return zero rows. **`drizzle-kit push` mis-generates advanced indexes** (confirmed open issue #5792: HNSW loses its operator class on push) — use `generate`+`migrate` and eyeball DDL for anything with GIN/HNSW/generated columns. **GIN cast mismatches** silently fall back to seq scans — verify every path with `EXPLAIN (ANALYZE, BUFFERS)`. **PGlite is single-connection WASM** — keep a thin real-Postgres e2e tier for RLS-pooling and migration-script behavior PGlite can't exercise. **FTS config drift** — the generated `tsvector` and query config (`'english'`) must match; pick deliberately if content is multilingual. **Migration idempotency** — without `legacy_mongo_id` a partial-failure re-run double-inserts; quarantine records that violate new NOT NULL/FK constraints (missing `author`, orphan comments) before cutover. **Pin exact versions** — drizzle-orm/kit have had breaking minor releases, especially in migration-diff and RLS APIs.

*Cites:* https://orm.drizzle.team/docs/get-started-postgresql · https://orm.drizzle.team/docs/migrations · https://orm.drizzle.team/docs/rls · https://orm.drizzle.team/docs/connect-pglite · https://www.crunchydata.com/blog/indexing-jsonb-in-postgres · https://orm.drizzle.team/docs/guides/full-text-search-with-generated-columns

---

### 2.5 Monorepo + tooling + build

**Final decision.** Migrate npm workspaces → **pnpm workspaces** (`pnpm@10`) with the **`workspace:*`** protocol for internal deps and a **catalog** (`pnpm-workspace.yaml`) pinning shared deps (zod, typescript, @types/node, vitest, tsup, hono, the `@tanstack/*` line). Add **Turborepo** (`turbo.json` with `dependsOn` for the core→mcp-server graph; defer remote caching until CI time hurts). **Keep ESLint flat + Prettier** and **add `typescript-eslint`** to the TS packages (currently excluded from lint) — do *not* switch to Biome as the type-aware linter. **Stay on tsup**; track **tsdown** for a cheap post-1.0 migration. **Keep Vitest**, configured with the inline **`projects`** array (the standalone `vitest.workspace` file is deprecated since 3.2). Adopt a shared **`@tsconfig/strictest` + Node base**, `moduleResolution: bundler` / `module: preserve`, replacing the hand-rolled per-package tsconfig. Adopt **Changesets** (`@changesets/cli` + `changesets/action`) because you publish `@vulndesk/core` and `@vulndesk/mcp-server`.

**Repo context (confirmed in-tree).** Root is a **legacy CommonJS Express app** (`express@4`, `mongoose@6`, `pug@3`, `passport`, `make min` build) alongside two **ESM TS packages** on `typescript@6.0.3` and `vitest@4.1.9`, `@types/node@26`, Node engine `>=20`. The internal dep is currently `"@vulndesk/core": "*"` in mcp-server — **change to `"workspace:*"`** under pnpm so it always resolves locally and Changesets can bump it correctly. TS 6.0 is the *final* JS-based TS release (strict + ESM are defaults); **TS 7.0 (tsgo) is preview-only** — do not depend on it for CI typechecking yet, but the bundler/strict/ESM config above is forward-compatible when it lands.

**Versions (verified/noted):** `pnpm@10` (10.33.0 noted Apr 2026), `turbo`, `eslint@10`, `typescript-eslint`, `prettier@3`, `eslint-config-prettier@10`, `tsup@8.5.1`, `vitest@4.1.9`, `@tsconfig/strictest`, `typescript@6.0.3`, `@changesets/cli`. ⚠️ `tsdown` is sub-1.0 (`v0.22.x`) — do **not** adopt yet for a published library.

**Rejected.** npm workspaces (no catalogs, looser local resolution). Bun (fastest installs but monorepo-correctness still maturing; risky with the legacy CommonJS app). Yarn (no advantage). Nx (heavier; justified only for multi-team/multi-app-type repos). Bare `pnpm run --workspaces` (no caching). Biome full switch (type-aware rules cover only ~75–85% of typescript-eslint cases and analyze single-file only — fatal for reliable `no-floating-promises`/`no-misused-promises` on async DB/HTTP code; revisit Biome-as-formatter only later). Oxlint (even more limited). tsdown now (pre-1.0 churn). Manual versioning / semantic-release / Nx release.

**Sequencing within this area (critical).** The repo is mid-migration, so do **not** couple all changes into one PR: (1) switch to pnpm **first** (mechanical) and verify the **legacy Express app still installs/runs under pnpm's strict node_modules** — phantom-dependency breakage in old Express middleware is the main risk; start catalogs in default/`prefer` mode and tighten to `strict` after the loose ranges are reconciled. (2) Then layer in Turborepo + the shared tsconfig + typescript-eslint.

*Cites:* https://pnpm.io/catalogs · https://www.pkgpulse.com/guides/turborepo-vs-nx-monorepo-2026 · https://biomejs.dev/blog/biome-v2/ · https://tsdown.dev/guide/migrate-from-tsup · https://github.com/tsconfig/bases · https://vitest.dev/guide/projects · https://infinum.com/handbook/frontend/changesets

---

## 3. Auth & MCP Architecture (detailed)

This section resolves the auth track into one concrete system and is the spine for the auth ADRs.

### 3.1 Roles in the system

```
                         ┌──────────────────────────────┐
                         │   BetterAuth (in Hono API)    │
   browser (SPA) ──────▶ │  = OAuth 2.1 Authorization    │
   credentials:include   │    Server                     │
                         │  • @better-auth/oauth-provider│
                         │  • jwt() → JWKS               │
                         │  • organization (RBAC + teams)│
                         │  • Drizzle/pg adapter         │
                         └──────────────┬───────────────┘
                                        │  issues audience-bound JWT
                                        │  (PKCE, auth_code/refresh/
                                        │   client_credentials)
        MCP client (Claude/IDE) ────────┤  discovers AS via PRM
                                        ▼
                         ┌──────────────────────────────┐
                         │   @vulndesk/mcp-server        │
                         │  = OAuth 2.1 Resource Server  │
                         │  • RFC 9728 PRM endpoint      │
                         │  • validates JWT vs JWKS      │
                         │    (iss + aud + scope)        │
                         │  • wraps @vulndesk/core tools │
                         └──────────────────────────────┘
```

### 3.2 BetterAuth as the Authorization Server

Use the **new `@better-auth/oauth-provider` plugin** (`oauthProvider()`), paired with the **`jwt()` plugin** so access tokens are **JWTs verifiable via JWKS**. Do **not** use the legacy `mcp()` or `oidcProvider()` plugins: docs state the `mcp` plugin "will soon be deprecated in favor of the OAuth Provider Plugin," `@better-auth/mcp` is **frozen at 1.4.17** (release-1.4 line) while core is **1.6.19** (published 2026-06-18), endpoints moved `/mcp/*` → `/oauth2/*`, and `oidcProvider` is likewise being superseded. `oauthProvider` is OAuth 2.1-compliant (PKCE-required public clients; `authorization_code`/`refresh_token`/`client_credentials`), is "MCP Enabled," exposes RFC 8414/OIDC discovery, and supports RFC 7591 dynamic client registration.

**Mount on Hono (Drizzle/pg adapter):**

```ts
betterAuth({
  database: drizzleAdapter(db, { provider: 'pg' }),
  plugins: [
    jwt(),                                   // must precede consumers; enables JWKS-verifiable JWTs
    oauthProvider({ loginPage: '/sign-in', consentPage: '/consent',
                    allowDynamicClientRegistration: true }),
    organization({ ac, roles, teams: { enabled: true } }),
  ],
})
// app.on(['POST','GET'], '/api/auth/*', c => auth.handler(c.req.raw))
```
Register **CORS on `/api/auth/*` BEFORE the auth routes**; the SPA must send `credentials:'include'`. Add a session middleware calling `auth.api.getSession` to set `c.var.user/session`. Generate the org/team/member/invitation/oauth tables with BetterAuth's CLI and keep them in the Drizzle migration set (§2.4).

### 3.3 The MCP server as Resource Server (RFC 9728 / RFC 8707)

The `@vulndesk/mcp-server` runs as its **own process** (stdio binary today; HTTP transport for remote auth) and must **not** share BetterAuth's DB session. It validates **bearer JWTs offline against BetterAuth's JWKS**, enforcing **`iss` = the BetterAuth AS base URL** and **`aud` = the MCP server's canonical resource URI** (RFC 8707; **no trailing slash, no fragment**). Per the current MCP authorization spec (OAuth 2.1 draft-13-based), it:

- Serves **RFC 9728 Protected Resource Metadata** at `/.well-known/oauth-protected-resource` (built from `getProtectedResourceMetadata` with `resource=<canonical MCP URI>`, `authorization_servers=[<AS URL>]`).
- On missing/invalid token → **HTTP 401** with `WWW-Authenticate: Bearer resource_metadata="…"` + scope hint.
- On insufficient scope → **HTTP 403** `error="insufficient_scope"`.
- **Rejects any token whose `aud` is not itself** (confused-deputy / token-passthrough prevention) and never transits tokens onward. Token must arrive in the `Authorization: Bearer` header (query-string tokens are prohibited).

Use BetterAuth's `verifyAccessToken` (from `better-auth/oauth2`) / `oauthProviderResourceClient`; the `mcpHandler({ jwksUrl, verifyOptions: { issuer, audience } })` wrapper packages this for an MCP HTTP transport.

> ⚠️ **Verification caveat (flagged for ADR).** Package names and versions and the *shape* of the APIs are verified from npm + current docs, but the **exact helper signatures** (`mcpHandler`, `verifyAccessToken`, `oauthProviderResourceClient`, `getProtectedResourceMetadata`, `withMcpAuth`) are summarized from docs and **must be pinned against the installed 1.6.x `.d.ts` before coding** — `@better-auth/oauth-provider` is new and moving (`1.7.0-beta.8` exists; a release-1.4 line is still maintained). Re-check on every minor bump.

**Rejected.** `auth.api.getMcpSession` / `createMcpAuthClient` (remote DB lookup — couples RS to the AS DB/process; part of the deprecated mcp surface). Opaque-token introspection (network round-trip per call; JWKS verification is stateless). Skipping PRM (non-conformant). Rolling our own AS.

### 3.4 Role / permission model (owner / admin / member / viewer)

Use the **organization plugin** with `createAccessControl(statement)` + `ac.newRole` to define **static** roles over a resource-action statement, and enable **teams** for the orgs→teams→members hierarchy:

```ts
const ac = createAccessControl({
  advisory:    ['create','read','update','delete','publish'],
  organization:['update','delete'],
  team:        ['create','update','delete'],
  member:      ['invite','remove','update-role'],
});
const roles = {
  owner:  ac.newRole({ advisory:['create','read','update','delete','publish'],
                       organization:['update','delete'], team:['create','update','delete'],
                       member:['invite','remove','update-role'] }),
  admin:  ac.newRole({ advisory:['create','read','update','delete','publish'],
                       team:['create','update','delete'], member:['invite','remove','update-role'] }),
  member: ac.newRole({ advisory:['create','read','update'] }),
  viewer: ac.newRole({ advisory:['read'] }),                 // read-only, extends the defaults
};
```
Enable teams via `{ enabled: true, maximumTeams, allowRemovingAllTeams: false }`. Enforce server-side with `auth.api.hasPermission` and client-side with `authClient.organization.checkRolePermission`. **Defer `dynamicAccessControl`** (DB-stored custom roles + `organizationRole` table) to a later phase — static roles are simpler and synchronously checkable, and dynamic roles can be enabled later without ripping them out.

**Rejected.** `admin` plugin alone (app-wide, not per-org/per-team). `dynamicAccessControl` from day one (extra schema + runtime CRUD before a product need). Hand-rolled RBAC.

### 3.5 Enterprise-managed-auth forward path (ID-JAG / Okta XAA)

**Not implemented in v1** — treat as a future, **optional/additive** extension. The Enterprise-Managed Authorization extension went **STABLE 2026-06-18** (Okta first IdP; Claude/VS Code first clients), but MCP extensions are explicitly never active by default, and a self-hosted PSIRT tool acting as its own AS needs none of it for conformance. **Keep the seams open:** design the AS so it can later validate externally-issued **ID-JAG JWTs** (RFC 8693-style token exchange) against an enterprise IdP's JWKS and **map IdP claims → org/team roles**. ⚠️ No BetterAuth plugin for AS-side ID-JAG validation is verifiable today, so committing now would be speculative.

### 3.6 Standing auth risks

- **RFC 8707 audience binding** is easy to get subtly wrong: the `resource` param (client), the token `aud`, and the RS's expected audience must match **exactly** (canonical URI, no trailing slash) or every request 401s.
- **Stale tutorials** still reference `/mcp/*` and `getMcpSession` — following them couples the RS to the AS DB and uses deprecated paths.
- **`jwt()` ordering:** omit it and tokens are opaque → the separate RS can't validate offline (would need introspection).
- **Shifting conformance target:** the MCP auth spec is on OAuth 2.1 draft-13 + an evolving "draft" revision (Client ID Metadata Documents now preferred; DCR marked deprecated-but-retained). Track the protocol revision string and re-validate PRM / `WWW-Authenticate` / `iss` (RFC 9207) behavior each release.
- **Schema sync:** the org+team+oauth Drizzle tables must be CLI-generated and kept in migrations as plugins change (e.g. `organizationRole` if dynamic AC is later enabled), or runtime failures follow.

*Cites:* https://better-auth.com/docs/plugins/oauth-provider · https://better-auth.com/docs/plugins/jwt · https://better-auth.com/docs/plugins/organization · https://better-auth.com/docs/integrations/hono · https://modelcontextprotocol.io/specification/draft/basic/authorization · https://datatracker.ietf.org/doc/html/rfc9728 · https://www.rfc-editor.org/rfc/rfc8707.html · https://modelcontextprotocol.io/extensions/auth/enterprise-managed-authorization

---

## 4. Open Questions / Risks (cross-cutting)

1. **`@better-auth/oauth-provider` API churn (highest).** New, fast-moving (`1.6.19`, `1.7.0-beta.8` exists). Helper signatures unverified — **pin against the installed `.d.ts` before coding the AS↔RS contract.** This gates the entire MCP-auth milestone.
2. **CVE5 editor parity is the long pole.** 195+107+16+18 `@json-editor` custom keywords → a hand-authored uiSchema + ~6 custom widgets, plus an eval→declarative-logic inventory. Drive from a field-by-field parity checklist; this dominates the editor schedule and is bigger than the AJV/validation work (which is done).
3. **`ae-cvss-calculator` v4.0 correctness unverified.** Run the FIRST official v4.0 test vectors as a regression gate before swapping out the vendored calculators; keep `test/cvss.test.js` snapshots as a guard.
4. **`ajv-formats` 2.x vs 3.x skew** between `@rjsf/validator-ajv8` and `@vulndesk/core`. Pin/dedupe and add a **cross-validator agreement test** over real CVE records (form-valid must equal API-valid).
5. **RPC type-instantiation cliff.** A large `@hono/zod-openapi` graph can break tsserver. Hard-require: single pinned Hono version (catalog), `strict:true` everywhere, feature sub-routers behind one `AppType` barrel, TS project references. If the SPA team diverges from the API team, fall back to a generated OpenAPI client.
6. **RLS pool-safety.** `SET LOCAL`/`set_config(...,true)` inside transactions; app role without `BYPASSRLS`; a CI test proving cross-tenant isolation returns zero rows. This is a security-product correctness gate, not a nicety.
7. **`drizzle-kit push` mis-generates GIN/HNSW/generated-column DDL** (issue #5792). Use `generate`+`migrate` for those and review SQL; never `push` to anything but local dev.
8. **pnpm strictness vs the legacy Express app.** Strict node_modules may surface phantom deps in old middleware. Migrate pnpm first, in isolation, with catalogs in non-strict mode initially.
9. **React 19 × RJSF v6** ("in progress") — validate the chosen `@rjsf/*` widgets under 19 before committing UX work to them.
10. **MCP spec is a moving target** (draft-13 + evolving draft; DCR deprecated-but-retained, Client ID Metadata Documents preferred). Track the revision string each release.
11. **TS 6→7 (tsgo)** is preview-only with ~74 edge-case checker differences; config choices are forward-compatible but do not adopt for CI typechecking yet.

---

## 5. Sequencing (parity + the Mongo→PG lift)

The driving constraints: reach **feature/UX parity** with the legacy tool, and execute the **Mongo→Postgres** lift, without destabilizing the legacy CommonJS Express app still serving traffic. Build the spine before the surface, and keep `@vulndesk/core` as the validator everywhere.

**Phase 0 — Monorepo foundation (mechanical, low-risk).** Migrate npm → **pnpm** (catalogs non-strict initially), change `@vulndesk/core` dep to `workspace:*`, verify the **legacy Express app still installs/runs under strict node_modules**. *Then* add Turborepo, the shared `@tsconfig/strictest` base, `typescript-eslint` on the TS packages, Vitest `projects`, and Changesets. Do these as separate PRs. (§2.5)

**Phase 1 — Data layer + tenancy spine.** Stand up Drizzle/postgres.js, the relational+JSONB schema (`organizations`/`teams`/`members`/`documents`/`comments`/`files`), `generate`/`migrate` workflow, PGlite test harness, RLS policies, the JSONB GIN + promoted-column indexes, and the generated `tsvector` FTS. **Write the cross-tenant isolation CI test now.** (§2.4) — *Build first because everything else writes through it.*

**Phase 2 — Auth/AS + RBAC.** BetterAuth on Hono with the Drizzle/pg adapter, `jwt()` + `oauthProvider()` + `organization()` (teams on), static owner/admin/member/viewer roles, CLI-generated tables folded into migrations. Pin the actual `.d.ts` signatures. (§3.2–3.4)

**Phase 3 — API surface.** `@hono/zod-openapi` routes over `@vulndesk/core` Zod models, OpenAPI 3.1 via `doc31`, Scalar docs, the `hc<AppType>` barrel. Wire the session/permission middleware (`hasPermission`). (§2.1)

**Phase 4 — Mongo→PG ETL.** Backup Mongo; run the one-way Zod-validated batch ETL into the Phase-1 schema, `legacy_mongo_id`-keyed, quarantining constraint violations; reconcile row counts + JSONB round-trips before cutover. (§2.4)

**Phase 5 — Editor SPA (parity, the long pole — can start in parallel after Phase 3's types exist).** Vite SPA (Router+Query, Tailwind v4, shadcn), then the hybrid RJSF editor: official CVE5 schema + uiSchema + the ~6 custom widgets (CWE/CAPEC combobox, CVSS via `ae-cvss-calculator`, array/reference editors, conditional `oneOf`), validated against `@vulndesk/core`. Drive from the parity checklist; add the cross-validator agreement test. (§2.2, §2.3)

**Phase 6 — MCP resource server + offline bundle.** Add RFC 9728 PRM + audience-bound JWT validation to `@vulndesk/mcp-server` against the Phase-2 AS (HTTP transport). Build the `vite-plugin-singlefile` offline target with everything inlined. (§3.3, §2.3)

**Deferred (design seams kept, not built):** pgvector semantic search (§2.4); `dynamicAccessControl` custom roles (§3.4); ID-JAG / enterprise-managed auth (§3.5); tsdown migration (post-1.0, §2.5); Turborepo remote caching (when CI hurts); a separate SSR advisory-viewer surface (TanStack Start only after it reaches 1.0 — never block the editor SPA on it).

---

*Flagged as unverifiable in current docs (carry into ADRs as explicit risks): exact `@better-auth/oauth-provider` helper signatures; `ae-cvss-calculator` conformance to FIRST v4.0 test vectors; RJSF v6 full React 19 parity. Everything else above is version-verified against npm as of 2026-06-19.*