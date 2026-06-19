<!-- Generated from the multi-agent tech-stack assessment run on 2026-06-19. -->
<!-- Findings reference real files/lines in this repo at the time of assessment. -->

# Vulndesk Modernization Roadmap

> **⚠️ Superseded in part.** The end-state is now a ground-up rewrite to a modern
> TypeScript stack (Hono · React/TanStack · Zod · Drizzle/Postgres · BetterAuth ·
> Tailwind) — see [`REWRITE.md`](./REWRITE.md). The Phase 3/4/5 "upgrade
> Express/Mongoose/Pug" items below are moot (those layers are being replaced).
> Phases 0–2 (safety net, hygiene, headless `@vulndesk/core`) still hold and feed
> the rewrite, and the findings here remain an accurate audit of the v0.6.0 code.

## Executive Summary

The realistic end-state is a **single repository with a framework-agnostic `@vulndesk/core` package** — schema, AJV validation, and CVE5 transforms as plain, typed, unit-tested functions — that the Express UI, the standalone browser bundle, and a future MCP server all import, so they can never disagree on what "valid CVE5" means. We get there **incrementally and test-first**: nothing risky moves until a behavioral safety net exists, because today there are zero tests, CI runs against a branch that does not exist (`master` vs. the real `main`), and `package-lock.json` is gitignored so no build is even reproducible. The guiding strategy is to **lock current behavior with golden-file tests before refactoring**, **preserve byte/shape-compatible CVE5 MITRE JSON output and the offline standalone bundle as inviolable contracts**, and sequence work so safety net → quick wins → core extraction → data layer → framework upgrades, never the reverse. Critically, **all CVE validation and business rules live only in the browser today** (serialized to the client via `Function.toString()` in `views/edit.pug:48`), which is the single largest blocker to every roadmap goal — extracting that into a headless core is the keystone that simultaneously fixes the "no server-side validation" security hole and gives the MCP server something real to call. We deliberately defer the Express 4→5 migration and ESM conversion to last, since they are repo-wide and only safe once tests, CI, lint, and the new bundler absorb the churn. MIT licensing, existing saved-document compatibility, and the air-gapped standalone artifact are guardrails, not negotiable trade-offs.

## Current Stack at a Glance

| Concern | Today | Notable reality |
|---|---|---|
| Runtime | Node (unpinned); `Dockerfile` pins EOL `node:12` | No `engines` field, no `.nvmrc`; README says 14+, local dev Node 26 |
| Web framework | Express `4.18.1` (4.22.2 resolved) | `csurf` (archived 2022) required in 7 files; `connect-flash`, `express-messages` unmaintained |
| Data layer | Mongoose `6.12.2`, standalone `mongodb` `3.7.3` driver | Single `body:Object`, `strict:false` schema (`models/doc.js`) reused for docs **and** history; callback-style queries removed in Mongoose 7 |
| Auth/session | passport-local `0.6.0` + express-session `1.17.3` | In-memory `MemoryStore`; **per-boot random secret** (`app.js:86`); hand-rolled `lib/pbkdf2.js` (uses deprecated `new Buffer`) |
| Validation | **Browser-only** via `@json-editor/json-editor` `2.15.2` | No server-side AJV anywhere; AJV declared but never invoked; server persists arbitrary JSON |
| Frontend | Vanilla JS globals (`public/js/editor.js`, 1489 lines), no module system | json-editor/ace loaded from cdnjs CDN; `eval(template)` in editor; `document.execCommand` rich-text editor |
| Schema core | Forked `default/cve5/cve5.schema.json` (159KB, draft-07) | Pristine spec intermixed with ~195 `options`/107 `format` editor keywords; runtime `$ref`s to `/users/list/json` |
| Build | GNU `Makefile` + `uglify-es@3.3.10` (dead since 2018) + `csso` | Produces offline `standalone/index.html`; enumerates every output by hand |
| Tests / CI | **Zero tests**; `npm test` = `nodemon app` | CodeQL workflow targets `master` (repo is `main`) → never runs on PRs |
| Supply chain | `package-lock.json` **gitignored**; no `devDependencies` block | 11 audit vulns (4 high); `light-server` is dead weight = 4 of 11 vulns |
| Process mgmt | `pm2` declared, but scripts call `forever` (not installed) | Plus a stray `scripts/vulnogram.service` systemd unit — three deploy stories |

## Guardrails — Must Not Break

1. **CVE5 output compatibility.** The exact MITRE CVE Record Format 5.1 JSON emitted by `reduceJSON` / `getMITREJSON` / `cveFixForVulndesk` is a hard contract. Lock it with golden-file snapshots of real published CVEs **before** touching the transforms.
2. **Standalone browser bundle.** The offline, single-file `standalone/index.html` (air-gapped PSIRT/CNA use on confidential vuln data) must keep building and keep working without network access. Any bundler swap must reproduce this artifact.
3. **MIT licensing.** Every dependency added or swapped (CSRF replacement, bundler, AJV, DOMPurify, fast-json-patch, terser/esbuild) must be MIT/BSD/ISC-compatible. No copyleft creep into a community fork.
4. **Existing saved-document compatibility.** Documents already persisted as `{author, body:Object, comments, files}` with `strict:false` must still load and edit. When server-side validation is introduced, it must default to **validate-on-write, warn-don't-reject for legacy reads**, so older imperfect records remain openable.

## Roadmap — Phased

### Phase 0 — Safety Net & Zero-Risk Quick Wins
**Goal:** Make the codebase reproducible, testable, and CI-guarded before changing any behavior. Bank the free security wins.

**Steps:**
- Un-ignore and commit `package-lock.json` (remove line 8 of `.gitignore`); switch Docker + CI to `npm ci`.
- Add `"engines": {"node": ">=20"}` to `package.json` + a matching `.nvmrc`, reconciling the three conflicting Node versions (Dockerfile 12 / README 14 / local 26).
- **Retarget CI from `master` to `main`** in `.github/workflows/codeql-analysis.yml` (lines 10, 13) — it currently never runs on PRs.
- Stand up a test harness (vitest) and replace `"test": "nodemon app"` with a real runner; move the dev server to `npm run dev`.
- Write **golden-file fixtures** round-tripping several real published CVEs through `util.js` `reduceJSON`/`getMITREJSON`/`cveFixForVulndesk`, plus unit tests for the `cvssjs` v2/v3.1/v4 calculators and the `simplehtml.js` sanitizer. This is the contract that protects Guardrails #1 and #2.
- Add a CI workflow on push/PR to `main`: `npm ci`, lint (stub), test, and `make min` (so the standalone build is verified every change).
- Delete confirmed-dead deps: `light-server` (zero references, accounts for **4 of 11** audit vulns), `node-fetch` (code uses core `https`). Verify `object-path`/`linkifyjs` are standalone-only before removing.

**Dependencies/sequencing:** Foundational. Everything else depends on the lockfile + tests + green CI existing first.
**Effort:** M · **Risk:** Low (no behavior change; dead-dep removal is verifiable).
**Advances MCP:** A committed lockfile + Node pin make the future MCP server reproducibly installable and CI-verifiable — currently impossible. Golden tests become the contract the MCP server must honor.

### Phase 1 — Toolchain Hygiene & Latent-Bug Fixes
**Goal:** Establish dev/prod boundaries, kill the abandoned minifier, fix confirmed broken happy-paths and security misconfig. All localized, all test-covered now.

**Steps:**
- Add a `devDependencies` block; move `nodemon`, `csso`, `csso-cli`, `uglify-es`, `pm2` out of runtime `dependencies`.
- Replace `uglify-es@3.3.10` in `Makefile` (line 6 `UJS`, lines 37–38) with **terser** (drop-in CLI, MIT, parses modern ES). Unblocks writing modern JS in the bundle. (Full bundler swap is Phase 3.)
- Add ESLint flat config + Prettier as devDeps with `npm run lint`/`format`; wire lint into the Phase 0 CI job.
- Broaden `.github/dependabot.yml` to add `docker` and `github-actions` ecosystems (so EOL `node:12` and pinned actions get flagged).
- **Fix the broken `next` references** confirmed by audit: `checkDir(req,res)` in `routes/attachments.js:15` calls `return next()` with `next` out of scope → every valid-doc attachment route throws `ReferenceError`; same bug in the `users.js` logout handler.
- Add a single `(err,req,res,next)` error middleware (none exists in `app.js`); wrap async route handlers; replace `if(err) throw err` in `config/passport.js:12,19` with `return done(err)` so DB errors don't crash the process.
- **Harden session/CORS** (`app.js`): move the per-boot random `secret` (`app.js:86`) to an env var, add `connect-mongo` store, set cookie `secure:true`+`sameSite:'lax'`, flip `resave`/`saveUninitialized` to `false`, add `helmet`, remove the global `Access-Control-Allow-Origin: *` (self-flagged `// XXX investigate`).
- Fix `busboy` v1 API misuse in `routes/attachments.js` (legacy `new Busboy()` constructor, 6-arg callbacks, private `_done`).
- Standardize process management on `pm2` (bump to 7.x, clears the js-yaml advisory) and align `package.json` scripts + `scripts/start.sh`; drop the `forever` references (not even a dependency).

**Dependencies/sequencing:** After Phase 0 (needs tests to verify the bug fixes and the terser output parity). Session store + secret stability are prerequisites for any multi-instance / headless deployment.
**Effort:** M · **Risk:** Low–Medium (session cookie changes need a staging check).
**Advances MCP:** A stable session secret + persistent store mean future headless callers aren't tied to a single in-memory process; helmet/CORS cleanup hardens the surface the API will expose.

### Phase 2 — Extract the Headless `@vulndesk/core` (Keystone)
**Goal:** Pull CVE5 schema, validators, and transforms out of the browser into a pure, DOM-free, dependency-light package that the UI **and** server **and** MCP server all import. Enforce the schema server-side for the first time.

**Steps:**
- Create `packages/core` (ESM/TS-ready). Export plain functions: `validateRecord(json) -> {valid, errors[]}`, `normalize`/`cveFixForVulndesk`, `cvssImport`, `toMITRE`, and `scoreCvss(vector)`.
- Move the business-rule `validators` array **verbatim** from `default/cve5/conf.js:230` into the core as real exported functions (today smuggled to the browser via `opts.validators.toString()` at `edit.pug:48`).
- Lift the pure transforms out of `default/cve5/script.js` (`cveFixForVulndesk`, `cvssImport`, `versionStatusTable5`, `getBestTitle`, `getProblemTypeString`, `getProductList`) and `public/js/util.js` (`reduceJSON`, `getMITREJSON`, `affectedTable`, `cvssjs`) — separating them from their DOM code.
- **Split the schema:** keep a pristine, upstream-trackable `cve5.structural.schema.json` (validated by AJV) separate from a JSONEditor **overlay** (the ~195 `options`/107 `format`/`grid_columns`/`infoText`/`template`/`CNA_private` keywords) merged only at editor-build time. This kills the index-based `oneOf[0]` schema surgery in `scripts/standalone.js:36-43` and the `"gird"` typos' blast radius, and lets you re-pull official CVE 5.1.x/5.2 by diff.
- **Turn AJV from dead config into the real validator:** AJV is already declared but never invoked (no `new Ajv()` anywhere server-side, confirmed). Compile the structural schema once at startup; pre-resolve the runtime `$ref`s (`/users/list/json`, `js/cwe-all.json`, `js/capec.json`) into bundled in-memory schemas so validation needs no HTTP runtime.
- **Call `validateRecord` in `routes/onedoc.js` before persisting** (create `:187-208`, update `:211-293`), which today save `req.body` opaquely. Honor Guardrail #4: validate-on-write, warn-don't-reject on legacy reads.
- Make `routes/onedoc.js`/`routes/doc.js` thin adapters over the core. Point the browser editor at the **same** core module so UI and headless paths cannot diverge.
- Add a typed, introspectable **document-type registry** (`listTypes()`/`getType(id)`) to replace the implicit `if(s.facet && s.facet.ID)` convention in `app.js:157-167`.
- Pin and version-stamp the vendored reference data (`default/cve5/static/cvss40.js` FIRST fork, `cwe-all.json`/`capec.json`) with provenance + a regeneration script extending `scripts/parse-cwe.js`.

**Dependencies/sequencing:** Requires Phase 0 golden tests (this is where regression risk is highest). Independent of the Express/Mongoose upgrades — do it **before** them so the upgrades have a clean core to lean on.
**Effort:** XL · **Risk:** Medium (touches the create/update write path and the validator semantics; golden tests + warn-don't-reject mitigate).
**Advances MCP:** This **is** the MCP enabler. The MCP tools (`validate_record`, `create_cve`, `set_affected`, `score_cvss`, `normalize`) wrap exactly these functions; the type registry lets MCP enumerate which record types exist and what each requires (foundation for Phase-3 author-assist skills).

### Phase 3 — Frontend Bundler & Module System
**Goal:** Replace the load-order/global-script frontend and the Makefile with a real import graph, while preserving the offline standalone bundle (Guardrail #2).

**Steps:**
- Introduce **Vite/esbuild** with an ESM entrypoint; use `vite-plugin-singlefile` (or `esbuild --bundle`) to keep emitting the offline `standalone/index.html`. Keep `scripts/standalone.js` as the Pug HTML generator invoked from the build.
- Move `@json-editor/json-editor`, `ace-builds`, `tagify`, `linkify` to **pinned npm deps** (today CDN-loaded, absent from `package.json`, with stale unused vendored `public/js/jsoneditor.min.js` (425KB) + `ace.js` (370KB)). Bundling them locally also restores true air-gapped capability and removes the cdnjs/SRI hand-maintenance. Delete the dead vendored copies.
- Modularize `public/js/editor.js` (33 globals) into `custom-editors/`, `theme.js`, `tabs.js`, `save.js`, and an init module that receives its DOM root + config as arguments.
- **Remove the `eval`/`toString` injection path:** import the Phase-2 core on the client instead of `opts.validators.toString()` (`edit.pug:45-51`); replace schema `template` strings + `eval(template)` (`editor.js:93-104`) with named functions from the core. Removes a CSP hazard and makes validators testable.
- Add a small **Playwright e2e smoke suite** (load a CVE, edit a field, validate, export) against both server mode and the standalone bundle, in CI.

**Dependencies/sequencing:** After Phase 2 (the client must import the extracted core, not its own globals). After Phase 1 (terser/devDeps already in place). Diff the new bundle output against the old for parity.
**Effort:** L · **Risk:** Medium (standalone parity is the watch item; Playwright guards it).
**Advances MCP:** Confirms the UI consumes the identical core the MCP server does, guaranteeing lockstep. A clean import graph also lets the core be published/consumed as a library by the MCP service.

### Phase 4 — Data Layer Modernization
**Goal:** Make the persistence layer promise-based, properly modeled, and injection-hardened — the prerequisite for Mongoose 7+ and for the MCP server's read/write paths.

**Steps:**
- Convert all **callback-style Mongoose queries** to async/await (`config/passport.js:11,36`, `routes/onedoc.js:36,191`, `init-vulnogram.js:13`, `routes/users.js`) and drop `keepAlive` (`app.js:31`) — these throw immediately on a Mongoose 7+ bump.
- Replace `routes/attachments.js:151` `.update()` (removed in Mongoose 7).
- Remove the **stale standalone `mongodb@3.7.3`** dep (Mongoose 6 bundles its own driver 4.x; the standalone dep is used only for `ObjectID` in `doc.js:3`).
- Replace the single overloaded `body:Object`/`strict:false` schema with per-section typed sub-schemas + a discriminated `CveRecord`; model **history** and **comments** as real relations instead of the hand-rolled `json-patch-extended` `bulkWrite` in `onedoc.js:128-166`.
- Swap `json-patch-extended@0.1.2` (pre-1.0, unmaintained, on the revision write path) for **`fast-json-patch`** (RFC 6902).
- Allow-list operators in `lib/querymw.js` to close the NoSQL-injection surface; make the full-collection `$**:text` index (`doc.js:21`) opt-in/tunable. Replace `querymen@2.1.4` (unfixable prototype-pollution advisory, on the search hot path) with an explicit validated query builder.
- Step Mongoose 6 → 7 → 8/9 incrementally, each step independently test-verified.

**Dependencies/sequencing:** After Phase 0 (callback→promise conversion is broad and needs tests). After Phase 2 (the core's `createDoc`/`listDocs` should already wrap persistence). Before Phase 5's framework upgrades touch the same files.
**Effort:** XL · **Risk:** High (persistence + the dynamic route generator `doc.js:119-127,230-477`).
**Advances MCP:** A promise-based, properly-modeled data layer with hardened query building is exactly what an MCP tool handler invokes for list/search/create/update — and what the prototype-pollution-prone `querymen` currently blocks.

### Phase 5 — Framework, CSRF, Runtime & TypeScript
**Goal:** Migrate the Express ecosystem as a coordinated set, replace deprecated CSRF, modernize the container, and lock the contract with TypeScript. Last because it is repo-wide and only safe atop everything prior.

**Steps:**
- **Replace archived `csurf`** (required in all 7 files: `routes/{doc,onedoc,users,comments,attachments}.js` + `default/cve5/conf.js` + `default/cvss4/conf.js`) with a maintained double-submit module (`csrf-csrf`), centralized in **one** place. This both clears the `cookie<0.7.0` advisory and **decouples CSRF from the write logic** — directly enabling the MCP server to call those write paths with token auth instead of browser cookies.
- Migrate Express 4→5 as a set with `express-validator` 6→7, `express-rate-limit` 7→8, `passport` 0.6→0.7, and replacements for unmaintained `connect-flash`/`express-messages`; update the route-pattern style for Express 5's path-to-regexp.
- Add a **token/API-key auth path** alongside passport-local sessions so headless (MCP) clients authenticate without the cookie/session dance.
- **Multi-stage Dockerfile** on `node:20-slim`: builder stage builds deps + standalone bundle, final stage copies runtime artifacts + `npm ci --omit=dev`; remove the hardcoded `--platform=linux/amd64`. Replace `new Buffer` in `lib/pbkdf2.js:22` with `Buffer.alloc`.
- Generate **TypeScript types** from the Phase-2 structural schema (`json-schema-to-typescript`); type the core API first (`allowJs`/`checkJs` interop), migrating inward. Optionally convert CommonJS `require` → ESM.
- Split `config/conf*.js`: env-only validated secrets vs. CDN/SRI/UI config; remove the hardcoded `admin:admin` fallback (`conf-default.js:9`) and the hardcoded `app.set('env','production')` (`app.js:64`).

**Dependencies/sequencing:** Last. CSRF replacement needs the centralized error handling (Phase 1); Express 5's async error propagation complements it. TS is most valuable once tests/CI/bundler exist to absorb churn.
**Effort:** XL · **Risk:** High (coordinated multi-dep migration).
**Advances MCP:** Decoupled CSRF + a token auth path are the final blockers to exposing write operations headlessly. TS types give MCP tools a checkable input/output contract; a clean LTS container hosts the MCP server alongside or instead of Express.

## Start Here

1. **PR #1 — "Make builds reproducible + fix dead CI"** (Phase 0): un-ignore and commit `package-lock.json`, add `engines.node>=20` + `.nvmrc`, switch installs to `npm ci`, and retarget `.github/workflows/codeql-analysis.yml` from `master` to `main`. Near-zero risk, unblocks everything.
2. **PR #2 — "Test harness + CVE5 golden-file snapshots"** (Phase 0): add vitest, replace `npm test`, and snapshot real-CVE round-trips through `util.js` + `cvssjs` + the `simplehtml` sanitizer — the contract protecting CVE5 output compatibility before any refactor.
3. **PR #3 — "Remove dead deps + add CI build/lint/test job"** (Phase 0/1): delete `light-server` (eliminates 4 of 11 audit vulns) and `node-fetch`, add a `devDependencies` block, and wire a GitHub Actions job on `main` running `npm ci` → lint → test → `make min`.
