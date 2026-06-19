<!-- Security & maintainability audit: find -> adversarial-verify -> synthesize workflow, 2026-06-19. 49 findings, 39 confirmed real. -->

# Vulndesk (OpenVG) — Security & Maintainability Review

## 1. Executive Summary

The current app is a single-trust-tier, authenticated-only tool whose stated threat model ("only create accounts for trusted users — no RBAC/ACL", `README.md:38`) papers over several real cross-user defects: a **high-severity stored XSS in comments** (server stores raw HTML, renders it unescaped to every viewer) and a **broken read-only privilege tier** (priv==2 accounts get full write/delete) are exploitable by any authenticated colleague *today*. These are amplified by **CSP being globally disabled** (`app.js:70-71`), which removes the last line of defense against the XSS sinks. Most dependency findings are either obviated by the planned TS/Hono/Drizzle/BetterAuth rewrite or are exploitation-inert hygiene issues; the genuine fix-now list is short, concrete, and cheap. One non-security item — a half-applied env-var rename — silently breaks the documented Docker deploy and should be fixed immediately.

## 2. Fix Now

Ordered by severity. These matter for the running app and are **not** obviated by the rewrite.

### S1 — Stored XSS in comments (HIGH)
- **What:** `req.body.text` is stored verbatim as `hypertext` and rendered unescaped via `+asis(c.hypertext)` (`!{x}`) to every viewer — both on server render (`edit.pug` `+comments` on page load) and client render (`comment.js:56` `innerHTML`). The client-side SimpleHtml sanitizer is bypassed by a direct authenticated POST. Cross-user, persistent, session-theft capable.
- **Where:** store at `routes/comments.js:69` (addComment) and `:95` (updateComment); sink `views/subcontent.pug:55-56` → `views/util.pug:179-180`; route `routes/comments.js:113`.
- **Fix:** Sanitize server-side before persisting in both handlers, e.g. `text = require('isomorphic-dompurify').sanitize(req.body.text)` with an allowlist matching SimpleHtml's allowed tags. Never rely on the client sanitizer as the only gate.
- **Package:** `isomorphic-dompurify` (or `sanitize-html`).
- **Risk/Effort:** High risk / Low effort (2 call sites).

### S2 — Read-only users (priv==2) can create/update/delete everything (HIGH)
- **What:** `models/user.js` documents priv tiers (0=admin, 1=read-write, 2=read-only), but **no** write handler checks `req.user.priv`. A read-only account can POST/overwrite/delete documents, post comments, upload/delete attachments, and run bulk update. Priv is consulted only in user-account management.
- **Where:** mounts `app.js:185`; unguarded writes `routes/onedoc.js:172/210/295`, `routes/comments.js:113`, `routes/attachments.js:25/151`, `routes/doc.js:529`.
- **Fix:** Add `function ensureCanWrite(req,res,next){ if(req.user && req.user.priv <= 1) return next(); return res.status(403).json({type:'err',msg:'Read-only account'}); }` and apply to every mutating route. **Carry forward** — the rewrite's BetterAuth/Drizzle swap does not auto-create this policy; port it explicitly.
- **Package:** none (in-app middleware).
- **Risk/Effort:** High risk (broken access control) / Low-Medium effort. Note the priv==2 option is commented out in `views/users/edit.pug:45`, so exposure depends on whether read-only accounts are provisioned.

### S3 — Stored XSS in `supportingMedia` (server editor + standalone bundle) (MEDIUM)
- **What:** `d.supportingMedia[0].value` is interpolated unescaped (`p !{...}`) and rendered via `innerHTML = pugRender(...)` in the Advisory preview. The genuinely reachable route is the **Source tab** (raw JSON → preview, no sanitization) and the offline `standalone/index.html` (no CSP meta). The readonly published view is already protected by a per-route CSP (`onedoc.js:50`), so the public-viewer path is defended; the exposed surface is the authenticated editor and the offline bundle.
- **Where:** `default/cve5/render.pug:7,412-413`; sinks `default/cve5/script.js:173/179/185`, `standalone/index.html` (~1511, 413/419/425); import `standalone/js/editor.js` loadFile.
- **Fix:** Sanitize `supportingMedia` HTML with DOMPurify before rendering (applies to both server and standalone builds), then regenerate the bundle via `scripts/standalone.js`. Add a restrictive CSP `<meta>` to the standalone template (`default/cve5/edit.pug`).
- **Package:** `dompurify`.
- **Risk/Effort:** Medium risk / Low-Medium effort (shared sanitizer + bundle regen).

### S4 — No CSP on editor/app routes (MEDIUM)
- **What:** `helmet({contentSecurityPolicy:false})` emits no CSP on the editor/list pages — exactly where the S1/S3 sinks execute. The only CSP is the readonly per-route header.
- **Where:** `app.js:70-71`; contrast `routes/onedoc.js:50`.
- **Fix:** Enable a real CSP for editor/app routes (`script-src 'self'; object-src 'none'; base-uri 'none'`). The editor embeds inline scripts (`edit.pug:31-56` — compiled pugRender, iconMap, csrfToken), so this needs **nonces/hashes**, not naive `'self'`. This is defense-in-depth that neutralizes injected inline handlers from S1/S3; track with the Phase-3 bundler work noted in `app.js:67-69`.
- **Package:** `helmet` (already present).
- **Risk/Effort:** Medium risk / Medium effort (nonce plumbing). The validator/`eval`-as-string patterns (see §3) are the deeper CSP blockers, deferred to the rewrite — so a nonce-based interim policy is the realistic near-term step.

### S5 — Replace the custom SimpleHtml sanitizer + enforce it server-side (MEDIUM)
- **What:** The only sanitizer is the hand-rolled, browser-only `SimpleHtml.sanitize`. It is bypassable (direct POST), allows `data:` img URLs, and is unaudited. The load-bearing problem is the **absence of server-side enforcement** (already the root cause of S1/S3), not the sanitizer's internal robustness.
- **Where:** `public/js/simplehtml.js:42-54,57,796-841`; same in `standalone/js/simplehtml.js`.
- **Fix:** Standardize on DOMPurify (same tag/attr allowlist) for the editor **and** enforce DOMPurify on every HTML-bearing field server-side (comments `hypertext`, `supportingMedia.value`) so the client sanitizer is never the sole control. Drop `data:` from allowed img src unless required. This is largely the same work as S1+S3 — do them together.
- **Package:** `dompurify`.
- **Risk/Effort:** Medium risk / Medium effort. (Folds into S1/S3.)

### S6 — Path traversal in attachment download (MEDIUM — deployment-dependent)
- **What:** `express.static(path.join(opts.conf.files))` serves the whole attachments root and `checkDir` validates only `req.params.id`, never the filename. URL-encoded traversal (`..%2f..%2f`) lets any authenticated user read **any other document's attachments** (and any file under `conf.files`). `send` caps at its own root, so no `/etc/passwd` — but the per-document `:id` boundary is fully defeated. Only mounts when an operator sets `files:` in a section conf (`routes/doc.js:618`); **off in the shipped default config**.
- **Where:** `routes/attachments.js:142-148`.
- **Fix:** Don't hand the raw URL to `express.static`. Validate `req.params.filename` with the same `sanitizeFile()` check applied to `id` (reject if `sanitizeFile(name) !== name`, plus decoded `../`, `..\`, NUL), then `res.sendFile(basename, { root: path.join(conf.files, id, 'file'), dotfiles: 'deny' })` — or root `express.static` at the per-document directory.
- **Package:** `sanitize-filename` (already declared).
- **Risk/Effort:** Medium risk where enabled / Low effort.

### S7 — Half-applied env-var rename breaks the documented Docker deploy (HIGH availability, not security)
- **What:** Live config reads `process.env.VULNOGRAM_HOST`/`VULNOGRAM_PORT`, but `example.env`, `docker-compose.yml`, `README.md`, and `init-vulndesk.js` all set `VULNDESK_*`. The correct `VULNDESK_*` names landed only in the **dead** `config/conf-default.js`. Result: documented `VULNDESK_PORT`/`VULNDESK_HOST` are silently ignored; the container binds `127.0.0.1:3555` (loopback inside the container), so the published port reaches nothing — the documented happy path fails.
- **Where:** `config/conf.js:28-29` vs `docker-compose.yml:29`, `example.env:11-12`, `README.md:161-167`.
- **Fix:** Rename the reads at `config/conf.js:28-29` to `VULNDESK_HOST`/`VULNDESK_PORT`. Add a startup assertion/test that the documented env vars drive `serverHost`/`serverPort`. Grep for any remaining `VULNOGRAM_`.
- **Risk/Effort:** High (deploy-breaking) / Trivial effort.

### S8 — Cheap quick-wins (LOW, fix while in the area)
- **`downloadHtml` string-concatenates live `innerHTML` + unescaped title** into a downloadable HTML file (`public/js/editor.js`, same in `standalone/js/editor.js`). Secondary propagation of S1/S3; HTML-escape `title` and build from sanitized data. Largely fixed once S1/S3 land.
- **DELETE attachment never unlinks the file** (`routes/attachments.js:151-160`): only `$pull` metadata; bytes remain on disk and stay downloadable via S6's route. Data-retention/confidentiality defect — `fs.unlink` the validated path after the `$pull`.
- **`/files/:id` null-deref → 500** (`routes/attachments.js:172-173`): guard `if (!doc) return res.status(404)...` before `res.json(doc.files)`, mirroring the upload handler.
- **`lib/pbkdf2.js:47` non-constant-time compare** and **`:22` `new Buffer()`**: low real-world risk (both operands are PBKDF2 outputs; modern Node zero-fills `new Buffer(n)` and every byte is overwritten). Cheap to fix now (`crypto.timingSafeEqual` on Buffers; `Buffer.alloc`) but obviated by BetterAuth — optional.

## 3. Defer to the Rewrite

Real issues the TS/Hono/Drizzle/BetterAuth/Tailwind rewrite eliminates anyway — don't gold-plate:

- **NoSQL operator injection in `/comment`** (`routes/comments.js:51-111`): real but marginal given no RBAC/ownership baseline; Zod-typed query params + Drizzle/Postgres remove it. (Interim defense if touched: `mongoose.set('sanitizeFilter', true)`.)
- **Field-value enumeration via `distinct(req.query.field)`** (`routes/doc.js:237-245`): discloses nothing a user can't already read per-document; typed query layer removes it.
- **Validators / `errorFilter` shipped to browser via `Function.toString()`** (`views/edit.pug:42-51`): the main CSP blocker; becomes Zod refinements running in both runtimes. (errorFilter/script branches are already dead today.)
- **`eval(template)` for JSONEditor watch-templates** (`public/js/editor.js:93-104`): first-party-only today; becomes computed selectors. Removing this + the validator stringification is what makes a real CSP possible.
- **Login brute-force**: single global 200/min limiter, no per-account lockout, no `trust proxy` (`app.js:57-63`); BetterAuth ships login rate limiting.
- **Logout is a CSRF-unprotected GET** (`routes/users.js:258-267`): nuisance-only (SameSite=Lax blocks the `<img>` PoC); rewrite session handling fixes it.
- **850-line global `public/js/util.js`** (clone + CVSS + render + clipboard): split during the frontend rebuild; no live XSS sink.
- **`textUtil.jsonView`** latent unescaped concat (`public/js/util.js:53-72`): dead code (zero call sites), removed in rewrite.
- **Unanchored `usernameRegex`/idpattern route regexes**: not exploitable (Express anchors full path; params are strings); Zod regex schemas in rewrite.

## 4. Maintained-Library Swaps

| Unmaintained / phantom dep | Where | Replacement | Fix-now or rewrite |
|---|---|---|---|
| `csurf ^1.11.0` (archived; pulls `cookie@0.4.0`, GHSA-pxg6-pf52-xh8x) | `package.json:35`; all routers | `csrf-csrf` | Rewrite (BetterAuth CSRF); vuln path is dead code today — low urgency |
| `lodash` **undeclared phantom** dep (resolves via hoist) | `routes/onedoc.js:6`, `routes/doc.js:12` | declare `lodash@^4.17.21` | **Fix now** (installed 4.18.1 is current/patched, but declare it) |
| `json-patch-extended ^0.1.2` (abandoned 2017) | `package.json:45`; `routes/onedoc.js:5,146` | `fast-json-patch` (drop-in `compare`) | **Fix now** (low risk) or rewrite |
| `mongodb ^3.7.3` standalone (EOL) alongside mongoose's 4.17.2 | `package.json:47`; `routes/doc.js:3` (`ObjectID`, **unused/dead import**) | `mongoose.Types.ObjectId`, then drop dep | **Fix now** (trivial) / removed in rewrite |
| `pm2 ^5.3.1` (ReDoS GHSA-x5gf-qvw8-r2rm + js-yaml DoS; runtime via `start.sh`) | `package.json:86`; `scripts/start.sh:8` | `pm2@^7.0.1` or systemd/node supervisor | **Fix now** (not web-reachable; low) / dropped in rewrite |
| `connect-flash 0.1.1` + `express-messages 1.0.1` (stale; unescaped HTML via `!=messages()`) | `package.json:34,39`; `app.js:11,121,125` | inline session messages / client toasts | Rewrite — but note `routes/onedoc.js:40` flashes unescaped user-controlled `req.params.id` into `!=messages()` (no per-route CSP) → reflected XSS; escape that flash now |
| `passport ^0.6.0` / `passport-local 1.0.0` | `package.json:50`; `config/passport.js` | `passport@^0.7.0` interim | Rewrite (BetterAuth); CVE-2022-25896 already fixed in 0.6.0 — no urgency |
| `express-validator ^6.14.2` (6.x maintenance) | `package.json:42` | `express-validator@^7` or Zod | Rewrite (Zod) |
| `lib/pbkdf2.js` hand-rolled hash | `config/passport.js:3` | `argon2`/`bcrypt` interim | Rewrite (BetterAuth) |

Note on §4: one item escalates out of "defer" — the `connect-flash`/`express-messages` row carries a **live reflected XSS** at `routes/onedoc.js:40` (`req.flash('error', 'ID not found: ' + req.params.id)` rendered via unescaped `!=messages()` at `views/layout.pug:64`/`views/splash.pug:29`, on the no-CSP editor render path; the `GET /:id` handler has no idpattern constraint and ignores `validationResult`). **Escape that flash value now** even though the libraries themselves wait for the rewrite.

## 5. Watch List / Won't-Fix

- **No RBAC/ACL across documents** — intentionally accepted (`README.md:38`); every account is fully trusted. This is the baseline that downgrades the NoSQL-injection and `distinct`/attachment-enumeration findings to "marginal." S2 (read-only tier) is the exception worth fixing because the model *advertises* a boundary it doesn't enforce.
- **`reviewToken` unauthenticated-access feature** — documented in `config/conf.js:23-25` but **unimplemented** (no `/review` route exists). Latent trap, not a vuln. Either delete the misleading config comment now, or implement with `crypto.timingSafeEqual` + read-only handler if the rewrite ports it.
- **Dead config sprawl** — delete orphan `config/conf-default.js` (only `test/config.test.js` + README reference it); it actively misleads (holds the "correct" env names that caused S7). Keep `conf-standalone.js` (used by the build). Factor shared CDN/SRI block to one module.
- **Dead/cosmetic code** — `typeof opts.script === 'array'` impossible-branch (`views/edit.pug:42`); commented-out handlers + stray `console.log(['Bulkd',...])` (`routes/doc.js:554`); empty `else` blocks (`routes/users.js:287/309/330`) that are unreachable dead code (not request-hangs); `app.set('env','production')` (`app.js:77`) redundant. All zero-impact maintainability; clean opportunistically per-file before porting.
- **`package` reserved-word bindings** (`routes/doc.js:7`, `config/*conf.js`, `default/*/conf.js`) and module-scoped `var queryMW` (`routes/doc.js:16`) — work today (CommonJS sloppy mode) but break under ESM/TS; rename to `pkg`/`const` during migration.