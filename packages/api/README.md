# @vulndesk/api

The Vulndesk HTTP API — **Hono + `@hono/zod-openapi`**, where one Zod definition
drives runtime validation, the **OpenAPI 3.1** spec, and the typed RPC client
(see [ADR-0001](../../docs/adr/0001-modern-typescript-stack.md)).

> 🚧 Building in public — v1 is stateless, wrapping [`@vulndesk/core`](../core).
> Authenticated, org-scoped document routes (BetterAuth + Drizzle/Postgres RBAC)
> arrive with the data + auth layer.

## Endpoints

- `POST /validate` — validate a CVE Record Format 5.x record → `{ valid, errorCount, errors[] }`.
- `GET /cve5/schema` — the canonical CVE5 JSON Schema.
- `GET /openapi.json` — the OpenAPI 3.1 spec (also committed as `openapi.json`).
- `GET /docs` — interactive [Scalar](https://scalar.com) API reference.

## Run / develop

```bash
npm install                              # builds the package
node packages/api/dist/index.js          # serves on :3000 (PORT to override)
npm run -w @vulndesk/api gen:openapi      # regenerate the committed openapi.json
npm test                                  # vitest (test/api.test.js)
```

## Typed client (in-repo SPA)

The React SPA consumes the API with zero codegen via Hono RPC:

```ts
import { hc } from 'hono/client'
import type { AppType } from '@vulndesk/api'
const client = hc<AppType>('/')
```
