// Generate the committed OpenAPI 3.1 spec from the built app. Run via
// `npm run -w @vulndesk/api gen:openapi` after building. The /openapi.json
// route is the live source of truth; this snapshot makes the spec browsable
// in the repo and diffable in PRs.
import { writeFileSync } from 'node:fs'
import { createDb } from '@vulndesk/db'
import { createApp } from '../dist/app.js'

// postgres.js connects lazily, and emitting the spec issues no query, so this
// never opens a connection — no live database needed to snapshot the OpenAPI.
const app = createApp(createDb('postgresql://localhost:5432/vulndesk_openapi_gen'))
const res = await app.request('/openapi.json')
const doc = await res.json()
writeFileSync(new URL('../openapi.json', import.meta.url), JSON.stringify(doc, null, 2) + '\n')
console.log(`wrote packages/api/openapi.json (openapi ${doc.openapi}, paths: ${Object.keys(doc.paths).join(', ')})`)
