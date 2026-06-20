// Generate the committed OpenAPI 3.1 spec from the built app. Run via
// `npm run -w @vulndesk/api gen:openapi` after building. The /openapi.json
// route is the live source of truth; this snapshot makes the spec browsable
// in the repo and diffable in PRs.
import { writeFileSync } from 'node:fs'
import app from '../dist/app.js'

const res = await app.request('/openapi.json')
const doc = await res.json()
writeFileSync(new URL('../openapi.json', import.meta.url), JSON.stringify(doc, null, 2) + '\n')
console.log(`wrote packages/api/openapi.json (openapi ${doc.openapi}, paths: ${Object.keys(doc.paths).join(', ')})`)
