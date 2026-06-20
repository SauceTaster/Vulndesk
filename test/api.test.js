import { describe, it, expect, beforeAll } from 'vitest'
import { fileURLToPath } from 'node:url'
import { PGlite } from '@electric-sql/pglite'
import { drizzle } from 'drizzle-orm/pglite'
import { migrate } from 'drizzle-orm/pglite/migrator'
import * as schema from '../packages/db/src/schema.ts'
import { createApp } from '../packages/api/src/app.ts'

const migrationsFolder = fileURLToPath(new URL('../packages/db/drizzle', import.meta.url))

// The app is db-injected; the stateless routes below don't touch it, but
// createApp requires a Db, so we build it over an in-memory PGlite.
let app

beforeAll(async () => {
  const db = drizzle(new PGlite(), { schema })
  await migrate(db, { migrationsFolder })
  app = createApp(db)
}, 30000)

const validRecord = {
  dataType: 'CVE_RECORD',
  dataVersion: '5.1',
  cveMetadata: {
    cveId: 'CVE-2024-0001',
    assignerOrgId: 'b3476cb9-2e3d-41a6-98d0-0f47421a65b6',
    state: 'PUBLISHED',
  },
  containers: {
    cna: {
      providerMetadata: { orgId: 'b3476cb9-2e3d-41a6-98d0-0f47421a65b6' },
      descriptions: [{ lang: 'en', value: 'A sufficiently long test vulnerability description.' }],
      affected: [
        { vendor: 'Acme', product: 'Widget', versions: [{ version: '1.0', status: 'affected' }] },
      ],
      references: [{ url: 'https://example.com/advisory' }],
    },
  },
}

const postJson = (path, body) =>
  app.request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })

describe('@vulndesk/api', () => {
  it('POST /validate accepts a well-formed record', async () => {
    const res = await postJson('/validate', validRecord)
    expect(res.status).toBe(200)
    const data = await res.json()
    expect(data.valid).toBe(true)
    expect(data.errorCount).toBe(0)
  })

  it('POST /validate reports errors for a malformed record', async () => {
    const res = await postJson('/validate', { dataType: 'CVE_RECORD' })
    expect(res.status).toBe(200)
    const data = await res.json()
    expect(data.valid).toBe(false)
    expect(data.errorCount).toBeGreaterThan(0)
    expect(data.errors.join('\n')).toMatch(/containers|dataVersion/)
  })

  it('POST /validate rejects a non-object body with 400 (zod-openapi request validation)', async () => {
    const res = await postJson('/validate', 'not an object')
    expect(res.status).toBe(400)
  })

  it('GET /openapi.json serves an OpenAPI 3.1 spec describing the routes', async () => {
    const res = await app.request('/openapi.json')
    expect(res.status).toBe(200)
    const doc = await res.json()
    expect(doc.openapi).toMatch(/^3\.1/)
    expect(doc.paths['/validate']?.post).toBeTruthy()
    expect(doc.paths['/cve5/schema']?.get).toBeTruthy()
    expect(doc.paths['/documents']?.post).toBeTruthy()
    expect(doc.paths['/documents/{id}']?.get).toBeTruthy()
    expect(doc.components?.schemas?.ValidationResult).toBeTruthy()
    expect(doc.components?.schemas?.Document).toBeTruthy()
  })

  it('GET /cve5/schema returns the canonical CVE5 schema', async () => {
    const res = await app.request('/cve5/schema')
    expect(res.status).toBe(200)
    const doc = await res.json()
    expect(doc.title).toMatch(/CVE/i)
  })

  it('GET /docs serves the Scalar API reference (HTML)', async () => {
    const res = await app.request('/docs')
    expect(res.status).toBe(200)
    expect(res.headers.get('content-type')).toMatch(/html/)
  })

  it('GET / redirects to /docs', async () => {
    const res = await app.request('/')
    expect([301, 302, 307, 308]).toContain(res.status)
    expect(res.headers.get('location')).toBe('/docs')
  })
})
