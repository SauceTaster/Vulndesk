import { describe, it, expect, beforeAll, beforeEach } from 'vitest'
import { fileURLToPath } from 'node:url'
import { PGlite } from '@electric-sql/pglite'
import { drizzle } from 'drizzle-orm/pglite'
import { migrate } from 'drizzle-orm/pglite/migrator'
import { sql } from 'drizzle-orm'
import * as schema from '../packages/db/src/schema.ts'
import { createApp } from '../packages/api/src/app.ts'

// End-to-end integration: the real Hono routes against real SQL (PGlite),
// exercising the @vulndesk/db repository through the API exactly as production
// will (which uses postgres.js instead). Behavior, not mocks.

const migrationsFolder = fileURLToPath(new URL('../packages/db/drizzle', import.meta.url))

const recordBody = (cveId, state = 'PUBLISHED') => ({
  dataType: 'CVE_RECORD',
  dataVersion: '5.1',
  cveMetadata: { cveId, state, assignerOrgId: 'b3476cb9-2e3d-41a6-98d0-0f47421a65b6' },
  containers: { cna: { descriptions: [{ lang: 'en', value: 'A sufficiently long description.' }] } },
})

let db
let app

const req = (path, init) => app.request(path, init)
const postJson = (path, body) =>
  req(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
const patchJson = (path, body) =>
  req(path, { method: 'PATCH', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })

beforeAll(async () => {
  db = drizzle(new PGlite(), { schema })
  await migrate(db, { migrationsFolder })
  app = createApp(db)
}, 30000)

beforeEach(async () => {
  await db.execute(sql`truncate table documents restart identity cascade`)
})

describe('POST /documents', () => {
  it('creates a document (201), promoting docId/cveId/state from the body', async () => {
    const res = await postJson('/documents', {
      section: 'cve5',
      author: 'alice',
      body: recordBody('CVE-2024-0001'),
    })
    expect(res.status).toBe(201)
    const doc = await res.json()
    expect(doc.id).toMatch(/-/)
    expect(doc.section).toBe('cve5')
    expect(doc.docId).toBe('CVE-2024-0001')
    expect(doc.cveId).toBe('CVE-2024-0001')
    expect(doc.state).toBe('PUBLISHED')
    expect(doc.author).toBe('alice')
    expect(doc.version).toBe(0)
    expect(doc.body.cveMetadata.cveId).toBe('CVE-2024-0001')
    expect(typeof doc.createdAt).toBe('string')
  })

  it('400s when no docId can be determined (no body id, no explicit docId)', async () => {
    const res = await postJson('/documents', { section: 'cve5', body: { title: 'draft' } })
    expect(res.status).toBe(400)
    expect((await res.json()).error).toMatch(/docId/)
  })

  it('honors an explicit docId for a body without an id path', async () => {
    const res = await postJson('/documents', { section: 'notes', docId: 'NOTE-1', body: { title: 'draft' } })
    expect(res.status).toBe(201)
    expect((await res.json()).docId).toBe('NOTE-1')
  })

  it('409s on a duplicate (section, docId)', async () => {
    await postJson('/documents', { section: 'cve5', body: recordBody('CVE-2024-0002') })
    const dup = await postJson('/documents', { section: 'cve5', body: recordBody('CVE-2024-0002') })
    expect(dup.status).toBe(409)
    expect((await dup.json()).error).toMatch(/already exists/i)
  })

  it('400s on a non-object body (zod request validation)', async () => {
    const res = await postJson('/documents', { section: 'cve5', body: 'not an object' })
    expect(res.status).toBe(400)
  })
})

describe('GET /documents/{id}', () => {
  it('returns the document (200) and 404s for a missing id', async () => {
    const created = await (await postJson('/documents', { section: 'cve5', body: recordBody('CVE-2024-0010') })).json()
    const got = await req(`/documents/${created.id}`)
    expect(got.status).toBe(200)
    expect((await got.json()).id).toBe(created.id)

    const missing = await req('/documents/00000000-0000-0000-0000-000000000000')
    expect(missing.status).toBe(404)
  })

  it('400s for a non-uuid id (param validation)', async () => {
    const res = await req('/documents/not-a-uuid')
    expect(res.status).toBe(400)
  })
})

describe('GET /documents', () => {
  beforeEach(async () => {
    await postJson('/documents', { section: 'cve5', body: recordBody('CVE-2024-0020', 'PUBLISHED') })
    await postJson('/documents', { section: 'cve5', body: recordBody('CVE-2024-0021', 'REJECTED') })
    await postJson('/documents', { section: 'nvd', body: recordBody('CVE-2024-0022', 'PUBLISHED') })
  })

  it('lists all with total + pagination metadata', async () => {
    const data = await (await req('/documents')).json()
    expect(data.total).toBe(3)
    expect(data.items).toHaveLength(3)
    expect(data.limit).toBe(50)
    expect(data.offset).toBe(0)
  })

  it('filters by section, state, cveId via query params', async () => {
    expect((await (await req('/documents?section=cve5')).json()).total).toBe(2)
    expect((await (await req('/documents?state=REJECTED')).json()).total).toBe(1)
    expect((await (await req('/documents?cveId=CVE-2024-0022')).json()).total).toBe(1)
  })

  it('paginates with limit + offset (coerced from strings)', async () => {
    const page1 = await (await req('/documents?limit=2&offset=0')).json()
    const page2 = await (await req('/documents?limit=2&offset=2')).json()
    expect(page1.total).toBe(3)
    expect(page1.items).toHaveLength(2)
    expect(page2.items).toHaveLength(1)
  })

  it('400s on an invalid limit (non-positive)', async () => {
    const res = await req('/documents?limit=0')
    expect(res.status).toBe(400)
  })
})

describe('PATCH /documents/{id}', () => {
  it('updates state, bumps version', async () => {
    const created = await (await postJson('/documents', { section: 'cve5', body: recordBody('CVE-2024-0030', 'PUBLISHED') })).json()
    const res = await patchJson(`/documents/${created.id}`, { state: 'REJECTED' })
    expect(res.status).toBe(200)
    const doc = await res.json()
    expect(doc.state).toBe('REJECTED')
    expect(doc.version).toBe(created.version + 1)
  })

  it('re-derives cveId from a replacement body', async () => {
    const created = await (await postJson('/documents', { section: 'cve5', body: recordBody('CVE-2024-0031') })).json()
    const res = await patchJson(`/documents/${created.id}`, { body: recordBody('CVE-2024-9999', 'REJECTED') })
    const doc = await res.json()
    expect(doc.cveId).toBe('CVE-2024-9999')
    expect(doc.state).toBe('REJECTED')
  })

  it('404s when patching a missing id', async () => {
    const res = await patchJson('/documents/00000000-0000-0000-0000-000000000000', { state: 'x' })
    expect(res.status).toBe(404)
  })
})

describe('DELETE /documents/{id}', () => {
  it('deletes (204), then 404s on re-delete and on GET', async () => {
    const created = await (await postJson('/documents', { section: 'cve5', body: recordBody('CVE-2024-0040') })).json()
    const del = await req(`/documents/${created.id}`, { method: 'DELETE' })
    expect(del.status).toBe(204)

    expect((await req(`/documents/${created.id}`)).status).toBe(404)
    expect((await req(`/documents/${created.id}`, { method: 'DELETE' })).status).toBe(404)
  })
})
