import { describe, it, expect, beforeAll } from 'vitest'
import { fileURLToPath } from 'node:url'
import { PGlite } from '@electric-sql/pglite'
import { drizzle } from 'drizzle-orm/pglite'
import { migrate } from 'drizzle-orm/pglite/migrator'
import { sql, eq } from 'drizzle-orm'
import * as schema from '../packages/db/src/schema.ts'
import { mapMongoDoc, insertMappedDoc } from '../packages/db/src/index.ts'

const migrationsFolder = fileURLToPath(new URL('../packages/db/drizzle', import.meta.url))

const legacyDoc = {
  _id: '507f1f77bcf86cd799439011',
  __v: 2,
  author: 'alice',
  doc_id: 'CVE-2024-0001',
  slug: 'abc',
  full_slug: 'abc-def',
  body: {
    dataType: 'CVE_RECORD',
    dataVersion: '5.1',
    cveMetadata: { cveId: 'CVE-2024-0001', state: 'PUBLISHED', assignerOrgId: 'b3476cb9-2e3d-41a6-98d0-0f47421a65b6' },
    containers: { cna: { descriptions: [{ lang: 'en', value: 'A description.' }] } },
  },
  comments: [{ author: 'bob', slug: 's1', hypertext: '<b>hi</b>', createdAt: new Date(), updatedAt: new Date() }],
  files: [{ name: 'poc.txt', size: 10, comment: 'c', user: 'bob', type: 'text', subtype: 'plain', updatedAt: new Date() }],
  createdAt: new Date('2026-01-01T00:00:00Z'),
  updatedAt: new Date('2026-02-01T00:00:00Z'),
}

let db

beforeAll(async () => {
  db = drizzle(new PGlite(), { schema })
  await migrate(db, { migrationsFolder })
}, 30000)

describe('@vulndesk/db — schema + migrations (PGlite)', () => {
  it('applies the committed migration (tables exist)', async () => {
    const res = await db.execute(
      sql`select table_name from information_schema.tables where table_schema='public' order by table_name`
    )
    const names = res.rows.map((r) => r.table_name)
    expect(names).toEqual(expect.arrayContaining(['users', 'documents', 'comments', 'files']))
  })

  it('round-trips a user', async () => {
    await db.insert(schema.users).values({
      name: 'Alice', username: 'alice', email: 'a@example.com', emoji: '👩', passwordHash: 'x', priv: 0,
    })
    const [u] = await db.select().from(schema.users).where(eq(schema.users.username, 'alice'))
    expect(u.priv).toBe(0)
    expect(u.id).toMatch(/-/) // uuid
  })
})

describe('@vulndesk/db — Mongo→PG mapping', () => {
  it('mapMongoDoc promotes id/cveId/state and normalizes comments/files', () => {
    const m = mapMongoDoc('cve5', legacyDoc)
    expect(m.document.docId).toBe('CVE-2024-0001')
    expect(m.document.cveId).toBe('CVE-2024-0001')
    expect(m.document.state).toBe('PUBLISHED')
    expect(m.document.legacyMongoId).toBe('507f1f77bcf86cd799439011')
    expect(m.document.version).toBe(2)
    expect(m.comments).toHaveLength(1)
    expect(m.files[0].uploadedBy).toBe('bob') // legacy file.user -> uploaded_by
    expect(m.document.body.cveMetadata.cveId).toBe('CVE-2024-0001')
  })
})

describe('@vulndesk/db — insert + idempotency (PGlite)', () => {
  it('inserts the document with JSONB body + relations, queryable via @> containment', async () => {
    await insertMappedDoc(db, mapMongoDoc('cve5', legacyDoc))

    const docs = await db.select().from(schema.documents).where(eq(schema.documents.section, 'cve5'))
    expect(docs).toHaveLength(1)
    expect(docs[0].body.cveMetadata.cveId).toBe('CVE-2024-0001') // JSONB round-trip
    expect(docs[0].cveId).toBe('CVE-2024-0001')

    const found = await db.execute(
      sql`select count(*)::int as n from documents where body @> '{"cveMetadata":{"state":"PUBLISHED"}}'`
    )
    expect(found.rows[0].n).toBe(1) // GIN/jsonb_path_ops containment works

    const cmts = await db.select().from(schema.comments).where(eq(schema.comments.documentId, docs[0].id))
    expect(cmts).toHaveLength(1)
    expect(cmts[0].hypertext).toBe('<b>hi</b>')
    const fls = await db.select().from(schema.files).where(eq(schema.files.documentId, docs[0].id))
    expect(fls[0].name).toBe('poc.txt')
  })

  it('is idempotent on legacy_mongo_id (re-run does not duplicate)', async () => {
    await insertMappedDoc(db, mapMongoDoc('cve5', legacyDoc))
    await insertMappedDoc(db, mapMongoDoc('cve5', legacyDoc))

    const docs = await db.select().from(schema.documents).where(eq(schema.documents.section, 'cve5'))
    expect(docs).toHaveLength(1) // still one row
    const cmts = await db.select().from(schema.comments).where(eq(schema.comments.documentId, docs[0].id))
    expect(cmts).toHaveLength(1) // comments replaced, not appended
  })
})
