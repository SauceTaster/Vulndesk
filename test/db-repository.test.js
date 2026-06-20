import { describe, it, expect, beforeAll, beforeEach } from 'vitest'
import { fileURLToPath } from 'node:url'
import { PGlite } from '@electric-sql/pglite'
import { drizzle } from 'drizzle-orm/pglite'
import { migrate } from 'drizzle-orm/pglite/migrator'
import { sql } from 'drizzle-orm'
import * as schema from '../packages/db/src/schema.ts'
import {
  createDocument,
  getDocumentById,
  getDocument,
  listDocuments,
  updateDocument,
  deleteDocument,
  deriveDocumentFields,
} from '../packages/db/src/repository.ts'

const migrationsFolder = fileURLToPath(new URL('../packages/db/drizzle', import.meta.url))

const recordBody = (cveId, state = 'PUBLISHED') => ({
  dataType: 'CVE_RECORD',
  dataVersion: '5.1',
  cveMetadata: { cveId, state, assignerOrgId: 'b3476cb9-2e3d-41a6-98d0-0f47421a65b6' },
  containers: { cna: { descriptions: [{ lang: 'en', value: 'A description.' }] } },
})

// Build a NewDocument insert the way the API route will: derive promoted fields
// from the body, then attach section/author.
const insertFor = (section, body, extra = {}) => ({
  section,
  body,
  ...deriveDocumentFields(body),
  ...extra,
})

let db

beforeAll(async () => {
  db = drizzle(new PGlite(), { schema })
  await migrate(db, { migrationsFolder })
}, 30000)

beforeEach(async () => {
  // Each test starts from an empty documents table (cascades comments/files).
  await db.execute(sql`truncate table documents restart identity cascade`)
})

describe('deriveDocumentFields', () => {
  it('promotes cveId/state/docId from a cve5 body', () => {
    const f = deriveDocumentFields(recordBody('CVE-2024-1000', 'REJECTED'))
    expect(f).toEqual({ docId: 'CVE-2024-1000', cveId: 'CVE-2024-1000', state: 'REJECTED' })
  })

  it('falls back to an explicit docId when the body has no id path', () => {
    const f = deriveDocumentFields({ title: 'draft' }, { docId: 'DRAFT-1' })
    expect(f).toEqual({ docId: 'DRAFT-1', cveId: null, state: null })
  })

  it('returns nulls for an empty/unknown body with no fallback', () => {
    expect(deriveDocumentFields(undefined)).toEqual({ docId: null, cveId: null, state: null })
  })
})

describe('createDocument', () => {
  it('inserts and returns the row with generated id + defaults', async () => {
    const row = await createDocument(db, insertFor('cve5', recordBody('CVE-2024-0001'), { author: 'alice' }))
    expect(row.id).toMatch(/-/) // uuid
    expect(row.section).toBe('cve5')
    expect(row.docId).toBe('CVE-2024-0001')
    expect(row.cveId).toBe('CVE-2024-0001')
    expect(row.state).toBe('PUBLISHED')
    expect(row.author).toBe('alice')
    expect(row.version).toBe(0)
    expect(row.body.cveMetadata.cveId).toBe('CVE-2024-0001')
    expect(row.createdAt).toBeInstanceOf(Date)
  })

  it('rejects a duplicate (section, docId) via the unique index', async () => {
    await createDocument(db, insertFor('cve5', recordBody('CVE-2024-0002')))
    await expect(
      createDocument(db, insertFor('cve5', recordBody('CVE-2024-0002')))
    ).rejects.toThrow()
  })

  it('allows the same docId in a different section', async () => {
    await createDocument(db, insertFor('cve5', recordBody('CVE-2024-0003')))
    const other = await createDocument(db, insertFor('nvd', recordBody('CVE-2024-0003')))
    expect(other.section).toBe('nvd')
  })
})

describe('getDocumentById / getDocument', () => {
  it('round-trips by id and by natural key', async () => {
    const created = await createDocument(db, insertFor('cve5', recordBody('CVE-2024-0004')))
    expect((await getDocumentById(db, created.id)).id).toBe(created.id)
    expect((await getDocument(db, 'cve5', 'CVE-2024-0004')).id).toBe(created.id)
  })

  it('returns null for a missing id and a missing natural key', async () => {
    expect(await getDocumentById(db, '00000000-0000-0000-0000-000000000000')).toBeNull()
    expect(await getDocument(db, 'cve5', 'CVE-9999-9999')).toBeNull()
  })
})

describe('listDocuments', () => {
  beforeEach(async () => {
    await createDocument(db, insertFor('cve5', recordBody('CVE-2024-0010', 'PUBLISHED')))
    await createDocument(db, insertFor('cve5', recordBody('CVE-2024-0011', 'REJECTED')))
    await createDocument(db, insertFor('nvd', recordBody('CVE-2024-0012', 'PUBLISHED')))
  })

  it('returns all rows with a total and pagination metadata', async () => {
    const { items, total, limit, offset } = await listDocuments(db)
    expect(total).toBe(3)
    expect(items).toHaveLength(3)
    expect(limit).toBe(50)
    expect(offset).toBe(0)
  })

  it('filters by section', async () => {
    const { items, total } = await listDocuments(db, { section: 'cve5' })
    expect(total).toBe(2)
    expect(items.every((d) => d.section === 'cve5')).toBe(true)
  })

  it('filters by state and by cveId', async () => {
    expect((await listDocuments(db, { state: 'REJECTED' })).total).toBe(1)
    expect((await listDocuments(db, { cveId: 'CVE-2024-0012' })).total).toBe(1)
  })

  it('paginates: limit + offset slice the result, total is unfiltered-by-page', async () => {
    const page1 = await listDocuments(db, { limit: 2, offset: 0 })
    const page2 = await listDocuments(db, { limit: 2, offset: 2 })
    expect(page1.total).toBe(3)
    expect(page1.items).toHaveLength(2)
    expect(page2.items).toHaveLength(1)
    // disjoint pages
    const ids = new Set([...page1.items, ...page2.items].map((d) => d.id))
    expect(ids.size).toBe(3)
  })

  it('clamps an over-large limit to 200 and a negative offset to 0', async () => {
    const r = await listDocuments(db, { limit: 9999, offset: -5 })
    expect(r.limit).toBe(200)
    expect(r.offset).toBe(0)
  })
})

describe('updateDocument', () => {
  it('patches fields, bumps version, advances updatedAt', async () => {
    const created = await createDocument(db, insertFor('cve5', recordBody('CVE-2024-0020', 'PUBLISHED')))
    const updated = await updateDocument(db, created.id, { state: 'REJECTED' })
    expect(updated.state).toBe('REJECTED')
    expect(updated.version).toBe(created.version + 1)
    expect(updated.updatedAt.getTime()).toBeGreaterThanOrEqual(created.updatedAt.getTime())
  })

  it('returns null when patching a missing id', async () => {
    expect(await updateDocument(db, '00000000-0000-0000-0000-000000000000', { state: 'x' })).toBeNull()
  })
})

describe('deleteDocument', () => {
  it('removes the row and reports true, then false on re-delete', async () => {
    const created = await createDocument(db, insertFor('cve5', recordBody('CVE-2024-0030')))
    expect(await deleteDocument(db, created.id)).toBe(true)
    expect(await getDocumentById(db, created.id)).toBeNull()
    expect(await deleteDocument(db, created.id)).toBe(false)
  })
})
