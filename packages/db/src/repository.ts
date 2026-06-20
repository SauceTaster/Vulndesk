// Document repository — the typed data-access layer the API (and later the MCP
// server) call instead of writing Drizzle queries inline. Single-tenant for now
// (ADR-0003); org scoping is a deferred SaaS concern. Every function takes the
// shared `Db` (postgres.js in prod, PGlite in tests), so the same code path is
// exercised under test.

import { and, desc, eq, sql, type SQL } from 'drizzle-orm'
import { documents } from './schema.js'
import type { Db } from './migrate.js'

export type DocumentRow = typeof documents.$inferSelect
export type NewDocument = typeof documents.$inferInsert

export interface ListDocumentsFilter {
  section?: string
  state?: string
  cveId?: string
  /** 1–200, default 50. */
  limit?: number
  offset?: number
}

export interface ListDocumentsResult {
  items: DocumentRow[]
  total: number
  limit: number
  offset: number
}

/** Fields a route may patch; `body`/`state`/etc. — never `id`/`createdAt`. */
export type DocumentPatch = Partial<
  Pick<NewDocument, 'body' | 'cveId' | 'state' | 'author' | 'slug' | 'fullSlug' | 'docId'>
>

const MAX_LIMIT = 200
const DEFAULT_LIMIT = 50

function deepGet(obj: unknown, dotted: string): unknown {
  return dotted.split('.').reduce<unknown>((acc, key) => {
    if (acc && typeof acc === 'object') return (acc as Record<string, unknown>)[key]
    return undefined
  }, obj)
}

function asString(v: unknown): string | null {
  return typeof v === 'string' ? v : null
}

export interface DeriveFieldsOptions {
  /** dotted path into `body` for the lookup id (default 'cveMetadata.cveId'). */
  idPath?: string
  /** dotted path into `body` for the workflow state (default 'cveMetadata.state'). */
  statePath?: string
}

/**
 * Derive the promoted/indexed columns (docId, cveId, state) from a record body,
 * mirroring the migrator's promotion (mapMongoDoc) so API-created and migrated
 * rows are shaped identically. `docId` falls back to an explicitly supplied id.
 */
export function deriveDocumentFields(
  body: unknown,
  opts: DeriveFieldsOptions & { docId?: string } = {}
): { docId: string | null; cveId: string | null; state: string | null } {
  const cveId = asString(deepGet(body, 'cveMetadata.cveId'))
  const state = asString(deepGet(body, opts.statePath ?? 'cveMetadata.state'))
  const derivedId = asString(deepGet(body, opts.idPath ?? 'cveMetadata.cveId'))
  return { docId: derivedId ?? opts.docId ?? null, cveId, state }
}

/** Insert a new document and return the stored row. */
export async function createDocument(db: Db, input: NewDocument): Promise<DocumentRow> {
  const [row] = await db.insert(documents).values(input).returning()
  return row
}

/** Fetch by primary key (uuid). Returns null when not found. */
export async function getDocumentById(db: Db, id: string): Promise<DocumentRow | null> {
  const [row] = await db.select().from(documents).where(eq(documents.id, id)).limit(1)
  return row ?? null
}

/** Fetch by the natural key (section + the section's id-path value). */
export async function getDocument(
  db: Db,
  section: string,
  docId: string
): Promise<DocumentRow | null> {
  const [row] = await db
    .select()
    .from(documents)
    .where(and(eq(documents.section, section), eq(documents.docId, docId)))
    .limit(1)
  return row ?? null
}

/** Filtered, paginated, newest-first listing plus a total count for the filter. */
export async function listDocuments(
  db: Db,
  filter: ListDocumentsFilter = {}
): Promise<ListDocumentsResult> {
  const conds: SQL[] = []
  if (filter.section) conds.push(eq(documents.section, filter.section))
  if (filter.state) conds.push(eq(documents.state, filter.state))
  if (filter.cveId) conds.push(eq(documents.cveId, filter.cveId))
  const where = conds.length ? and(...conds) : undefined

  const limit = Math.min(Math.max(1, filter.limit ?? DEFAULT_LIMIT), MAX_LIMIT)
  const offset = Math.max(0, filter.offset ?? 0)

  const items = await db
    .select()
    .from(documents)
    .where(where)
    .orderBy(desc(documents.updatedAt))
    .limit(limit)
    .offset(offset)

  const [{ total }] = await db
    .select({ total: sql<number>`count(*)::int` })
    .from(documents)
    .where(where)

  return { items, total, limit, offset }
}

/**
 * Patch a document, bumping `version` and `updatedAt`. Returns the updated row,
 * or null when the id does not exist.
 */
export async function updateDocument(
  db: Db,
  id: string,
  patch: DocumentPatch
): Promise<DocumentRow | null> {
  const [row] = await db
    .update(documents)
    .set({ ...patch, version: sql`${documents.version} + 1`, updatedAt: new Date() })
    .where(eq(documents.id, id))
    .returning()
  return row ?? null
}

/** Delete by id. Returns true when a row was removed (cascades comments/files). */
export async function deleteDocument(db: Db, id: string): Promise<boolean> {
  const deleted = await db
    .delete(documents)
    .where(eq(documents.id, id))
    .returning({ id: documents.id })
  return deleted.length > 0
}
