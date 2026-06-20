import { eq } from 'drizzle-orm'
import type { PgDatabase, PgQueryResultHKT } from 'drizzle-orm/pg-core'
import type { ExtractTablesWithRelations } from 'drizzle-orm'
import { DocumentEnvelopeSchema } from '@vulndesk/core'
import { documents, comments as commentsTable, files as filesTable } from './schema.js'
import type * as schema from './schema.js'

/** Any PG drizzle database bound to the Vulndesk schema (postgres.js or PGlite). */
export type Db = PgDatabase<
  PgQueryResultHKT,
  typeof schema,
  ExtractTablesWithRelations<typeof schema>
>

export interface MappedDoc {
  document: typeof documents.$inferInsert
  comments: Omit<typeof commentsTable.$inferInsert, 'documentId'>[]
  files: Omit<typeof filesTable.$inferInsert, 'documentId'>[]
}

export interface MapOptions {
  /** dotted path into `body` for the lookup id (default 'cveMetadata.cveId' for cve5). */
  idPath?: string
  statePath?: string
}

function deepGet(obj: unknown, dotted: string): unknown {
  return dotted.split('.').reduce<unknown>((acc, key) => {
    if (acc && typeof acc === 'object') return (acc as Record<string, unknown>)[key]
    return undefined
  }, obj)
}

function asString(v: unknown): string | null {
  return typeof v === 'string' ? v : null
}

/**
 * Map one legacy Mongo document ({ _id, author, body, doc_id, slug, comments[],
 * files[] }, strict:false) to the relational + JSONB shape. Pure + testable.
 */
export function mapMongoDoc(section: string, raw: unknown, opts: MapOptions = {}): MappedDoc {
  const env = DocumentEnvelopeSchema.parse(raw)
  const body = (env.body ?? {}) as Record<string, unknown>
  const r = raw as Record<string, unknown>
  const legacyMongoId = r._id != null ? String(r._id) : null

  const idPath = opts.idPath ?? 'cveMetadata.cveId'
  const docId = asString(deepGet(body, idPath)) ?? env.doc_id ?? legacyMongoId ?? ''
  const cveId = asString(deepGet(body, 'cveMetadata.cveId'))
  const state = asString(deepGet(body, opts.statePath ?? 'cveMetadata.state'))

  return {
    document: {
      section,
      docId,
      cveId,
      state,
      author: env.author ?? null,
      body: env.body ?? {},
      slug: env.slug ?? null,
      fullSlug: env.full_slug ?? null,
      parentId: null, // parent linkage (history docs) is a follow-up
      legacyMongoId,
      version: typeof r.__v === 'number' ? r.__v : 0,
      ...(env.createdAt ? { createdAt: env.createdAt } : {}),
      ...(env.updatedAt ? { updatedAt: env.updatedAt } : {}),
    },
    comments: env.comments.map((c) => ({
      author: c.author,
      slug: c.slug,
      hypertext: c.hypertext,
      ...(c.createdAt ? { createdAt: c.createdAt } : {}),
      ...(c.updatedAt ? { updatedAt: c.updatedAt } : {}),
    })),
    files: env.files.map((f) => ({
      name: f.name,
      size: f.size ?? null,
      comment: f.comment ?? null,
      uploadedBy: (f as Record<string, unknown>).user as string | undefined ?? null,
      type: f.type ?? null,
      subtype: f.subtype ?? null,
      ...(f.updatedAt ? { updatedAt: f.updatedAt } : {}),
    })),
  }
}

/**
 * Idempotently upsert a mapped document and replace its comments/files.
 * Keyed on `legacy_mongo_id`, so re-running the migration is safe.
 */
export async function insertMappedDoc(db: Db, mapped: MappedDoc): Promise<string> {
  return db.transaction(async (tx) => {
    const [doc] = await tx
      .insert(documents)
      .values(mapped.document)
      .onConflictDoUpdate({
        target: documents.legacyMongoId,
        set: { ...mapped.document, updatedAt: new Date() },
      })
      .returning({ id: documents.id })

    const documentId = doc.id
    await tx.delete(commentsTable).where(eq(commentsTable.documentId, documentId))
    await tx.delete(filesTable).where(eq(filesTable.documentId, documentId))

    if (mapped.comments.length) {
      await tx.insert(commentsTable).values(mapped.comments.map((c) => ({ ...c, documentId })))
    }
    if (mapped.files.length) {
      await tx.insert(filesTable).values(mapped.files.map((f) => ({ ...f, documentId })))
    }
    return documentId
  })
}

/**
 * Migrate an iterable of legacy Mongo docs for one section. The Mongo cursor is
 * supplied by the caller (which owns the mongoose connection), so @vulndesk/db
 * does not depend on mongoose. Returns the number of documents migrated.
 */
export async function migrateDocs(
  db: Db,
  section: string,
  rawDocs: Iterable<unknown> | AsyncIterable<unknown>,
  opts: MapOptions = {}
): Promise<{ count: number }> {
  let count = 0
  for await (const raw of rawDocs as AsyncIterable<unknown>) {
    await insertMappedDoc(db, mapMongoDoc(section, raw, opts))
    count++
  }
  return { count }
}
