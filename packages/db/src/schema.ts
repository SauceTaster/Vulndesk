import { pgTable, uuid, text, integer, jsonb, timestamp, index, uniqueIndex } from 'drizzle-orm/pg-core'

// Single-tenant schema for self-host (ADR-0003). Multi-tenant org/team/RBAC
// columns (org_id, RLS) are deferred to the SaaS phase — see ADR-0002 (Deferred).
// `legacy_mongo_id` keys every row to its source Mongo `_id` so the migrator is
// idempotent (re-runnable).

export const users = pgTable(
  'users',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    name: text('name').notNull(),
    username: text('username').notNull(),
    email: text('email').notNull(),
    emoji: text('emoji').notNull(),
    // The pbkdf2 hash (legacy `password`). Auth implementation is unchanged for
    // now; BetterAuth is the deferred SaaS-phase concern.
    passwordHash: text('password_hash').notNull(),
    priv: integer('priv').notNull().default(1), // 0=admin, 1=read-write, 2=read-only
    group: text('group'),
    legacyMongoId: text('legacy_mongo_id'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    uniqueIndex('users_username_key').on(t.username),
    uniqueIndex('users_legacy_mongo_id_key').on(t.legacyMongoId),
  ]
)

export const documents = pgTable(
  'documents',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    section: text('section').notNull(), // plugin section: cve5 | cve | nvd | ...
    docId: text('doc_id').notNull(), // the section's id-path value (lookup key)
    cveId: text('cve_id'), // promoted from body for fast equality (cve5)
    state: text('state'), // promoted (e.g. PUBLISHED/REJECTED)
    author: text('author'),
    // the CVE/advisory record. Always a JSON object: the API enforces this on
    // write (CveRecord = z.record) and the migrator coerces (asObject), so the
    // response contract (Document.body is an object) holds. `.$type` is a
    // type-only annotation — the column stays plain jsonb (no migration).
    body: jsonb('body').$type<Record<string, unknown>>().notNull(),
    slug: text('slug'),
    fullSlug: text('full_slug'),
    parentId: uuid('parent_id'),
    legacyMongoId: text('legacy_mongo_id'),
    version: integer('version').notNull().default(0),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    uniqueIndex('documents_section_doc_id_key').on(t.section, t.docId),
    uniqueIndex('documents_legacy_mongo_id_key').on(t.legacyMongoId),
    index('documents_cve_id_idx').on(t.cveId),
    index('documents_state_idx').on(t.state),
    // GIN containment index for `body @> '{...}'` queries.
    index('documents_body_gin').using('gin', t.body.op('jsonb_path_ops')),
  ]
)

export const comments = pgTable(
  'comments',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    documentId: uuid('document_id')
      .notNull()
      .references(() => documents.id, { onDelete: 'cascade' }),
    author: text('author').notNull(),
    slug: text('slug').notNull(),
    hypertext: text('hypertext').notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index('comments_document_id_idx').on(t.documentId)]
)

export const files = pgTable(
  'files',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    documentId: uuid('document_id')
      .notNull()
      .references(() => documents.id, { onDelete: 'cascade' }),
    name: text('name').notNull(),
    size: integer('size'),
    comment: text('comment'),
    uploadedBy: text('uploaded_by'), // legacy file.user
    type: text('type'),
    subtype: text('subtype'),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index('files_document_id_idx').on(t.documentId)]
)
