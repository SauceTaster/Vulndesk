// Zod domain models for Vulndesk's OWN entities (the app's data), distinct from
// the CVE record itself (validated against the canonical JSON Schema by
// validateRecord). These type the data the Mongo→Postgres migration moves and
// the API surface the Hono server / MCP server expose.
//
// Shapes mirror the current persisted document (models/doc.js, strict:false) so
// they double as the migration source-of-truth. `looseObject` preserves unknown
// keys (Mongo stored extras) rather than dropping them.

import { z } from 'zod'

export const CommentSchema = z.looseObject({
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
  author: z.string(),
  slug: z.string(),
  hypertext: z.string(),
})
export type Comment = z.infer<typeof CommentSchema>

export const FileMetaSchema = z.looseObject({
  name: z.string(),
  updatedAt: z.coerce.date().optional(),
  size: z.number().optional(),
  comment: z.string().optional(),
  user: z.string().optional(),
  type: z.string().optional(),
  subtype: z.string().optional(),
})
export type FileMeta = z.infer<typeof FileMetaSchema>

/**
 * The persisted document envelope. `body` is the CVE/advisory record itself
 * (validated separately via validateRecord); Drizzle will store it as JSONB.
 */
export const DocumentEnvelopeSchema = z.looseObject({
  author: z.string().optional(),
  body: z.unknown(),
  doc_id: z.string().optional(),
  parent_id: z.unknown().optional(),
  slug: z.string().optional(),
  full_slug: z.string().optional(),
  comments: z.array(CommentSchema).default([]),
  files: z.array(FileMetaSchema).default([]),
  createdAt: z.coerce.date().optional(),
  updatedAt: z.coerce.date().optional(),
})
export type DocumentEnvelope = z.infer<typeof DocumentEnvelopeSchema>
