import { OpenAPIHono, createRoute, z } from '@hono/zod-openapi'
import { Scalar } from '@scalar/hono-api-reference'
import { validateRecord, formatErrors, cveSchema } from '@vulndesk/core'
import {
  type Db,
  type DocumentRow,
  createDocument,
  getDocumentById,
  listDocuments,
  updateDocument,
  deleteDocument,
  deriveDocumentFields,
} from '@vulndesk/db'

// One Zod definition drives runtime validation, the OpenAPI 3.1 doc, and the RPC
// client types. v1 exposes @vulndesk/core validation plus single-tenant document
// CRUD over @vulndesk/db; auth + org scoping arrive later (see ADR-0002, Deferred).

const CveRecord = z
  .record(z.string(), z.unknown())
  .openapi('CveRecord', { description: 'A CVE Record Format 5.x record (JSON object).' })

const ValidationResult = z
  .object({
    valid: z.boolean(),
    errorCount: z.number().int(),
    errors: z.array(z.string()),
  })
  .openapi('ValidationResult')

const ErrorResponse = z
  .object({ error: z.string(), errors: z.array(z.string()).optional() })
  .openapi('Error')

const DocumentResponse = z
  .object({
    id: z.string().uuid(),
    section: z.string(),
    docId: z.string(),
    cveId: z.string().nullable(),
    state: z.string().nullable(),
    author: z.string().nullable(),
    body: CveRecord,
    slug: z.string().nullable(),
    fullSlug: z.string().nullable(),
    version: z.number().int(),
    createdAt: z.string(),
    updatedAt: z.string(),
  })
  .openapi('Document')

const DocumentList = z
  .object({
    items: z.array(DocumentResponse),
    total: z.number().int(),
    limit: z.number().int(),
    offset: z.number().int(),
  })
  .openapi('DocumentList')

const CreateDocumentInput = z
  .object({
    section: z.string().min(1).openapi({ example: 'cve5' }),
    body: CveRecord,
    docId: z.string().optional().openapi({
      description: 'Lookup id; derived from the body (e.g. cveMetadata.cveId) when omitted.',
    }),
    author: z.string().optional(),
    slug: z.string().optional(),
    fullSlug: z.string().optional(),
  })
  .openapi('CreateDocumentInput')

const UpdateDocumentInput = z
  .object({
    body: CveRecord.optional(),
    state: z.string().optional(),
    author: z.string().optional(),
    slug: z.string().optional(),
    fullSlug: z.string().optional(),
  })
  .openapi('UpdateDocumentInput')

const IdParam = z.object({
  id: z
    .string()
    .uuid()
    .openapi({ param: { name: 'id', in: 'path' }, example: '00000000-0000-0000-0000-000000000000' }),
})

const ListQuery = z.object({
  section: z.string().optional(),
  state: z.string().optional(),
  cveId: z.string().optional(),
  limit: z.coerce.number().int().positive().optional(),
  offset: z.coerce.number().int().nonnegative().optional(),
})

/** Serialize a stored row to the JSON response shape (Date -> ISO string). */
function toResponse(row: DocumentRow) {
  return {
    id: row.id,
    section: row.section,
    docId: row.docId,
    cveId: row.cveId,
    state: row.state,
    author: row.author,
    body: row.body as Record<string, unknown>,
    slug: row.slug,
    fullSlug: row.fullSlug,
    version: row.version,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  }
}

const validateRoute = createRoute({
  method: 'post',
  path: '/validate',
  tags: ['CVE'],
  summary: 'Validate a CVE Record Format 5.x record',
  description: 'Validates the record against the official CVE5 JSON Schema via @vulndesk/core.',
  request: { body: { content: { 'application/json': { schema: CveRecord } }, required: true } },
  responses: {
    200: { content: { 'application/json': { schema: ValidationResult } }, description: 'Validation result' },
  },
})

const schemaRoute = createRoute({
  method: 'get',
  path: '/cve5/schema',
  tags: ['CVE'],
  summary: 'The canonical CVE Record Format 5.x JSON Schema',
  responses: {
    200: { content: { 'application/json': { schema: z.record(z.string(), z.unknown()) } }, description: 'CVE5 JSON Schema' },
  },
})

const createDocumentRoute = createRoute({
  method: 'post',
  path: '/documents',
  tags: ['Documents'],
  summary: 'Create a document',
  description:
    'Stores a CVE/advisory record (drafts allowed — use /validate to check conformance). ' +
    'docId/cveId/state are promoted from the body for indexing.',
  request: { body: { content: { 'application/json': { schema: CreateDocumentInput } }, required: true } },
  responses: {
    201: { content: { 'application/json': { schema: DocumentResponse } }, description: 'Created' },
    400: { content: { 'application/json': { schema: ErrorResponse } }, description: 'Invalid input' },
    409: { content: { 'application/json': { schema: ErrorResponse } }, description: 'Duplicate (section, docId)' },
  },
})

const listDocumentsRoute = createRoute({
  method: 'get',
  path: '/documents',
  tags: ['Documents'],
  summary: 'List documents',
  request: { query: ListQuery },
  responses: {
    200: { content: { 'application/json': { schema: DocumentList } }, description: 'A page of documents' },
  },
})

const getDocumentRoute = createRoute({
  method: 'get',
  path: '/documents/{id}',
  tags: ['Documents'],
  summary: 'Get a document by id',
  request: { params: IdParam },
  responses: {
    200: { content: { 'application/json': { schema: DocumentResponse } }, description: 'The document' },
    404: { content: { 'application/json': { schema: ErrorResponse } }, description: 'Not found' },
  },
})

const updateDocumentRoute = createRoute({
  method: 'patch',
  path: '/documents/{id}',
  tags: ['Documents'],
  summary: 'Update a document',
  description: 'Patches the supplied fields and bumps version. A new body re-derives cveId/state.',
  request: {
    params: IdParam,
    body: { content: { 'application/json': { schema: UpdateDocumentInput } }, required: true },
  },
  responses: {
    200: { content: { 'application/json': { schema: DocumentResponse } }, description: 'Updated' },
    404: { content: { 'application/json': { schema: ErrorResponse } }, description: 'Not found' },
  },
})

const deleteDocumentRoute = createRoute({
  method: 'delete',
  path: '/documents/{id}',
  tags: ['Documents'],
  summary: 'Delete a document',
  request: { params: IdParam },
  responses: {
    204: { description: 'Deleted' },
    404: { content: { 'application/json': { schema: ErrorResponse } }, description: 'Not found' },
  },
})

/** Postgres unique-violation, portably across postgres.js and PGlite. */
function isUniqueViolation(err: unknown): boolean {
  const e = err as { code?: string; cause?: { code?: string }; message?: string }
  return (
    e?.code === '23505' ||
    e?.cause?.code === '23505' ||
    /duplicate key value|unique constraint/i.test(String(e?.message ?? ''))
  )
}

/**
 * Build the API bound to a database. The db is captured by the handlers, so the
 * server (index.ts) injects a postgres.js connection while tests inject PGlite —
 * the same routes, exercised against real SQL.
 */
export function createApp(db: Db) {
  const app = new OpenAPIHono({
    // Surface Zod request-validation failures in our ErrorResponse shape.
    defaultHook: (result, c) => {
      if (!result.success) {
        return c.json(
          {
            error: 'Invalid request',
            errors: result.error.issues.map((i) => `${i.path.join('.')} ${i.message}`.trim()),
          },
          400
        )
      }
    },
  })

  // Chained so `typeof routes` carries the full type graph for the Hono RPC client.
  const routes = app
    .openapi(validateRoute, (c) => {
      const record = c.req.valid('json')
      const result = validateRecord(record)
      return c.json(
        { valid: result.valid, errorCount: result.errors.length, errors: formatErrors(result.errors) },
        200
      )
    })
    .openapi(schemaRoute, (c) => c.json(cveSchema as Record<string, unknown>, 200))
    .openapi(createDocumentRoute, async (c) => {
      const input = c.req.valid('json')
      const fields = deriveDocumentFields(input.body, { docId: input.docId })
      if (!fields.docId) {
        return c.json(
          { error: 'Could not determine docId: provide `docId` or a body with cveMetadata.cveId.' },
          400
        )
      }
      try {
        const row = await createDocument(db, {
          section: input.section,
          docId: fields.docId,
          cveId: fields.cveId,
          state: fields.state,
          author: input.author ?? null,
          body: input.body,
          slug: input.slug ?? null,
          fullSlug: input.fullSlug ?? null,
        })
        return c.json(toResponse(row), 201)
      } catch (err) {
        if (isUniqueViolation(err)) {
          return c.json(
            { error: `A document already exists in section '${input.section}' with docId '${fields.docId}'.` },
            409
          )
        }
        throw err
      }
    })
    .openapi(listDocumentsRoute, async (c) => {
      const q = c.req.valid('query')
      const result = await listDocuments(db, q)
      return c.json(
        {
          items: result.items.map(toResponse),
          total: result.total,
          limit: result.limit,
          offset: result.offset,
        },
        200
      )
    })
    .openapi(getDocumentRoute, async (c) => {
      const { id } = c.req.valid('param')
      const row = await getDocumentById(db, id)
      if (!row) return c.json({ error: 'Document not found' }, 404)
      return c.json(toResponse(row), 200)
    })
    .openapi(updateDocumentRoute, async (c) => {
      const { id } = c.req.valid('param')
      const input = c.req.valid('json')
      const patch: Parameters<typeof updateDocument>[2] = {
        ...(input.body !== undefined ? { body: input.body } : {}),
        ...(input.state !== undefined ? { state: input.state } : {}),
        ...(input.author !== undefined ? { author: input.author } : {}),
        ...(input.slug !== undefined ? { slug: input.slug } : {}),
        ...(input.fullSlug !== undefined ? { fullSlug: input.fullSlug } : {}),
      }
      // A replacement body re-derives the promoted index columns (an explicit
      // `state` in the request still wins).
      if (input.body !== undefined) {
        const d = deriveDocumentFields(input.body)
        patch.cveId = d.cveId
        if (input.state === undefined && d.state !== null) patch.state = d.state
      }
      const row = await updateDocument(db, id, patch)
      if (!row) return c.json({ error: 'Document not found' }, 404)
      return c.json(toResponse(row), 200)
    })
    .openapi(deleteDocumentRoute, async (c) => {
      const { id } = c.req.valid('param')
      const removed = await deleteDocument(db, id)
      if (!removed) return c.json({ error: 'Document not found' }, 404)
      return c.body(null, 204)
    })

  // Emit OpenAPI 3.1 explicitly (app.doc() would emit 3.0 and lose Zod 4 fidelity).
  app.doc31('/openapi.json', {
    openapi: '3.1.0',
    info: {
      title: 'Vulndesk API',
      version: '0.1.0',
      description:
        'CVE / security-advisory authoring API. Building in public — v1: @vulndesk/core validation + document CRUD.',
    },
  })

  app.get('/docs', Scalar({ url: '/openapi.json', pageTitle: 'Vulndesk API' }))
  app.get('/', (c) => c.redirect('/docs'))

  return routes
}

export type AppType = ReturnType<typeof createApp>
