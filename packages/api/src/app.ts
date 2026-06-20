import { OpenAPIHono, createRoute, z } from '@hono/zod-openapi'
import { Scalar } from '@scalar/hono-api-reference'
import { validateRecord, formatErrors, cveSchema } from '@vulndesk/core'

// One Zod definition drives runtime validation, the OpenAPI 3.1 doc, and the RPC
// client types. v1 exposes the stateless @vulndesk/core capabilities; authed,
// org-scoped document routes arrive with the data + auth layer (see ADR-0001).

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

const validateRoute = createRoute({
  method: 'post',
  path: '/validate',
  tags: ['CVE'],
  summary: 'Validate a CVE Record Format 5.x record',
  description: 'Validates the record against the official CVE5 JSON Schema via @vulndesk/core.',
  request: {
    body: { content: { 'application/json': { schema: CveRecord } }, required: true },
  },
  responses: {
    200: {
      content: { 'application/json': { schema: ValidationResult } },
      description: 'Validation result',
    },
  },
})

const schemaRoute = createRoute({
  method: 'get',
  path: '/cve5/schema',
  tags: ['CVE'],
  summary: 'The canonical CVE Record Format 5.x JSON Schema',
  responses: {
    200: {
      content: { 'application/json': { schema: z.record(z.string(), z.unknown()) } },
      description: 'CVE5 JSON Schema',
    },
  },
})

export const app = new OpenAPIHono()

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

// Emit OpenAPI 3.1 explicitly (app.doc() would emit 3.0 and lose Zod 4 fidelity).
app.doc31('/openapi.json', {
  openapi: '3.1.0',
  info: {
    title: 'Vulndesk API',
    version: '0.1.0',
    description:
      'CVE / security-advisory authoring API. Building in public — v1 exposes @vulndesk/core validation.',
  },
})

app.get('/docs', Scalar({ url: '/openapi.json', pageTitle: 'Vulndesk API' }))
app.get('/', (c) => c.redirect('/docs'))

export type AppType = typeof routes
export default app
