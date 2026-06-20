import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { z } from 'zod'
import { validateRecord, formatErrors, cveSchema } from '@vulndesk/core'

/**
 * Build the Vulndesk MCP server. Returned without a transport so it can be
 * driven over stdio (the bin) or an in-memory transport (tests).
 *
 * v1 exposes the stateless @vulndesk/core capabilities (CVE5 validation +
 * schema). Authenticated document tools (create/list/comment) arrive once the
 * data + authz layer lands, and will be gated by the same RBAC model.
 */
export function createServer(): McpServer {
  const server = new McpServer({ name: 'vulndesk', version: '0.1.0' })

  server.registerTool(
    'validate_cve_record',
    {
      title: 'Validate CVE Record',
      description:
        'Validate a CVE Record Format 5.x record against the official CVE JSON Schema. ' +
        'Returns whether it is valid plus human-readable errors. Accepts the record as a ' +
        'JSON object or a JSON string.',
      inputSchema: {
        record: z
          .union([z.string(), z.record(z.string(), z.unknown())])
          .describe('A full CVE Record Format 5.x record — a JSON object, or a JSON string.'),
      },
    },
    async ({ record }) => {
      let parsed: unknown
      try {
        parsed = typeof record === 'string' ? JSON.parse(record) : record
      } catch {
        return {
          isError: true,
          content: [{ type: 'text', text: 'Invalid JSON: could not parse the provided record string.' }],
        }
      }
      const result = validateRecord(parsed)
      const payload = {
        valid: result.valid,
        errorCount: result.errors.length,
        errors: formatErrors(result.errors),
      }
      return { content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }] }
    }
  )

  server.registerResource(
    'cve5-schema',
    'cve5://schema',
    {
      title: 'CVE Record Format 5.x JSON Schema',
      description: 'The canonical CVE Record Format 5.x JSON Schema used to validate records.',
      mimeType: 'application/json',
    },
    async (uri) => ({
      contents: [{ uri: uri.href, mimeType: 'application/json', text: JSON.stringify(cveSchema) }],
    })
  )

  return server
}
