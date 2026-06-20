import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import { createServer } from '../packages/mcp-server/src/server.ts'

const validRecord = {
  dataType: 'CVE_RECORD',
  dataVersion: '5.1',
  cveMetadata: {
    cveId: 'CVE-2024-0001',
    assignerOrgId: 'b3476cb9-2e3d-41a6-98d0-0f47421a65b6',
    state: 'PUBLISHED',
  },
  containers: {
    cna: {
      providerMetadata: { orgId: 'b3476cb9-2e3d-41a6-98d0-0f47421a65b6' },
      descriptions: [{ lang: 'en', value: 'A sufficiently long test vulnerability description.' }],
      affected: [
        { vendor: 'Acme', product: 'Widget', versions: [{ version: '1.0', status: 'affected' }] },
      ],
      references: [{ url: 'https://example.com/advisory' }],
    },
  },
}

describe('@vulndesk/mcp-server', () => {
  let client

  beforeAll(async () => {
    const server = createServer()
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
    client = new Client({ name: 'test-client', version: '0.0.0' })
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)])
  })

  afterAll(async () => {
    await client?.close()
  })

  it('advertises the validate_cve_record tool', async () => {
    const { tools } = await client.listTools()
    expect(tools.map((t) => t.name)).toContain('validate_cve_record')
  })

  it('validates a well-formed CVE record', async () => {
    const res = await client.callTool({
      name: 'validate_cve_record',
      arguments: { record: validRecord },
    })
    const data = JSON.parse(res.content[0].text)
    expect(data.valid).toBe(true)
    expect(data.errorCount).toBe(0)
  })

  it('reports errors for a malformed record', async () => {
    const res = await client.callTool({
      name: 'validate_cve_record',
      arguments: { record: { dataType: 'CVE_RECORD' } },
    })
    const data = JSON.parse(res.content[0].text)
    expect(data.valid).toBe(false)
    expect(data.errorCount).toBeGreaterThan(0)
    expect(data.errors.join('\n')).toMatch(/containers|dataVersion/)
  })

  it('accepts the record as a JSON string', async () => {
    const res = await client.callTool({
      name: 'validate_cve_record',
      arguments: { record: JSON.stringify(validRecord) },
    })
    expect(JSON.parse(res.content[0].text).valid).toBe(true)
  })

  it('flags invalid JSON strings as an error', async () => {
    const res = await client.callTool({
      name: 'validate_cve_record',
      arguments: { record: '{not valid json' },
    })
    expect(res.isError).toBe(true)
    expect(res.content[0].text).toMatch(/Invalid JSON/i)
  })

  it('exposes the CVE5 schema as a resource', async () => {
    const { resources } = await client.listResources()
    expect(resources.map((r) => r.uri)).toContain('cve5://schema')
    const read = await client.readResource({ uri: 'cve5://schema' })
    const schema = JSON.parse(read.contents[0].text)
    expect(schema.title).toMatch(/CVE/i)
  })
})
