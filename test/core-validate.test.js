import { describe, it, expect } from 'vitest'
import { validateRecord, formatErrors, cveSchema } from '@vulndesk/core'

// A minimal, well-formed PUBLISHED CVE Record Format 5.x record.
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

describe('@vulndesk/core validateRecord', () => {
  it('loads the official CVE Record Format schema', () => {
    expect(cveSchema.title).toMatch(/CVE/i)
  })

  it('accepts a well-formed CVE5 record', () => {
    const { valid, errors } = validateRecord(validRecord)
    expect(errors).toEqual([])
    expect(valid).toBe(true)
  })

  it('rejects a record missing required top-level fields', () => {
    const { valid, errors } = validateRecord({ dataType: 'CVE_RECORD' })
    expect(valid).toBe(false)
    const messages = formatErrors(errors)
    expect(messages.join('\n')).toMatch(/dataVersion/)
    expect(messages.join('\n')).toMatch(/containers/)
  })

  it('rejects a wrong field type (descriptions must be an array)', () => {
    const bad = JSON.parse(JSON.stringify(validRecord))
    bad.containers.cna.descriptions = 'not an array'
    const { valid, errors } = validateRecord(bad)
    expect(valid).toBe(false)
    expect(errors.length).toBeGreaterThan(0)
  })

  it('formatErrors returns human-readable strings', () => {
    const { errors } = validateRecord({})
    const messages = formatErrors(errors)
    expect(Array.isArray(messages)).toBe(true)
    expect(typeof messages[0]).toBe('string')
  })
})
