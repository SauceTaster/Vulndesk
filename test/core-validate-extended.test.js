import { describe, it, expect } from 'vitest'
import { validateRecord, formatErrors, cveSchema } from '@vulndesk/core'

// ---------------------------------------------------------------------------
// CHARACTERIZATION (golden-master) tests for @vulndesk/core's CVE5 validator.
//
// These lock down the CURRENT behavior of validateRecord / formatErrors /
// cveSchema so that the upcoming consolidation of CVE transforms into
// @vulndesk/core surfaces ANY regression. Every expected value here was
// observed by running the real code first; nothing is guessed.
//
// The existing test/core-validate.test.js covers 5 basic cases (valid record,
// missing top-level fields, wrong description type, formatErrors strings,
// schema title). This file goes much further and does not duplicate those.
// ---------------------------------------------------------------------------

const ORG_ID = 'b3476cb9-2e3d-41a6-98d0-0f47421a65b6'

// A minimal, well-formed PUBLISHED CVE Record Format 5.x record. Each test
// that needs a mutated copy starts from a deep clone of this.
function publishedRecord() {
  return {
    dataType: 'CVE_RECORD',
    dataVersion: '5.1',
    cveMetadata: {
      cveId: 'CVE-2024-0001',
      assignerOrgId: ORG_ID,
      state: 'PUBLISHED',
    },
    containers: {
      cna: {
        providerMetadata: { orgId: ORG_ID },
        descriptions: [
          { lang: 'en', value: 'A sufficiently long test vulnerability description.' },
        ],
        affected: [
          {
            vendor: 'Acme',
            product: 'Widget',
            versions: [{ version: '1.0', status: 'affected' }],
          },
        ],
        references: [{ url: 'https://example.com/advisory' }],
      },
    },
  }
}

// A minimal, well-formed REJECTED CVE Record Format 5.x record.
function rejectedRecord() {
  return {
    dataType: 'CVE_RECORD',
    dataVersion: '5.1',
    cveMetadata: {
      cveId: 'CVE-2024-0002',
      assignerOrgId: ORG_ID,
      state: 'REJECTED',
    },
    containers: {
      cna: {
        providerMetadata: { orgId: ORG_ID },
        rejectedReasons: [
          { lang: 'en', value: 'This CVE ID was a duplicate and is rejected.' },
        ],
      },
    },
  }
}

const clone = (o) => JSON.parse(JSON.stringify(o))

// ===========================================================================
// cveSchema export shape
// ===========================================================================
describe('@vulndesk/core cveSchema export', () => {
  it('exposes the official CVE Record Format schema title', () => {
    expect(cveSchema.title).toBe('CVE JSON record format')
  })

  it('declares the draft-07 meta-schema', () => {
    expect(cveSchema['$schema']).toBe('http://json-schema.org/draft-07/schema#')
  })

  it('models the record as a oneOf with exactly two branches', () => {
    expect(Array.isArray(cveSchema.oneOf)).toBe(true)
    expect(cveSchema.oneOf).toHaveLength(2)
  })

  it('names the two oneOf branches Published and Rejected', () => {
    expect(cveSchema.oneOf.map((b) => b.title)).toEqual(['Published', 'Rejected'])
  })

  it('requires the four top-level fields in the Published branch', () => {
    expect(cveSchema.oneOf[0].required).toEqual([
      'dataType',
      'dataVersion',
      'cveMetadata',
      'containers',
    ])
  })

  it('exposes the cveId pattern definition', () => {
    expect(cveSchema.definitions.cveId.pattern).toBe('^CVE-[0-9]{4}-[0-9]{4,19}$')
  })

  it('has a stable definitions block (snapshot of key names)', () => {
    expect(Object.keys(cveSchema.definitions)).toMatchSnapshot()
  })
})

// ===========================================================================
// Valid records: PUBLISHED and REJECTED branches
// ===========================================================================
describe('validateRecord: valid records', () => {
  it('accepts a minimal PUBLISHED record', () => {
    const { valid, errors } = validateRecord(publishedRecord())
    expect(valid).toBe(true)
    expect(errors).toEqual([])
  })

  it('accepts a minimal REJECTED record (state REJECTED + rejectedReasons)', () => {
    const { valid, errors } = validateRecord(rejectedRecord())
    expect(valid).toBe(true)
    expect(errors).toEqual([])
  })

  it('accepts a REJECTED record carrying replacedBy and a date', () => {
    const r = rejectedRecord()
    r.cveMetadata.dateRejected = '2024-01-15T00:00:00.000Z'
    r.containers.cna.replacedBy = ['CVE-2024-9999']
    const { valid, errors } = validateRecord(r)
    expect(valid).toBe(true)
    expect(errors).toEqual([])
  })

  it('accepts a PUBLISHED record with optional cveMetadata timestamps', () => {
    const r = publishedRecord()
    r.cveMetadata.dateReserved = '2024-01-01T00:00:00.000Z'
    r.cveMetadata.datePublished = '2024-02-01T00:00:00.000Z'
    r.cveMetadata.dateUpdated = '2024-03-01T00:00:00.000Z'
    r.cveMetadata.assignerShortName = 'acme'
    const { valid, errors } = validateRecord(r)
    expect(valid).toBe(true)
    expect(errors).toEqual([])
  })

  it('accepts a 19-digit numeric portion in cveId (boundary)', () => {
    const r = publishedRecord()
    r.cveMetadata.cveId = 'CVE-2024-' + '1'.repeat(19)
    expect(validateRecord(r).valid).toBe(true)
  })

  it('accepts the minimum 4-digit numeric portion in cveId (boundary)', () => {
    const r = publishedRecord()
    r.cveMetadata.cveId = 'CVE-2024-0001'
    expect(validateRecord(r).valid).toBe(true)
  })
})

// ===========================================================================
// PUBLISHED vs REJECTED oneOf cross-mismatches
// ===========================================================================
describe('validateRecord: PUBLISHED/REJECTED oneOf mismatches', () => {
  it('rejects a REJECTED-shaped record whose state says PUBLISHED', () => {
    const r = rejectedRecord()
    r.cveMetadata.state = 'PUBLISHED'
    const { valid, errors } = validateRecord(r)
    expect(valid).toBe(false)
    // Observed: neither oneOf branch matches -> multiple errors.
    expect(errors.length).toBeGreaterThan(0)
  })

  it('rejects a PUBLISHED-shaped record whose state says REJECTED', () => {
    const r = publishedRecord()
    r.cveMetadata.state = 'REJECTED'
    const { valid } = validateRecord(r)
    expect(valid).toBe(false)
  })

  it('rejects a REJECTED record missing rejectedReasons and names the field', () => {
    const r = rejectedRecord()
    delete r.containers.cna.rejectedReasons
    const { valid, errors } = validateRecord(r)
    expect(valid).toBe(false)
    const messages = formatErrors(errors)
    expect(
      messages.some((m) =>
        m.includes("/containers/cna must have required property 'rejectedReasons'"),
      ),
    ).toBe(true)
  })

  it('rejects an unknown state value', () => {
    const r = publishedRecord()
    r.cveMetadata.state = 'DISPUTED'
    const { valid, errors } = validateRecord(r)
    expect(valid).toBe(false)
    const joined = formatErrors(errors).join('\n')
    expect(joined).toMatch(/state must be equal to one of the allowed values/)
  })
})

// ===========================================================================
// CVSS metrics in the CNA container
// ===========================================================================
describe('validateRecord: CNA CVSS metrics', () => {
  it('accepts a CNA carrying a cvssV3_1 metric', () => {
    const r = publishedRecord()
    r.containers.cna.metrics = [
      {
        cvssV3_1: {
          version: '3.1',
          vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
          baseScore: 9.8,
          baseSeverity: 'CRITICAL',
        },
      },
    ]
    const { valid, errors } = validateRecord(r)
    expect(valid).toBe(true)
    expect(errors).toEqual([])
  })

  it('accepts a CNA carrying a cvssV4_0 metric', () => {
    const r = publishedRecord()
    r.containers.cna.metrics = [
      {
        cvssV4_0: {
          version: '4.0',
          vectorString:
            'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H',
          baseScore: 9.3,
          baseSeverity: 'CRITICAL',
        },
      },
    ]
    const { valid, errors } = validateRecord(r)
    expect(valid).toBe(true)
    expect(errors).toEqual([])
  })

  it('accepts a CNA carrying both cvssV3_1 and cvssV4_0 metrics', () => {
    const r = publishedRecord()
    r.containers.cna.metrics = [
      {
        cvssV3_1: {
          version: '3.1',
          vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
          baseScore: 9.8,
          baseSeverity: 'CRITICAL',
        },
      },
      {
        cvssV4_0: {
          version: '4.0',
          vectorString:
            'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H',
          baseScore: 9.3,
          baseSeverity: 'CRITICAL',
        },
      },
    ]
    expect(validateRecord(r).valid).toBe(true)
  })

  it('rejects a cvssV3_1 baseScore outside the 0-10 range and names baseScore', () => {
    const r = publishedRecord()
    r.containers.cna.metrics = [
      {
        cvssV3_1: {
          version: '3.1',
          vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
          baseScore: 99,
          baseSeverity: 'CRITICAL',
        },
      },
    ]
    const { valid, errors } = validateRecord(r)
    expect(valid).toBe(false)
    const joined = formatErrors(errors).join('\n')
    expect(joined).toMatch(/metrics\/0\/cvssV3_1\/baseScore/)
  })

  it('rejects a cvssV3_1 metric with a malformed vectorString', () => {
    const r = publishedRecord()
    r.containers.cna.metrics = [
      {
        cvssV3_1: {
          version: '3.1',
          vectorString: 'NOT-A-VECTOR',
          baseScore: 5.0,
          baseSeverity: 'MEDIUM',
        },
      },
    ]
    const { valid, errors } = validateRecord(r)
    expect(valid).toBe(false)
    expect(formatErrors(errors).join('\n')).toMatch(/vectorString/)
  })

  it('rejects a cvssV3_1 metric missing the required baseSeverity', () => {
    const r = publishedRecord()
    r.containers.cna.metrics = [
      {
        cvssV3_1: {
          version: '3.1',
          vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
          baseScore: 9.8,
        },
      },
    ]
    const { valid, errors } = validateRecord(r)
    expect(valid).toBe(false)
    expect(formatErrors(errors).join('\n')).toMatch(/baseSeverity/)
  })

  it('rejects an empty metrics array (minItems 1)', () => {
    const r = publishedRecord()
    r.containers.cna.metrics = []
    const { valid, errors } = validateRecord(r)
    expect(valid).toBe(false)
    expect(formatErrors(errors).join('\n')).toMatch(/metrics/)
  })

  it('rejects a metrics entry that has none of the required score keys', () => {
    const r = publishedRecord()
    r.containers.cna.metrics = [{ format: 'cvssV3_1' }]
    const { valid } = validateRecord(r)
    expect(valid).toBe(false)
  })
})

// ===========================================================================
// ADP containers
// ===========================================================================
describe('validateRecord: ADP containers', () => {
  it('accepts a PUBLISHED record with a valid adp container', () => {
    const r = publishedRecord()
    r.containers.adp = [{ providerMetadata: { orgId: ORG_ID }, title: 'ADP note' }]
    const { valid, errors } = validateRecord(r)
    expect(valid).toBe(true)
    expect(errors).toEqual([])
  })

  it('rejects an adp container missing providerMetadata and names the field', () => {
    const r = publishedRecord()
    r.containers.adp = [{ title: 'no provider' }]
    const { valid, errors } = validateRecord(r)
    expect(valid).toBe(false)
    expect(
      formatErrors(errors).some((m) =>
        m.includes("/containers/adp/0 must have required property 'providerMetadata'"),
      ),
    ).toBe(true)
  })

  it('rejects an empty adp array (minItems 1)', () => {
    const r = publishedRecord()
    r.containers.adp = []
    const { valid } = validateRecord(r)
    expect(valid).toBe(false)
  })

  it('rejects an adp container on a REJECTED record (rejected branch forbids adp)', () => {
    const r = rejectedRecord()
    r.containers.adp = [{ providerMetadata: { orgId: ORG_ID } }]
    const { valid } = validateRecord(r)
    expect(valid).toBe(false)
  })
})

// ===========================================================================
// Invalid cveId patterns
// ===========================================================================
describe('validateRecord: invalid cveId patterns', () => {
  const cases = [
    'CVE-24-1',
    'cve-2024-0001',
    'CVE-2024-1',
    'CVE-2024-001',
    'CVE-20245-0001',
    'CVE2024-0001',
    '2024-0001',
    'CVE-2024-0001 ',
  ]
  for (const bad of cases) {
    it(`rejects cveId "${bad}" and reports the pattern`, () => {
      const r = publishedRecord()
      r.cveMetadata.cveId = bad
      const { valid, errors } = validateRecord(r)
      expect(valid).toBe(false)
      expect(formatErrors(errors).join('\n')).toMatch(/cveId must match pattern/)
    })
  }

  it('rejects a numeric (non-string) cveId', () => {
    const r = publishedRecord()
    r.cveMetadata.cveId = 20240001
    const { valid } = validateRecord(r)
    expect(valid).toBe(false)
  })
})

// ===========================================================================
// Invalid assignerOrgId (UUID) patterns
// ===========================================================================
describe('validateRecord: invalid assignerOrgId', () => {
  it('rejects a plainly non-UUID assignerOrgId', () => {
    const r = publishedRecord()
    r.cveMetadata.assignerOrgId = 'not-a-uuid'
    const { valid, errors } = validateRecord(r)
    expect(valid).toBe(false)
    expect(formatErrors(errors).join('\n')).toMatch(/assignerOrgId must match pattern/)
  })

  it('rejects a UUID with the wrong version nibble', () => {
    const r = publishedRecord()
    // version digit changed from 4 to 1 -> fails the "4[0-9A-Fa-f]{3}" group.
    r.cveMetadata.assignerOrgId = 'b3476cb9-2e3d-11a6-98d0-0f47421a65b6'
    const { valid, errors } = validateRecord(r)
    expect(valid).toBe(false)
    expect(formatErrors(errors).join('\n')).toMatch(/assignerOrgId/)
  })

  it('rejects a UUID missing a hyphen group', () => {
    const r = publishedRecord()
    r.cveMetadata.assignerOrgId = 'b3476cb92e3d41a698d00f47421a65b6'
    const { valid } = validateRecord(r)
    expect(valid).toBe(false)
  })
})

// ===========================================================================
// providerMetadata, descriptions, affected/versions
// ===========================================================================
describe('validateRecord: CNA structural requirements', () => {
  it('rejects a CNA missing providerMetadata and names the field', () => {
    const r = publishedRecord()
    delete r.containers.cna.providerMetadata
    const { valid, errors } = validateRecord(r)
    expect(valid).toBe(false)
    expect(
      formatErrors(errors).some((m) =>
        m.includes("/containers/cna must have required property 'providerMetadata'"),
      ),
    ).toBe(true)
  })

  it('rejects providerMetadata missing its required orgId', () => {
    const r = publishedRecord()
    r.containers.cna.providerMetadata = { shortName: 'acme' }
    const { valid, errors } = validateRecord(r)
    expect(valid).toBe(false)
    expect(formatErrors(errors).join('\n')).toMatch(/orgId/)
  })

  it('rejects an empty descriptions array (minItems 1)', () => {
    const r = publishedRecord()
    r.containers.cna.descriptions = []
    const { valid, errors } = validateRecord(r)
    expect(valid).toBe(false)
    expect(formatErrors(errors).join('\n')).toMatch(/descriptions must NOT have fewer than 1 items/)
  })

  it('rejects a description with an empty-string value (minLength 1)', () => {
    const r = publishedRecord()
    r.containers.cna.descriptions = [{ lang: 'en', value: '' }]
    const { valid, errors } = validateRecord(r)
    expect(valid).toBe(false)
    expect(formatErrors(errors).join('\n')).toMatch(
      /descriptions\/0\/value must NOT have fewer than 1 characters/,
    )
  })

  it('ACCEPTS a one-character description value (schema minLength is 1, not a sentence)', () => {
    // Characterization: there is NO "minimum sentence length" in the schema.
    // A single character is valid today; locking that so a refactor cannot
    // silently introduce or rely on a stricter rule.
    const r = publishedRecord()
    r.containers.cna.descriptions = [{ lang: 'en', value: 'x' }]
    expect(validateRecord(r).valid).toBe(true)
  })

  it('rejects descriptions that contain no English-language entry (contains constraint)', () => {
    const r = publishedRecord()
    r.containers.cna.descriptions = [
      { lang: 'fr', value: 'Une description de vulnerabilite assez longue.' },
    ]
    const { valid, errors } = validateRecord(r)
    expect(valid).toBe(false)
    expect(formatErrors(errors).join('\n')).toMatch(/descriptions must contain at least 1 valid item/)
  })

  it('rejects affected when it is not an array', () => {
    const r = publishedRecord()
    r.containers.cna.affected = 'nope'
    const { valid, errors } = validateRecord(r)
    expect(valid).toBe(false)
    expect(formatErrors(errors).join('\n')).toMatch(/affected must be array/)
  })

  it('rejects an empty affected array (minItems 1)', () => {
    const r = publishedRecord()
    r.containers.cna.affected = []
    const { valid } = validateRecord(r)
    expect(valid).toBe(false)
  })

  it('rejects versions when it is not an array', () => {
    const r = publishedRecord()
    r.containers.cna.affected[0].versions = 'nope'
    const { valid, errors } = validateRecord(r)
    expect(valid).toBe(false)
    expect(formatErrors(errors).join('\n')).toMatch(/affected\/0\/versions must be array/)
  })

  it('rejects a CNA missing affected', () => {
    const r = publishedRecord()
    delete r.containers.cna.affected
    const { valid, errors } = validateRecord(r)
    expect(valid).toBe(false)
    expect(formatErrors(errors).join('\n')).toMatch(/must have required property 'affected'/)
  })

  it('rejects a CNA missing references', () => {
    const r = publishedRecord()
    delete r.containers.cna.references
    const { valid, errors } = validateRecord(r)
    expect(valid).toBe(false)
    expect(formatErrors(errors).join('\n')).toMatch(/must have required property 'references'/)
  })

  it('rejects a reference whose url is not a valid uri', () => {
    const r = publishedRecord()
    r.containers.cna.references = [{ url: 'not a url' }]
    const { valid, errors } = validateRecord(r)
    expect(valid).toBe(false)
    expect(formatErrors(errors).join('\n')).toMatch(/references\/0\/url must match format "uri"/)
  })
})

// ===========================================================================
// Unknown / additional properties (additionalProperties: false)
// ===========================================================================
describe('validateRecord: unknown / extra properties', () => {
  it('rejects an unknown top-level property', () => {
    const r = publishedRecord()
    r.bogusTop = 'x'
    const { valid, errors } = validateRecord(r)
    expect(valid).toBe(false)
    expect(
      formatErrors(errors).some((m) => m.includes('(root) must NOT have additional properties')),
    ).toBe(true)
  })

  it('rejects an unknown property inside the cna container', () => {
    const r = publishedRecord()
    r.containers.cna.bogus = 'x'
    const { valid, errors } = validateRecord(r)
    expect(valid).toBe(false)
    expect(
      formatErrors(errors).some((m) =>
        m.includes('/containers/cna must NOT have additional properties'),
      ),
    ).toBe(true)
  })

  it('rejects an unknown property inside cveMetadata', () => {
    const r = publishedRecord()
    r.cveMetadata.bogus = 'x'
    const { valid } = validateRecord(r)
    expect(valid).toBe(false)
  })

  it('rejects an unknown container key besides cna/adp', () => {
    const r = publishedRecord()
    r.containers.bogus = {}
    const { valid } = validateRecord(r)
    expect(valid).toBe(false)
  })
})

// ===========================================================================
// Wrong top-level field values / types
// ===========================================================================
describe('validateRecord: top-level field types', () => {
  it('rejects a dataType that is not CVE_RECORD', () => {
    const r = publishedRecord()
    r.dataType = 'WRONG'
    const { valid, errors } = validateRecord(r)
    expect(valid).toBe(false)
    expect(formatErrors(errors).join('\n')).toMatch(/dataType must be equal to one of the allowed values/)
  })

  it('rejects a numeric dataVersion (must be string)', () => {
    const r = publishedRecord()
    r.dataVersion = 5.1
    const { valid, errors } = validateRecord(r)
    expect(valid).toBe(false)
    expect(formatErrors(errors).join('\n')).toMatch(/dataVersion must be string/)
  })

  it('rejects a record whose containers omit cna', () => {
    const r = publishedRecord()
    delete r.containers.cna
    const { valid, errors } = validateRecord(r)
    expect(valid).toBe(false)
    expect(formatErrors(errors).join('\n')).toMatch(/containers must have required property 'cna'/)
  })

  it('rejects a record missing cveMetadata entirely', () => {
    const r = publishedRecord()
    delete r.cveMetadata
    const { valid } = validateRecord(r)
    expect(valid).toBe(false)
  })
})

// ===========================================================================
// Empty object and non-object inputs (lock the exact return shapes)
// ===========================================================================
describe('validateRecord: empty and non-object inputs', () => {
  it('rejects {} and reports required top-level fields', () => {
    const { valid, errors } = validateRecord({})
    expect(valid).toBe(false)
    // Observed exactly 9 errors for {} (both oneOf branches enumerate the
    // four required props + the oneOf failure).
    expect(errors).toHaveLength(9)
    const joined = formatErrors(errors).join('\n')
    expect(joined).toMatch(/must have required property 'dataType'/)
    expect(joined).toMatch(/must have required property 'dataVersion'/)
    expect(joined).toMatch(/must have required property 'cveMetadata'/)
    expect(joined).toMatch(/must have required property 'containers'/)
  })

  it('rejects null with "must be object"', () => {
    const { valid, errors } = validateRecord(null)
    expect(valid).toBe(false)
    expect(formatErrors(errors).some((m) => m.includes('(root) must be object'))).toBe(true)
  })

  it('rejects an array []', () => {
    const { valid, errors } = validateRecord([])
    expect(valid).toBe(false)
    expect(formatErrors(errors).join('\n')).toMatch(/must be object/)
  })

  it('rejects a bare string', () => {
    const { valid, errors } = validateRecord('hello')
    expect(valid).toBe(false)
    expect(errors).toHaveLength(3)
  })

  it('rejects the number 42', () => {
    const { valid, errors } = validateRecord(42)
    expect(valid).toBe(false)
    expect(errors).toHaveLength(3)
  })

  it('rejects a boolean true', () => {
    const { valid } = validateRecord(true)
    expect(valid).toBe(false)
  })

  it('rejects undefined input', () => {
    const { valid, errors } = validateRecord(undefined)
    expect(valid).toBe(false)
    expect(formatErrors(errors).join('\n')).toMatch(/must be object/)
  })
})

// ===========================================================================
// Return contract of validateRecord
// ===========================================================================
describe('validateRecord: return contract', () => {
  it('returns { valid: true, errors: [] } for a valid record', () => {
    const result = validateRecord(publishedRecord())
    expect(result).toEqual({ valid: true, errors: [] })
  })

  it('returns an array of errors (not null) when invalid', () => {
    const { errors } = validateRecord({})
    expect(Array.isArray(errors)).toBe(true)
  })

  it('raw AJV error objects keep their standard keys', () => {
    const r = publishedRecord()
    r.cveMetadata.cveId = 'bad'
    const { errors } = validateRecord(r)
    expect(Object.keys(errors[0]).sort()).toEqual(
      ['instancePath', 'keyword', 'message', 'params', 'schemaPath'].sort(),
    )
  })
})

// ===========================================================================
// formatErrors behavior in isolation
// ===========================================================================
describe('formatErrors', () => {
  it('returns [] for null', () => {
    expect(formatErrors(null)).toEqual([])
  })

  it('returns [] for undefined', () => {
    expect(formatErrors(undefined)).toEqual([])
  })

  it('returns [] for an empty array', () => {
    expect(formatErrors([])).toEqual([])
  })

  it('uses "(root)" when instancePath is empty', () => {
    expect(formatErrors([{ message: 'is bad' }])).toEqual(['(root) is bad'])
  })

  it('uses "(root)" when instancePath is an empty string', () => {
    expect(formatErrors([{ instancePath: '', message: 'is bad' }])).toEqual(['(root) is bad'])
  })

  it('prefixes with the instancePath when present', () => {
    expect(formatErrors([{ instancePath: '/foo/bar', message: 'is bad' }])).toEqual([
      '/foo/bar is bad',
    ])
  })

  it('interpolates undefined when message is missing (no special handling)', () => {
    // Characterization: the template literal stringifies a missing message as
    // "undefined"; .trim() only removes whitespace, so the word remains.
    expect(formatErrors([{ instancePath: '/foo' }])).toEqual(['/foo undefined'])
  })

  it('maps multiple errors one-to-one', () => {
    const out = formatErrors([
      { instancePath: '/a', message: 'one' },
      { instancePath: '/b', message: 'two' },
    ])
    expect(out).toEqual(['/a one', '/b two'])
  })

  it('produces an array of strings for a real invalid record', () => {
    const { errors } = validateRecord({})
    const messages = formatErrors(errors)
    expect(messages).toHaveLength(errors.length)
    expect(messages.every((m) => typeof m === 'string')).toBe(true)
  })
})

// ===========================================================================
// Snapshots: lock the exact, full formatted-error output for key cases
// ===========================================================================
describe('validateRecord: formatted error snapshots', () => {
  it('empty {} formatted errors', () => {
    const { errors } = validateRecord({})
    expect(formatErrors(errors)).toMatchSnapshot()
  })

  it('null input formatted errors', () => {
    const { errors } = validateRecord(null)
    expect(formatErrors(errors)).toMatchSnapshot()
  })

  it('bad cveId formatted errors', () => {
    const r = publishedRecord()
    r.cveMetadata.cveId = 'CVE-24-1'
    const { errors } = validateRecord(r)
    expect(formatErrors(errors)).toMatchSnapshot()
  })

  it('non-UUID assignerOrgId formatted errors', () => {
    const r = publishedRecord()
    r.cveMetadata.assignerOrgId = 'not-a-uuid'
    const { errors } = validateRecord(r)
    expect(formatErrors(errors)).toMatchSnapshot()
  })

  it('REJECTED missing rejectedReasons formatted errors', () => {
    const r = rejectedRecord()
    delete r.containers.cna.rejectedReasons
    const { errors } = validateRecord(r)
    expect(formatErrors(errors)).toMatchSnapshot()
  })

  it('out-of-range cvssV3_1 baseScore formatted errors', () => {
    const r = publishedRecord()
    r.containers.cna.metrics = [
      {
        cvssV3_1: {
          version: '3.1',
          vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
          baseScore: 99,
          baseSeverity: 'CRITICAL',
        },
      },
    ]
    const { errors } = validateRecord(r)
    expect(formatErrors(errors)).toMatchSnapshot()
  })

  it('unknown top-level property formatted errors', () => {
    const r = publishedRecord()
    r.extraTopLevel = true
    const { errors } = validateRecord(r)
    expect(formatErrors(errors)).toMatchSnapshot()
  })
})

// ===========================================================================
// Determinism: same input -> same output across calls
// ===========================================================================
describe('validateRecord: determinism', () => {
  it('produces identical results on repeated calls with the same record', () => {
    const r = publishedRecord()
    const a = validateRecord(clone(r))
    const b = validateRecord(clone(r))
    expect(a).toEqual(b)
  })

  it('produces identical error lists on repeated invalid calls', () => {
    const bad = { dataType: 'CVE_RECORD' }
    const a = formatErrors(validateRecord(clone(bad)).errors)
    const b = formatErrors(validateRecord(clone(bad)).errors)
    expect(a).toEqual(b)
  })
})
