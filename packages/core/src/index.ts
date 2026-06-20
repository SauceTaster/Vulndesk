// @vulndesk/core — headless CVE/advisory core (TypeScript).
//
// The framework-agnostic kernel the web UI, the standalone bundle, and the
// future MCP server all depend on: CVE5 record validation (AJV against the
// canonical schema) plus the Zod domain models for the rest of the app.

import fs from 'node:fs'
import path from 'node:path'
import Ajv, { type ErrorObject, type ValidateFunction } from 'ajv'
import addFormats from 'ajv-formats'

const SCHEMA_DIR = path.join(__dirname, '..', 'schema')

function loadSchema(relPath: string): Record<string, unknown> {
  return JSON.parse(fs.readFileSync(path.join(SCHEMA_DIR, relPath), 'utf8'))
}

// The vendored CVSS sub-schemas are draft-04, which uses the legacy `id`
// keyword (AJV 8 only accepts `$id`) and a draft-04 `$schema`. Strip both so
// AJV 8 can register them; they are enum/number based, so this does not change
// what they accept.
function stripDraft04<T>(node: T): T {
  if (Array.isArray(node)) {
    node.forEach(stripDraft04)
  } else if (node && typeof node === 'object') {
    const obj = node as Record<string, unknown>
    delete obj.id
    delete obj.$schema
    for (const key of Object.keys(obj)) stripDraft04(obj[key])
  }
  return node
}

// The main schema references these by `file:` URI; register each under that
// exact key so AJV resolves the $refs offline (no network at runtime).
const EXTERNAL_REFS: Record<string, string> = {
  'file:imports/cvss/cvss-v2.0.json': 'imports/cvss/cvss-v2.0.json',
  'file:imports/cvss/cvss-v3.0.json': 'imports/cvss/cvss-v3.0.json',
  'file:imports/cvss/cvss-v3.1.json': 'imports/cvss/cvss-v3.1.json',
  'file:imports/cvss/cvss-v4.0.json': 'imports/cvss/cvss-v4.0.json',
  'file:tags/adp-tags.json': 'tags/adp-tags.json',
  'file:tags/cna-tags.json': 'tags/cna-tags.json',
  'file:tags/reference-tags.json': 'tags/reference-tags.json',
}

// strict:false — the upstream CVE schema uses keywords/metadata AJV's strict
// mode would reject; we validate data, not lint the schema.
// validateSchema:false — the draft-04 CVSS sub-schemas have no meta-schema in
// AJV 8; skip meta-validation (data validation is unaffected).
const ajv = new Ajv({ allErrors: true, strict: false, validateSchema: false })
addFormats(ajv)

for (const [refKey, relPath] of Object.entries(EXTERNAL_REFS)) {
  ajv.addSchema(stripDraft04(loadSchema(relPath)), refKey)
}

/** The canonical CVE Record Format 5.x JSON Schema (vendored). */
export const cveSchema = loadSchema('CVE_Record_Format.json')

const validateFn: ValidateFunction = ajv.compile(cveSchema)

export interface ValidationResult {
  valid: boolean
  errors: ErrorObject[]
}

/**
 * Validate a CVE Record Format 5.x record against the official structural schema.
 * @param record a full CVE record (the published/exported container)
 */
export function validateRecord(record: unknown): ValidationResult {
  const valid = validateFn(record) === true
  return { valid, errors: valid ? [] : (validateFn.errors ?? []) }
}

/** Human-readable one-liners for AJV errors, for logs and API responses. */
export function formatErrors(errors: ErrorObject[] | null | undefined): string[] {
  return (errors ?? []).map((e) => `${e.instancePath || '(root)'} ${e.message}`.trim())
}

export * from './models.js'
