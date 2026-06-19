'use strict'

// @vulndesk/core — headless CVE/advisory core.
//
// This module owns the framework-agnostic logic that the web UI, the standalone
// browser bundle, and the future MCP server all depend on. The first capability
// is the one the app has never had: server-side CVE5 record validation.

const fs = require('fs')
const path = require('path')
const Ajv = require('ajv')
const addFormats = require('ajv-formats')

const SCHEMA_DIR = path.join(__dirname, '..', 'schema')

function loadSchema(relPath) {
  return JSON.parse(fs.readFileSync(path.join(SCHEMA_DIR, relPath), 'utf8'))
}

// The vendored CVSS sub-schemas are draft-04, which uses the legacy `id`
// keyword (AJV 8 only accepts `$id`) and a draft-04 `$schema`. Strip both so
// AJV 8 can register them; they are enum/number based, so this does not change
// what they accept. We register each under an explicit `file:` key anyway.
function stripDraft04(node) {
  if (Array.isArray(node)) {
    node.forEach(stripDraft04)
  } else if (node && typeof node === 'object') {
    delete node.id
    delete node.$schema
    for (const key of Object.keys(node)) stripDraft04(node[key])
  }
  return node
}

// The main schema references these by `file:` URI; register each under that
// exact key so AJV can resolve the $refs offline (no network at runtime).
const EXTERNAL_REFS = {
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
// validateSchema:false — the vendored CVSS sub-schemas declare draft-04, whose
// meta-schema AJV 8 doesn't ship; skip meta-validation (data validation is
// unaffected — they are enum/string based).
const ajv = new Ajv({ allErrors: true, strict: false, validateSchema: false })
addFormats(ajv)

for (const [refKey, relPath] of Object.entries(EXTERNAL_REFS)) {
  ajv.addSchema(stripDraft04(loadSchema(relPath)), refKey)
}

const cveSchema = loadSchema('CVE_Record_Format.json')
const validateFn = ajv.compile(cveSchema)

/**
 * Validate a CVE Record Format 5.x record against the official structural schema.
 * @param {object} record - a full CVE record (the published/exported container).
 * @returns {{ valid: boolean, errors: Array }} validation result; `errors` is the
 *   raw AJV error list (empty when valid).
 */
function validateRecord(record) {
  const valid = validateFn(record) === true
  return { valid, errors: valid ? [] : validateFn.errors || [] }
}

/**
 * Human-readable one-liners for AJV errors, handy for logs and API responses.
 * @param {Array} errors - AJV error objects from validateRecord().
 * @returns {string[]}
 */
function formatErrors(errors) {
  return (errors || []).map((e) => `${e.instancePath || '(root)'} ${e.message}`.trim())
}

module.exports = {
  validateRecord,
  formatErrors,
  cveSchema,
}
