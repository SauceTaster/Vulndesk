import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest'
import { createRequire } from 'module'

// ---------------------------------------------------------------------------
// CHARACTERIZATION TESTS for config/conf-default.js and config/conf-standalone.js
//
// These configs are plain CommonJS and are evaluated at REQUIRE-TIME, reading
// from process.env. The DocumentDB migration depends on the env-driven
// `database` seam, so we lock down exactly how the connection string and the
// server host/port are built from environment variables TODAY.
//
// IMPORTANT (recorded current behavior, NOT a judgement of correctness):
//   * conf-default builds `database` from MONGO_* env vars. There is NO
//     DATABASE_URL override present in the code at the time these tests were
//     written — DATABASE_URL is ignored. We assert that explicitly so that if
//     the migration ADDS a DATABASE_URL seam, this test will flip and force a
//     conscious update.
//   * Defaults: mongodb://admin:admin@127.0.0.1:27017
//   * serverHost default 127.0.0.1, serverPort default 3555 (a NUMBER).
//   * When VULNDESK_PORT is set, serverPort becomes the raw STRING from env.
//   * Empty-string env vars are falsy and fall back to defaults.
//
// To exercise require-time env permutations cleanly we use a dedicated
// `createRequire` bound to this test file, set process.env, drop the module
// from that require's cache, and re-require. package.json is also dropped from
// cache so the copyright/version interpolation re-evaluates fresh.
// ---------------------------------------------------------------------------

const req = createRequire(import.meta.url)

const DEFAULT_PATH = req.resolve('../config/conf-default.js')
const STANDALONE_PATH = req.resolve('../config/conf-standalone.js')
const PKG_PATH = req.resolve('../package.json')

const pkg = req(PKG_PATH)

// The env keys these configs read. We snapshot/restore the whole set so tests
// are isolated and order-independent.
const ENV_KEYS = [
  'MONGO_INITDB_ROOT_USERNAME',
  'MONGO_INITDB_ROOT_PASSWORD',
  'MONGO_HOST',
  'MONGO_PORT',
  'VULNDESK_HOST',
  'VULNDESK_PORT',
  'DATABASE_URL',
]

let savedEnv = {}

function clearConfigEnv() {
  for (const k of ENV_KEYS) delete process.env[k]
}

// Re-require conf-default.js fresh after the current process.env is in place.
function loadDefault() {
  delete req.cache[DEFAULT_PATH]
  delete req.cache[PKG_PATH]
  return req(DEFAULT_PATH)
}

// Re-require conf-standalone.js fresh.
function loadStandalone() {
  delete req.cache[STANDALONE_PATH]
  delete req.cache[PKG_PATH]
  return req(STANDALONE_PATH)
}

beforeAll(() => {
  // Snapshot any pre-existing values for these keys so the dev's shell env
  // cannot leak into (or be clobbered by) these tests.
  for (const k of ENV_KEYS) savedEnv[k] = process.env[k]
})

afterAll(() => {
  // Restore original environment exactly.
  for (const k of ENV_KEYS) {
    if (savedEnv[k] === undefined) delete process.env[k]
    else process.env[k] = savedEnv[k]
  }
})

beforeEach(() => {
  // Every test starts from a clean slate; tests opt-in to the vars they need.
  clearConfigEnv()
})

// ===========================================================================
// conf-default.js — database connection string (the migration-critical seam)
// ===========================================================================
describe('conf-default.js :: database (MONGO_* env-driven connection string)', () => {
  it('with NO env vars, database uses the documented defaults', () => {
    const c = loadDefault()
    expect(c.database).toBe('mongodb://admin:admin@127.0.0.1:27017')
  })

  it('default has admin:admin credentials, 127.0.0.1 host, 27017 port, and no db path or query', () => {
    const c = loadDefault()
    expect(c.database).toMatch(/^mongodb:\/\//)
    expect(c.database).toContain('admin:admin@')
    expect(c.database).toContain('127.0.0.1:27017')
    // No trailing /dbname and no query string today.
    expect(c.database.endsWith('27017')).toBe(true)
    expect(c.database).not.toContain('?')
  })

  it('MONGO_INITDB_ROOT_USERNAME overrides the username component', () => {
    process.env.MONGO_INITDB_ROOT_USERNAME = 'vulndesk'
    const c = loadDefault()
    expect(c.database).toBe('mongodb://vulndesk:admin@127.0.0.1:27017')
  })

  it('MONGO_INITDB_ROOT_PASSWORD overrides the password component', () => {
    process.env.MONGO_INITDB_ROOT_PASSWORD = 'S3cretLong'
    const c = loadDefault()
    expect(c.database).toBe('mongodb://admin:S3cretLong@127.0.0.1:27017')
  })

  it('MONGO_HOST overrides the host component', () => {
    process.env.MONGO_HOST = 'mongo.internal'
    const c = loadDefault()
    expect(c.database).toBe('mongodb://admin:admin@mongo.internal:27017')
  })

  it('MONGO_PORT overrides the port component', () => {
    process.env.MONGO_PORT = '27018'
    const c = loadDefault()
    expect(c.database).toBe('mongodb://admin:admin@127.0.0.1:27018')
  })

  it('all four MONGO_* vars together build the full connection string', () => {
    process.env.MONGO_INITDB_ROOT_USERNAME = 'u'
    process.env.MONGO_INITDB_ROOT_PASSWORD = 'p'
    process.env.MONGO_HOST = 'h'
    process.env.MONGO_PORT = '999'
    const c = loadDefault()
    expect(c.database).toBe('mongodb://u:p@h:999')
  })

  it('empty-string MONGO_* vars are falsy and fall back to defaults', () => {
    process.env.MONGO_INITDB_ROOT_USERNAME = ''
    process.env.MONGO_INITDB_ROOT_PASSWORD = ''
    process.env.MONGO_HOST = ''
    process.env.MONGO_PORT = ''
    const c = loadDefault()
    expect(c.database).toBe('mongodb://admin:admin@127.0.0.1:27017')
  })

  it('special characters in MONGO_* are interpolated verbatim (no URL-encoding today)', () => {
    process.env.MONGO_INITDB_ROOT_USERNAME = 'a@b'
    process.env.MONGO_INITDB_ROOT_PASSWORD = 'p@ss:w/rd'
    process.env.MONGO_HOST = 'host'
    process.env.MONGO_PORT = '1'
    const c = loadDefault()
    // Recorded behavior: raw interpolation, no escaping.
    expect(c.database).toBe('mongodb://a@b:p@ss:w/rd@host:1')
  })

  // ---- DATABASE_URL seam lock --------------------------------------------
  it('DATABASE_URL is currently IGNORED — database is still built from MONGO_* defaults', () => {
    process.env.DATABASE_URL = 'postgres://should-not-be-used'
    const c = loadDefault()
    // TODAY there is no DATABASE_URL override; this MUST equal the MONGO-derived
    // default. If the migration adds the override, this assertion flips.
    expect(c.database).toBe('mongodb://admin:admin@127.0.0.1:27017')
    expect(c.database).not.toBe(process.env.DATABASE_URL)
  })

  it('DATABASE_URL set alongside MONGO_* still yields the MONGO_*-derived string', () => {
    process.env.DATABASE_URL = 'mongodb://verbatim:url@example.com:27017/db'
    process.env.MONGO_HOST = 'fromenv'
    const c = loadDefault()
    expect(c.database).toBe('mongodb://admin:admin@fromenv:27017')
    expect(c.database).not.toBe(process.env.DATABASE_URL)
  })

  it('conf-default has no `DATABASE_URL` key on the exported object', () => {
    const c = loadDefault()
    expect(Object.prototype.hasOwnProperty.call(c, 'DATABASE_URL')).toBe(false)
  })
})

// ===========================================================================
// conf-default.js — serverHost / serverPort (VULNDESK_* env-driven)
// ===========================================================================
describe('conf-default.js :: serverHost / serverPort (VULNDESK_* env-driven)', () => {
  it('default serverHost is 127.0.0.1', () => {
    const c = loadDefault()
    expect(c.serverHost).toBe('127.0.0.1')
  })

  it('default serverPort is the NUMBER 3555 (not a string)', () => {
    const c = loadDefault()
    expect(c.serverPort).toBe(3555)
    expect(typeof c.serverPort).toBe('number')
  })

  it('VULNDESK_HOST overrides serverHost', () => {
    process.env.VULNDESK_HOST = '0.0.0.0'
    const c = loadDefault()
    expect(c.serverHost).toBe('0.0.0.0')
  })

  it('VULNDESK_PORT overrides serverPort and becomes a STRING (env values are strings)', () => {
    process.env.VULNDESK_PORT = '8080'
    const c = loadDefault()
    expect(c.serverPort).toBe('8080')
    expect(typeof c.serverPort).toBe('string')
  })

  it('empty-string VULNDESK_HOST falls back to the 127.0.0.1 default', () => {
    process.env.VULNDESK_HOST = ''
    const c = loadDefault()
    expect(c.serverHost).toBe('127.0.0.1')
  })

  it('empty-string VULNDESK_PORT is falsy and falls back to the NUMBER 3555', () => {
    process.env.VULNDESK_PORT = ''
    const c = loadDefault()
    expect(c.serverPort).toBe(3555)
    expect(typeof c.serverPort).toBe('number')
  })

  it('VULNDESK_PORT="0" is falsy-string but non-empty, so it overrides to string "0"', () => {
    process.env.VULNDESK_PORT = '0'
    const c = loadDefault()
    // "0" is a truthy STRING, so the `|| 3555` does not trigger.
    expect(c.serverPort).toBe('0')
    expect(typeof c.serverPort).toBe('string')
  })

  it('both VULNDESK_* together override host and port', () => {
    process.env.VULNDESK_HOST = 'example.net'
    process.env.VULNDESK_PORT = '443'
    const c = loadDefault()
    expect(c.serverHost).toBe('example.net')
    expect(c.serverPort).toBe('443')
  })
})

// ===========================================================================
// conf-default.js — static/branding fields
// ===========================================================================
describe('conf-default.js :: static branding & literal fields', () => {
  it('copyright contains the package name and version', () => {
    const c = loadDefault()
    expect(c.copyright).toContain(pkg.name)
    expect(c.copyright).toContain(pkg.version)
    expect(c.copyright).toContain(`${pkg.name} ${pkg.version}`)
  })

  it('copyright equals the exact recorded string for the current package', () => {
    const c = loadDefault()
    expect(c.copyright).toBe(`© Example Org. Made with ${pkg.name} ${pkg.version}`)
  })

  it('homepage is the local /home route', () => {
    const c = loadDefault()
    expect(c.homepage).toBe('/home')
  })

  it('sections array is exactly [cve, cve5, nvd]', () => {
    const c = loadDefault()
    expect(c.sections).toEqual(['cve', 'cve5', 'nvd'])
  })

  it('basedir is "/"', () => {
    const c = loadDefault()
    expect(c.basedir).toBe('/')
  })

  it('groupName is the SIRT label', () => {
    const c = loadDefault()
    expect(c.groupName).toBe('Security Incident Response Team')
  })

  it('classification is the INTERNAL USE ONLY label', () => {
    const c = loadDefault()
    expect(c.classification).toBe('Confidential INTERNAL USE ONLY')
  })

  it('usernameRegex is the documented alnum-min-3 pattern', () => {
    const c = loadDefault()
    expect(c.usernameRegex).toBe('[a-zA-Z0-9]{3,}')
  })

  it('mitreURL, defectURL, publicDefectURL hold the recorded values', () => {
    const c = loadDefault()
    expect(c.mitreURL).toBe('https://www.cve.org/CVERecord?id=')
    expect(c.defectURL).toBe('https://example.net/internal/bugs/')
    expect(c.publicDefectURL).toBe('https://example.net/bugs/')
  })

  it('ace/jsoneditor/ajv CDN URLs and SRI hashes are locked', () => {
    const c = loadDefault()
    expect({
      ace: c.ace,
      aceHash: c.aceHash,
      jsoneditor: c.jsoneditor,
      jsoneditorHash: c.jsoneditorHash,
      ajv: c.ajv,
      ajvHash: c.ajvHash,
    }).toMatchSnapshot()
  })

  it('orgName, contact, reviewToken, httpsOptions, customRoutes are NOT present (commented out)', () => {
    const c = loadDefault()
    expect(c.orgName).toBeUndefined()
    expect(c.contact).toBeUndefined()
    expect(c.reviewToken).toBeUndefined()
    expect(c.httpsOptions).toBeUndefined()
    expect(c.customRoutes).toBeUndefined()
  })

  it('exported key set is exactly the recorded list (snapshot)', () => {
    const c = loadDefault()
    expect(Object.keys(c)).toMatchSnapshot()
  })

  it('full conf-default object (defaults, with env unset) snapshot', () => {
    const c = loadDefault()
    expect(c).toMatchSnapshot()
  })
})

// ===========================================================================
// conf-standalone.js — exported shape
// ===========================================================================
describe('conf-standalone.js :: exported shape', () => {
  it('exports exactly the recorded key set', () => {
    const c = loadStandalone()
    expect(Object.keys(c)).toEqual([
      'copyright',
      'basedir',
      'mitreURL',
      'defectURL',
      'ace',
      'aceHash',
      'jsoneditor',
      'jsoneditorHash',
      'sections',
      'homepage',
    ])
  })

  it('homepage is the GitHub repo URL', () => {
    const c = loadStandalone()
    expect(c.homepage).toBe('https://github.com/SauceTaster/Vulndesk')
  })

  it('sections array is exactly [cve5] (cve and cvss4 are commented out)', () => {
    const c = loadStandalone()
    expect(c.sections).toEqual(['cve5'])
  })

  it('basedir is "./" (relative, unlike conf-default which is "/")', () => {
    const c = loadStandalone()
    expect(c.basedir).toBe('./')
  })

  it('mitreURL uses the lowercase cverecord path', () => {
    const c = loadStandalone()
    expect(c.mitreURL).toBe('https://www.cve.org/cverecord?id=')
  })

  it('defectURL is the example.com bugtracker placeholder', () => {
    const c = loadStandalone()
    expect(c.defectURL).toBe('https://example.com/bugtracker=')
  })

  it('copyright contains the Chandan B.N attribution and package name+version', () => {
    const c = loadStandalone()
    expect(c.copyright).toContain('Chandan B.N')
    expect(c.copyright).toContain('2017-')
    expect(c.copyright).toContain(`${pkg.name} ${pkg.version}`)
    expect(c.copyright).toContain('This site does not track you')
  })

  it('copyright embeds the CURRENT year via new Date().getFullYear() (non-deterministic by design)', () => {
    const c = loadStandalone()
    const year = new Date().getFullYear()
    expect(c.copyright).toContain(`2017-${year}`)
    // Lock the full template around the live year.
    expect(c.copyright).toBe(
      `Copyright © Chandan B.N, 2017-${year}. Usage of CVE IDs is subject to CVE terms of use. ` +
        `This site does not track you and is safe for working with confidential vulnerability information. ` +
        `Made with ${pkg.name} ${pkg.version}`,
    )
  })

  it('does NOT carry database/server settings (standalone is a frontend-only config)', () => {
    const c = loadStandalone()
    expect(c.database).toBeUndefined()
    expect(c.serverHost).toBeUndefined()
    expect(c.serverPort).toBeUndefined()
    expect(c.groupName).toBeUndefined()
    expect(c.classification).toBeUndefined()
  })

  it('ace + jsoneditor URLs and SRI hashes are locked (jsoneditor differs from conf-default)', () => {
    const c = loadStandalone()
    expect({
      ace: c.ace,
      aceHash: c.aceHash,
      jsoneditor: c.jsoneditor,
      jsoneditorHash: c.jsoneditorHash,
    }).toMatchSnapshot()
  })

  it('standalone does NOT expose ajv (commented out, unlike conf-default)', () => {
    const c = loadStandalone()
    expect(c.ajv).toBeUndefined()
    expect(c.ajvHash).toBeUndefined()
  })

  it('standalone config is unaffected by MONGO_*/VULNDESK_*/DATABASE_URL env vars', () => {
    process.env.MONGO_HOST = 'ignored'
    process.env.VULNDESK_PORT = '1234'
    process.env.DATABASE_URL = 'ignored://x'
    const c = loadStandalone()
    expect(c.database).toBeUndefined()
    expect(c.serverPort).toBeUndefined()
    expect(c.homepage).toBe('https://github.com/SauceTaster/Vulndesk')
  })

  it('full conf-standalone object snapshot (year normalized)', () => {
    const c = loadStandalone()
    const normalized = {
      ...c,
      copyright: c.copyright.replace(/2017-\d{4}/, '2017-<YEAR>'),
    }
    expect(normalized).toMatchSnapshot()
  })
})

// ===========================================================================
// Cross-config differences worth locking (the two configs diverge on purpose)
// ===========================================================================
describe('conf-default vs conf-standalone :: divergences', () => {
  it('homepage differs: /home vs the GitHub repo URL', () => {
    const d = loadDefault()
    const s = loadStandalone()
    expect(d.homepage).toBe('/home')
    expect(s.homepage).toBe('https://github.com/SauceTaster/Vulndesk')
    expect(d.homepage).not.toBe(s.homepage)
  })

  it('basedir differs: "/" vs "./"', () => {
    const d = loadDefault()
    const s = loadStandalone()
    expect(d.basedir).toBe('/')
    expect(s.basedir).toBe('./')
  })

  it('sections differ: [cve,cve5,nvd] vs [cve5]', () => {
    const d = loadDefault()
    const s = loadStandalone()
    expect(d.sections).toEqual(['cve', 'cve5', 'nvd'])
    expect(s.sections).toEqual(['cve5'])
  })

  it('mitreURL casing differs: CVERecord vs cverecord', () => {
    const d = loadDefault()
    const s = loadStandalone()
    expect(d.mitreURL).toBe('https://www.cve.org/CVERecord?id=')
    expect(s.mitreURL).toBe('https://www.cve.org/cverecord?id=')
  })

  it('both copyright strings embed the same package name+version suffix', () => {
    const d = loadDefault()
    const s = loadStandalone()
    const suffix = `${pkg.name} ${pkg.version}`
    expect(d.copyright).toContain(suffix)
    expect(s.copyright).toContain(suffix)
  })
})
