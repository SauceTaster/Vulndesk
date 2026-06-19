import { describe, it, expect, beforeAll } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import vm from 'node:vm'
import { fileURLToPath } from 'node:url'

// CHARACTERIZATION (golden-master) tests for default/cve5/script.js.
//
// PURPOSE: lock down EXACTLY what the browser-oriented CVE5 helpers do TODAY so
// the upcoming refactors (Mongo->DocumentDB, Passport->BetterAuth, CSS->Tailwind,
// a frontend bundler, and consolidating CVE transforms into @vulndesk/core)
// surface ANY regression. We are NOT judging correctness — only recording
// behavior. Every expected value below was observed by RUNNING the real code.
//
// LOADING STRATEGY: script.js is a browser script, not a CommonJS/ESM module —
// it references window/document/fetch/localStorage/DOMParser/indexedDB at load
// and call time, and it leaks its top-level `function` declarations onto the
// global object. We therefore evaluate the REAL source via Node's `vm` module
// inside a sandbox that stubs only the globals the *pure* transforms touch.
// After evaluation, the pure functions are reachable as properties of the
// sandbox object. We never copy function bodies — the tests track the real file.
//
// FUNCTIONS COVERED (pure transforms): cveFixForVulndesk, cvssImport,
// fillCvssMetrics, versionStatusTable5, getProductAffected, getBestTitle,
// getProblemTypeString, getProductList, htmltoText, normalizeCPEtoken,
// resolveCpeTypeLetter, generateCpeApplicability, generateCpeApplicabilityNode,
// applyCpeNameOverride, findCpeNameOverride, normalizeCpeOverride* helpers,
// cpeOverrideListToMap, addRichText/addRichTextArray/addRichTextCVE.
//
// NOT COVERED (require live DOM / network / IndexedDB / editor singletons and
// cannot be exercised headlessly even with stubs): loadExamples, loadCVE,
// loadCVEFile, rejectRecord, draftEmail, autoText, autoCPE, clearCPE,
// setCPEstatus, the cpeOverride* DOM dialog functions, domhtml (needs DOMParser),
// hidepopups, and the additionalTabs render callbacks (need pugRender).

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const SCRIPT_PATH = path.resolve(__dirname, '../default/cve5/script.js')

const noop = () => {}

// Build a fresh sandbox + evaluate the real source. We return a fresh sandbox
// per call so tests that mutate localStorage / module-level vars stay isolated.
function loadScript() {
  const src = fs.readFileSync(SCRIPT_PATH, 'utf8')
  const localStore = {
    _d: {},
    getItem(k) {
      return Object.prototype.hasOwnProperty.call(this._d, k) ? this._d[k] : null
    },
    setItem(k, v) {
      this._d[k] = String(v)
    },
  }
  const docStub = {
    getElementById: () => null,
    querySelector: () => null,
    querySelectorAll: () => [],
    createElement: () => ({
      setAttribute: noop,
      appendChild: noop,
      querySelector: () => null,
      querySelectorAll: () => [],
      focus: noop,
      remove: noop,
      closest: () => null,
      innerHTML: '',
    }),
    addEventListener: noop,
    body: { innerText: '' },
  }
  const sandbox = {
    window: { vgExamples: {} },
    document: docStub,
    navigator: {},
    fetch: async () => ({ ok: true, json: async () => ({}), statusText: '' }),
    localStorage: localStore,
    console,
    setTimeout,
    clearTimeout,
    // a deterministic stub for the renderer used by addRichText -> cveFixForVulndesk
    cveRender: (args) => 'R:' + (args && args.t ? args.t : ''),
    // standard builtins
    Map, Set, Promise, Array, Object, JSON, String, Number, Boolean, RegExp, Math,
    Date, encodeURI, parseInt, parseFloat,
  }
  vm.createContext(sandbox)
  vm.runInContext(src, sandbox, { filename: 'default/cve5/script.js' })
  return sandbox
}

let S
beforeAll(() => {
  S = loadScript()
})

// ---------------------------------------------------------------------------
describe('module load / export shape (vm-evaluated browser script)', () => {
  it('evaluates the real source without throwing and exposes the pure helpers', () => {
    expect(typeof S.cveFixForVulndesk).toBe('function')
    expect(typeof S.cvssImport).toBe('function')
    expect(typeof S.fillCvssMetrics).toBe('function')
    expect(typeof S.versionStatusTable5).toBe('function')
    expect(typeof S.getProductAffected).toBe('function')
    expect(typeof S.getBestTitle).toBe('function')
    expect(typeof S.getProblemTypeString).toBe('function')
    expect(typeof S.getProductList).toBe('function')
    expect(typeof S.htmltoText).toBe('function')
    expect(typeof S.normalizeCPEtoken).toBe('function')
    expect(typeof S.resolveCpeTypeLetter).toBe('function')
    expect(typeof S.generateCpeApplicability).toBe('function')
    expect(typeof S.generateCpeApplicabilityNode).toBe('function')
    expect(typeof S.applyCpeNameOverride).toBe('function')
    expect(typeof S.findCpeNameOverride).toBe('function')
    expect(typeof S.normalizeCpeOverrideList).toBe('function')
    expect(typeof S.cpeOverrideListToMap).toBe('function')
    expect(typeof S.addRichTextCVE).toBe('function')
  })
})

// ---------------------------------------------------------------------------
describe('getProblemTypeString', () => {
  it('strips a leading "CWE-<n>" prefix and rewrites "Improper" -> "Insufficient"', () => {
    const o = {
      problemTypes: [{ descriptions: [{ lang: 'en', description: 'CWE-79 Improper Neutralization' }] }],
    }
    expect(S.getProblemTypeString(o)).toBe('Insufficient Neutralization')
  })

  it('joins multiple en descriptions with ", " and ignores non-en languages', () => {
    const o = {
      problemTypes: [
        { descriptions: [{ lang: 'en', description: 'CWE-79 Improper X' }, { lang: 'fr', description: 'ignore' }] },
        { descriptions: [{ lang: 'en', description: 'CWE-89 SQL' }] },
      ],
    }
    expect(S.getProblemTypeString(o)).toBe('Insufficient X, SQL')
  })

  it('returns empty string for empty problemTypes array', () => {
    expect(S.getProblemTypeString({ problemTypes: [] })).toBe('')
  })

  it('only rewrites the FIRST "Improper" occurrence (single regex replace, no /g)', () => {
    const o = {
      problemTypes: [{ descriptions: [{ lang: 'en', description: 'Improper Improper' }] }],
    }
    expect(S.getProblemTypeString(o)).toBe('Insufficient Improper')
  })

  it('skips descriptions whose text is falsy', () => {
    const o = {
      problemTypes: [{ descriptions: [{ lang: 'en', description: '' }, { lang: 'en', description: 'CWE-22 Path' }] }],
    }
    expect(S.getProblemTypeString(o)).toBe('Path')
  })
})

// ---------------------------------------------------------------------------
describe('getProductList', () => {
  it('joins product names with "; "', () => {
    expect(S.getProductList({ affected: [{ product: 'A' }, { product: 'B' }] })).toBe('A; B')
  })

  it('returns empty string for empty affected', () => {
    expect(S.getProductList({ affected: [] })).toBe('')
  })

  it('includes undefined entries as the literal output of join (missing product)', () => {
    // p.product is undefined -> pushed as undefined -> join renders empty between separators
    expect(S.getProductList({ affected: [{ product: 'A' }, {}] })).toBe('A; ')
  })
})

// ---------------------------------------------------------------------------
describe('getBestTitle', () => {
  it('returns providerMetadata.title verbatim when present', () => {
    expect(S.getBestTitle({ providerMetadata: { title: 'My Title' } })).toBe('My Title')
  })

  it('synthesizes "<problemTypes> vulnerability in <products>" when title absent', () => {
    const o = {
      providerMetadata: {},
      problemTypes: [{ descriptions: [{ lang: 'en', description: 'CWE-89 Improper SQL' }] }],
      affected: [{ product: 'X' }],
    }
    expect(S.getBestTitle(o)).toBe('Insufficient SQL vulnerability in X')
  })

  it('synthesizes with empty problem/product strings when both are empty', () => {
    const o = { providerMetadata: {}, problemTypes: [], affected: [] }
    expect(S.getBestTitle(o)).toBe(' vulnerability in ')
  })
})

// ---------------------------------------------------------------------------
describe('htmltoText', () => {
  it('strips tags and trims whitespace for a simple paragraph', () => {
    expect(S.htmltoText('<p>Hello <b>world</b></p>')).toBe('Hello world')
  })

  it('rewrites <a> links to " text url " form', () => {
    expect(S.htmltoText('<a href="http://x.com?q">link</a>')).toBe('link http://x.com')
  })

  it('removes <style> and <script> blocks entirely', () => {
    expect(S.htmltoText('<style>x{}</style>Hi<script>bad()</script>')).toBe('Hi')
  })

  it('converts </div> boundaries to double newlines', () => {
    expect(S.htmltoText('<div>a</div><div>b</div>')).toBe('a\n\nb')
  })

  it('converts <li> markers and </li> newlines', () => {
    expect(S.htmltoText('<ul><li>one</li><li>two</li></ul>')).toBe('*  one\n  *  two')
  })

  it('converts <br> and <br/> to single newlines', () => {
    expect(S.htmltoText('a<br>b<br/>c')).toBe('a\nb\nc')
  })

  it('returns undefined for an empty string input (falsy html guard)', () => {
    expect(S.htmltoText('')).toBeUndefined()
  })

  it('returns undefined for undefined input', () => {
    expect(S.htmltoText(undefined)).toBeUndefined()
  })

  it('locks the full transform of a richer fragment via snapshot', () => {
    const html =
      '<p>First paragraph with <a href="https://example.com/page?ref=1">a link</a>.</p>' +
      '<ul><li>item one</li><li>item two</li></ul>' +
      '<div>trailing</div>'
    expect(S.htmltoText(html)).toMatchSnapshot()
  })
})

// ---------------------------------------------------------------------------
describe('normalizeCPEtoken', () => {
  it('returns "*" for empty string', () => {
    expect(S.normalizeCPEtoken('')).toBe('*')
  })
  it('returns "*" for null', () => {
    expect(S.normalizeCPEtoken(null)).toBe('*')
  })
  it('returns "*" for undefined', () => {
    expect(S.normalizeCPEtoken(undefined)).toBe('*')
  })
  it('lowercases, trims, and collapses non-cpe chars to a single underscore', () => {
    expect(S.normalizeCPEtoken('  Foo Bar!! ')).toBe('foo_bar_')
  })
  it('preserves allowed cpe characters (digits, _, -, ., *)', () => {
    expect(S.normalizeCPEtoken('1.2.3-rc_1*')).toBe('1.2.3-rc_1*')
  })
})

// ---------------------------------------------------------------------------
describe('resolveCpeTypeLetter', () => {
  it('maps app -> a', () => expect(S.resolveCpeTypeLetter('app')).toBe('a'))
  it('maps os -> o', () => expect(S.resolveCpeTypeLetter('os')).toBe('o'))
  it('maps hardware -> h', () => expect(S.resolveCpeTypeLetter('hardware')).toBe('h'))
  it('returns "" for unknown values', () => expect(S.resolveCpeTypeLetter('zz')).toBe(''))
  it('returns "" for empty/undefined', () => {
    expect(S.resolveCpeTypeLetter('')).toBe('')
    expect(S.resolveCpeTypeLetter(undefined)).toBe('')
  })
})

// ---------------------------------------------------------------------------
describe('normalizeCpeOverrideType / normalizeCpeOverrideKey', () => {
  it('accepts only app/os/hardware, otherwise empty string', () => {
    expect(S.normalizeCpeOverrideType('app')).toBe('app')
    expect(S.normalizeCpeOverrideType('os')).toBe('os')
    expect(S.normalizeCpeOverrideType('hardware')).toBe('hardware')
    expect(S.normalizeCpeOverrideType('xx')).toBe('')
    expect(S.normalizeCpeOverrideType('')).toBe('')
    expect(S.normalizeCpeOverrideType(undefined)).toBe('')
  })

  it('key normalization trims + lowercases', () => {
    expect(S.normalizeCpeOverrideKey('  FooBar ')).toBe('foobar')
  })

  it('key normalization returns "" for falsy input', () => {
    expect(S.normalizeCpeOverrideKey('')).toBe('')
    expect(S.normalizeCpeOverrideKey(null)).toBe('')
    expect(S.normalizeCpeOverrideKey(undefined)).toBe('')
  })
})

// ---------------------------------------------------------------------------
describe('normalizeCpeOverrideList', () => {
  it('dedupes by lowercased normalName keeping the LAST occurrence, drops entries without normalName, normalizes type', () => {
    const list = [
      { normalName: 'A', cpeName: 'a1', cpeType: 'app' },
      { normalName: 'a', cpeName: 'a2', cpeType: 'os' }, // same key as 'A' -> last wins
      { cpeName: 'noname' }, // dropped (no normalName)
      { normalName: 'B', cpeType: 'bad' }, // bad type -> ''
    ]
    expect(S.normalizeCpeOverrideList(list)).toEqual([
      { normalName: 'a', cpeName: 'a2', cpeType: 'os' },
      { normalName: 'B', cpeName: '', cpeType: '' },
    ])
  })

  it('returns [] for a non-array argument', () => {
    expect(S.normalizeCpeOverrideList(null)).toEqual([])
    expect(S.normalizeCpeOverrideList(undefined)).toEqual([])
    expect(S.normalizeCpeOverrideList('nope')).toEqual([])
  })

  it('returns [] for an empty array', () => {
    expect(S.normalizeCpeOverrideList([])).toEqual([])
  })

  it('trims normalName/cpeName values', () => {
    expect(S.normalizeCpeOverrideList([{ normalName: '  Foo  ', cpeName: '  bar  ', cpeType: 'app' }])).toEqual([
      { normalName: 'Foo', cpeName: 'bar', cpeType: 'app' },
    ])
  })

  it('accepts a Map and converts via its values()', () => {
    const m = new Map([['k', { normalName: 'Z', cpeName: 'z', cpeType: 'os' }]])
    expect(S.normalizeCpeOverrideList(m)).toEqual([{ normalName: 'Z', cpeName: 'z', cpeType: 'os' }])
  })
})

// ---------------------------------------------------------------------------
describe('cpeOverrideListToMap', () => {
  it('keys by lowercased normalName', () => {
    const m = S.cpeOverrideListToMap([{ normalName: 'Foo', cpeName: 'foo' }])
    expect(m instanceof Map).toBe(true)
    expect(m.has('foo')).toBe(true)
    expect(m.get('foo')).toEqual({ normalName: 'Foo', cpeName: 'foo' })
  })

  it('returns an empty Map for non-array input', () => {
    const m = S.cpeOverrideListToMap(null)
    expect(m instanceof Map).toBe(true)
    expect(m.size).toBe(0)
  })

  it('skips entries without normalName', () => {
    const m = S.cpeOverrideListToMap([{ cpeName: 'x' }, { normalName: 'Y' }])
    expect([...m.keys()]).toEqual(['y'])
  })
})

// ---------------------------------------------------------------------------
describe('findCpeNameOverride', () => {
  const arr = [{ normalName: 'Acme', cpeName: 'acme_inc', cpeType: 'app' }]

  it('finds a case-insensitive match in an array', () => {
    expect(S.findCpeNameOverride('ACME', arr)).toEqual({ normalName: 'Acme', cpeName: 'acme_inc', cpeType: 'app' })
  })

  it('returns null when no entry matches', () => {
    expect(S.findCpeNameOverride('Nope', arr)).toBeNull()
  })

  it('returns null for empty name', () => {
    expect(S.findCpeNameOverride('', arr)).toBeNull()
  })

  it('returns null for null name', () => {
    expect(S.findCpeNameOverride(null, arr)).toBeNull()
  })

  it('looks up directly when overrides is a Map (keyed by normalized name)', () => {
    const m = S.cpeOverrideListToMap(arr)
    expect(S.findCpeNameOverride('acme', m)).toEqual(arr[0])
    expect(S.findCpeNameOverride('missing', m)).toBeNull()
  })

  it('returns null when overrides is neither Map nor array', () => {
    expect(S.findCpeNameOverride('Acme', 'bogus')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
describe('applyCpeNameOverride', () => {
  it('defaults to {name, type:"a"} when no override matches', () => {
    expect(S.applyCpeNameOverride('Foo', null)).toEqual({ name: 'Foo', type: 'a' })
  })

  it('defaults type "a" for empty name with empty overrides', () => {
    expect(S.applyCpeNameOverride('', [])).toEqual({ name: '', type: 'a' })
  })

  it('uses override cpeName + cpeType when both present', () => {
    const arr = [{ normalName: 'Acme', cpeName: 'acme_inc', cpeType: 'app' }]
    expect(S.applyCpeNameOverride('Acme', arr)).toEqual({ name: 'acme_inc', type: 'app' })
  })

  it('falls back to original name and type "*" when override has blank cpeName/cpeType', () => {
    const arr = [{ normalName: 'Acme', cpeName: '', cpeType: '' }]
    expect(S.applyCpeNameOverride('Acme', arr)).toEqual({ name: 'Acme', type: '*' })
  })
})

// ---------------------------------------------------------------------------
describe('cvssImport', () => {
  it('returns null/empty inputs unchanged', () => {
    expect(S.cvssImport(null)).toBeNull()
    expect(S.cvssImport({})).toEqual({})
  })

  it('upgrades cvssV3_0 to cvssV3_1, rewrites vector prefix, adds format + GENERAL scenario, and fills metrics', () => {
    const j = {
      containers: {
        cna: {
          metrics: [{ cvssV3_0: { vectorString: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', version: '3.0' } }],
        },
      },
    }
    const out = S.cvssImport(j)
    const m = out.containers.cna.metrics[0]
    expect(m.cvssV3_0).toBeUndefined()
    expect(m.format).toBe('CVSS')
    expect(m.scenarios).toEqual([{ lang: 'en', value: 'GENERAL' }])
    expect(m.cvssV3_1.version).toBe('3.1')
    expect(m.cvssV3_1.vectorString).toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')
    expect(m.cvssV3_1.attackVector).toBe('NETWORK')
    expect(out).toMatchSnapshot()
  })

  it('processes both cna and adp metrics and fills a v2.0 vector', () => {
    const j = {
      containers: {
        cna: { metrics: [{ format: 'CVSS', cvssV3_1: { vectorString: 'CVSS:3.1/AV:N', version: '3.1' } }] },
        adp: [{ metrics: [{ cvssV2_0: { vectorString: 'AV:N/AC:L/Au:N/C:C/I:C/A:C', version: '2.0' } }] }],
      },
    }
    const out = S.cvssImport(j)
    const adpMetric = out.containers.adp[0].metrics[0]
    expect(adpMetric.format).toBe('CVSS')
    expect(adpMetric.scenarios).toEqual([{ lang: 'en', value: 'GENERAL' }])
    expect(adpMetric.cvssV2_0.accessVector).toBe('NETWORK')
    expect(adpMetric.cvssV2_0.authentication).toBe('NONE')
    expect(out).toMatchSnapshot()
  })

  it('does not set format when no recognized cvss object is present, but still adds the scenario', () => {
    const j = { containers: { cna: { metrics: [{ other: { someScore: 1 } }] } } }
    const out = S.cvssImport(j)
    const m = out.containers.cna.metrics[0]
    expect(m.format).toBeUndefined()
    expect(m.scenarios).toEqual([{ lang: 'en', value: 'GENERAL' }])
  })

  it('preserves a pre-existing scenarios array', () => {
    const j = {
      containers: {
        cna: { metrics: [{ cvssV4_0: { vectorString: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N' }, scenarios: [{ lang: 'en', value: 'CUSTOM' }] }] },
      },
    }
    const out = S.cvssImport(j)
    expect(out.containers.cna.metrics[0].scenarios).toEqual([{ lang: 'en', value: 'CUSTOM' }])
    expect(out.containers.cna.metrics[0].format).toBe('CVSS')
  })

  it('returns input unchanged when cna has no metrics array', () => {
    const j = { containers: { cna: {} } }
    expect(S.cvssImport(j)).toEqual({ containers: { cna: {} } })
  })
})

// ---------------------------------------------------------------------------
describe('fillCvssMetrics', () => {
  it('fills v3.1 base metrics from the vector string', () => {
    const c = { version: '3.1', vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }
    expect(S.fillCvssMetrics(c)).toEqual({
      version: '3.1',
      vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      attackVector: 'NETWORK',
      attackComplexity: 'LOW',
      privilegesRequired: 'NONE',
      userInteraction: 'NONE',
      scope: 'UNCHANGED',
      confidentialityImpact: 'HIGH',
      integrityImpact: 'HIGH',
      availabilityImpact: 'HIGH',
    })
  })

  it('fills v2.0 base metrics with worst-case values when no vector is present', () => {
    const c = { version: '2.0', vectorString: '' }
    expect(S.fillCvssMetrics(c)).toEqual({
      version: '2.0',
      vectorString: '',
      accessVector: 'NETWORK',
      accessComplexity: 'LOW',
      authentication: 'NONE',
      confidentialityImpact: 'COMPLETE',
      integrityImpact: 'COMPLETE',
      availabilityImpact: 'COMPLETE',
    })
  })

  it('fills a full v4.0 record (base from vector, threat + supplemental -> NOT_DEFINED) via snapshot', () => {
    const c = { version: '4.0', vectorString: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N' }
    expect(S.fillCvssMetrics(c)).toMatchSnapshot()
  })

  it('infers v3.1 from a "CVSS:3.1" vector prefix when version is absent', () => {
    const out = S.fillCvssMetrics({ vectorString: 'CVSS:3.1/AV:P' })
    expect(out.version).toBe('3.1')
    expect(out.attackVector).toBe('PHYSICAL')
    // unspecified base metrics filled with worst-case
    expect(out.scope).toBe('CHANGED')
    expect(out.confidentialityImpact).toBe('HIGH')
  })

  it('heuristically picks v3.1 when "scope" key is present but no version/vector', () => {
    const out = S.fillCvssMetrics({ scope: 'UNCHANGED' })
    expect(out.version).toBe('3.1')
    expect(out.scope).toBe('UNCHANGED') // preserved (already present)
    expect(out.attackVector).toBe('NETWORK')
  })

  it('heuristically picks v4.0 when "attackRequirements" key is present', () => {
    const out = S.fillCvssMetrics({ attackRequirements: 'NONE' })
    expect(out.version).toBe('4.0')
    expect(out.exploitMaturity).toBe('NOT_DEFINED')
    expect(out.providerUrgency).toBe('NOT_DEFINED')
  })

  it('does NOT mutate version "3.0" on the object even though it normalizes internally to 3.1', () => {
    // version stays "3.0" because it is already present (not missing), but 3.1 base props are filled
    const out = S.fillCvssMetrics({ version: '3.0', vectorString: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' })
    expect(out.version).toBe('3.0')
    expect(out.attackVector).toBe('NETWORK')
    expect(out.scope).toBe('UNCHANGED')
  })

  it('mutates and returns the SAME object reference', () => {
    const c = { version: '2.0' }
    expect(S.fillCvssMetrics(c)).toBe(c)
  })

  it('falls back to v3.1 filling for an unknown version string', () => {
    const out = S.fillCvssMetrics({ version: '9.9', vectorString: '' })
    expect(out.version).toBe('9.9')
    expect(out.attackVector).toBe('NETWORK')
    expect(out.scope).toBe('CHANGED')
  })
})

// ---------------------------------------------------------------------------
describe('versionStatusTable5', () => {
  it('builds a simple "from X before Y" affected range', () => {
    const affected = [
      { vendor: 'V', product: 'P', defaultStatus: 'unknown', versions: [{ version: '1.0', lessThan: '2.0', status: 'affected' }] },
    ]
    expect(S.versionStatusTable5(affected)).toMatchSnapshot()
  })

  it('returns empty groups/vals and all-false show flags for empty input', () => {
    expect(S.versionStatusTable5([])).toEqual({
      groups: {},
      vals: {},
      show: { platforms: false, modules: false, affected: false, unaffected: false, unknown: false },
    })
  })

  it('handles platforms, modules, changes, and lessThanOrEqual via snapshot', () => {
    const affected = [
      {
        vendor: 'Acme',
        product: 'Thing',
        platforms: ['Linux', 'Win'],
        modules: ['m1'],
        defaultStatus: 'unaffected',
        versions: [
          { version: '1.0', lessThanOrEqual: '1.9', status: 'affected', changes: [{ at: '1.5', status: 'unaffected' }] },
          { version: '2.0', status: 'unaffected' },
        ],
      },
    ]
    expect(S.versionStatusTable5(affected)).toMatchSnapshot()
  })

  it('treats version "unspecified" + lessThan "*" as an empty range string', () => {
    const affected = [{ product: 'P', versions: [{ version: 'unspecified', lessThan: '*', status: 'affected' }] }]
    const out = S.versionStatusTable5(affected)
    const key = Object.keys(out.vals)[0]
    expect(out.vals[key][0].affected).toEqual([''])
    expect(out.show.affected).toBe(true)
  })

  it('captures packageName fallback and "others" (collectionURL/repo/programFiles/programRoutines)', () => {
    const affected = [
      {
        packageName: 'pkg',
        collectionURL: 'http://c',
        repo: 'http://r',
        programFiles: ['f'],
        programRoutines: [{ name: 'x' }],
        versions: [{ version: '3.0', status: 'unknown' }],
      },
    ]
    expect(S.versionStatusTable5(affected)).toMatchSnapshot()
  })

  it('sets the show flag for a product-level status even with no versions', () => {
    const affected = [{ product: 'P', status: 'affected' }]
    const out = S.versionStatusTable5(affected)
    expect(out.show.affected).toBe(true)
    // no versions -> no vals entry for the group
    expect(Object.keys(out.vals).length).toBe(0)
    expect(Object.keys(out.groups).length).toBe(1)
  })
})

// ---------------------------------------------------------------------------
describe('getProductAffected', () => {
  it('emits "This issue affects ..." with sorted versions and platforms, ignoring "!" / "?" versions', () => {
    const cve = {
      affected: {
        vendors: [
          {
            products: [
              {
                product_name: 'Prod',
                versions: [
                  { version_name: '1.0', version_affected: '=', platform: 'x86,arm' },
                  { version_name: '0.9', version_affected: '!', platform: '' }, // excluded by "!"
                ],
              },
            ],
          },
        ],
      },
    }
    expect(S.getProductAffected(cve)).toBe('This issue affects Prod 1.0. Affected platforms: arm, x86.')
  })

  it('drops platforms when a version targets platform "all"', () => {
    const cve = {
      affected: {
        vendors: [
          {
            products: [
              {
                product_name: 'P',
                versions: [
                  { version_name: '1.0', version_affected: '=', platform: 'all' },
                  { version_name: '2.0', version_affected: '=', platform: 'linux' },
                ],
              },
            ],
          },
        ],
      },
    }
    expect(S.getProductAffected(cve)).toBe('This issue affects P 1.0, 2.0.')
  })

  it('joins multiple vendors with the default Array.join() comma', () => {
    const cve = {
      affected: {
        vendors: [
          { products: [{ product_name: 'A', versions: [{ version_name: '1', version_affected: '=', platform: '' }] }] },
          { products: [{ product_name: 'B', versions: [{ version_name: '2', version_affected: '=', platform: '' }] }] },
        ],
      },
    }
    expect(S.getProductAffected(cve)).toBe('This issue affects A 1.,This issue affects B 2.')
  })
})

// ---------------------------------------------------------------------------
describe('generateCpeApplicability / generateCpeApplicabilityNode', () => {
  it('returns [] when autoCPEChk is not enabled in localStorage', () => {
    const local = loadScript()
    local.localStorage.setItem('autoCPEChk', 'false')
    const affected = [{ vendor: 'V', product: 'P', versions: [{ version: '1.0', lessThan: '2.0', status: 'affected' }] }]
    expect(local.generateCpeApplicability(affected, new Map())).toEqual([])
  })

  it('returns [] for empty/missing affected even when enabled', () => {
    const local = loadScript()
    local.localStorage.setItem('autoCPEChk', 'true')
    expect(local.generateCpeApplicability([], new Map())).toEqual([])
    expect(local.generateCpeApplicability(null, new Map())).toEqual([])
  })

  it('wraps nodes in an OR operator and emits a versionEndExcluding match for lessThan', () => {
    const local = loadScript()
    local.localStorage.setItem('autoCPEChk', 'true')
    const affected = [{ vendor: 'Acme', product: 'Web App', versions: [{ version: '1.0', lessThan: '2.0', status: 'affected' }] }]
    expect(local.generateCpeApplicability(affected, new Map())).toEqual([
      {
        operator: 'OR',
        nodes: [
          {
            operator: 'OR',
            negate: false,
            cpeMatch: [
              {
                vulnerable: true,
                criteria: 'cpe:2.3:a:acme:web_app:*:*:*:*:*:*:*:*',
                versionStartIncluding: '1.0',
                versionEndExcluding: '2.0',
              },
            ],
          },
        ],
      },
    ])
  })

  it('node emits lessThanOrEqual, plain-version, and platform-token matches via snapshot', () => {
    const local = loadScript()
    local.localStorage.setItem('autoCPEChk', 'true')
    const ap = {
      vendor: 'V',
      product: 'P',
      platforms: ['Linux'],
      versions: [
        { version: '1.0', lessThanOrEqual: '1.5', status: 'unaffected' },
        { version: '2.0', status: 'affected' },
      ],
    }
    expect(local.generateCpeApplicabilityNode(ap, new Map())).toMatchSnapshot()
  })

  it('node returns null when no versions yield matches (status not affected/unaffected)', () => {
    const local = loadScript()
    local.localStorage.setItem('autoCPEChk', 'true')
    const ap = { vendor: 'V', product: 'P', versions: [{ version: '1.0', status: 'unknown' }] }
    expect(local.generateCpeApplicabilityNode(ap, new Map())).toBeNull()
  })

  it('applies vendor/product overrides to the generated cpe criteria and type letter', () => {
    const local = loadScript()
    local.localStorage.setItem('autoCPEChk', 'true')
    const overrides = local.cpeOverrideListToMap([
      { normalName: 'Acme', cpeName: 'acme_corp', cpeType: 'os' },
      { normalName: 'Web App', cpeName: 'webapp', cpeType: '' },
    ])
    const ap = { vendor: 'Acme', product: 'Web App', versions: [{ version: '3.0', status: 'affected' }] }
    const node = local.generateCpeApplicabilityNode(ap, overrides)
    // product override has no type -> falls back to vendor's 'os' -> 'o'
    expect(node.cpeMatch[0].criteria).toBe('cpe:2.3:o:acme_corp:webapp:3.0:*:*:*:*:*:*:*')
    expect(node.cpeMatch[0].vulnerable).toBe(true)
  })
})

// ---------------------------------------------------------------------------
describe('addRichText / addRichTextArray / addRichTextCVE', () => {
  it('adds a supportingMedia entry rendered from the value', () => {
    const d = { value: 'Hello' }
    const out = S.addRichText(d)
    expect(out.supportingMedia).toEqual([{ type: 'text/html', base64: false, value: 'R:Hello' }])
  })

  it('leaves an existing supportingMedia untouched', () => {
    const d = { value: 'X', supportingMedia: [{ type: 'text/html', value: 'EXISTING' }] }
    const out = S.addRichText(d)
    expect(out.supportingMedia).toEqual([{ type: 'text/html', value: 'EXISTING' }])
  })

  it('renders empty html when value is absent (still creates supportingMedia)', () => {
    const out = S.addRichText({})
    expect(out.supportingMedia).toEqual([{ type: 'text/html', base64: false, value: '' }])
  })

  it('addRichTextArray processes every element', () => {
    const arr = [{ value: 'a' }, { value: 'b' }]
    S.addRichTextArray(arr)
    expect(arr[0].supportingMedia[0].value).toBe('R:a')
    expect(arr[1].supportingMedia[0].value).toBe('R:b')
  })

  it('addRichTextArray is a no-op for empty/falsy arrays', () => {
    expect(() => S.addRichTextArray([])).not.toThrow()
    expect(() => S.addRichTextArray(null)).not.toThrow()
  })

  it('addRichTextCVE processes only the recognized html fields under containers.cna', () => {
    const j = {
      containers: {
        cna: {
          descriptions: [{ value: 'desc' }],
          solutions: [{ value: 'sol' }],
          // unrelated field ignored
          title: 'ignored',
        },
      },
    }
    const out = S.addRichTextCVE(j)
    expect(out.containers.cna.descriptions[0].supportingMedia[0].value).toBe('R:desc')
    expect(out.containers.cna.solutions[0].supportingMedia[0].value).toBe('R:sol')
  })

  it('addRichTextCVE returns input unchanged when there is no cna', () => {
    expect(S.addRichTextCVE({ containers: {} })).toEqual({ containers: {} })
    expect(S.addRichTextCVE({})).toEqual({})
  })
})

// ---------------------------------------------------------------------------
describe('cveFixForVulndesk', () => {
  it('adds rich text, runs cvssImport, and defaults problemTypes/impacts/metrics to []', () => {
    const j = { containers: { cna: { descriptions: [{ lang: 'en', value: 'Hello' }] } } }
    const out = S.cveFixForVulndesk(j)
    expect(out.containers.cna.problemTypes).toEqual([])
    expect(out.containers.cna.impacts).toEqual([])
    expect(out.containers.cna.metrics).toEqual([])
    expect(out.containers.cna.descriptions[0].supportingMedia).toEqual([
      { type: 'text/html', base64: false, value: 'R:Hello' },
    ])
    expect(out).toMatchSnapshot()
  })

  it('returns the SAME object reference (mutates in place)', () => {
    const j = { containers: { cna: {} } }
    expect(S.cveFixForVulndesk(j)).toBe(j)
  })

  it('does not add cna defaults when containers/cna are absent', () => {
    expect(S.cveFixForVulndesk({})).toEqual({})
    expect(S.cveFixForVulndesk({ containers: {} })).toEqual({ containers: {} })
  })

  it('preserves existing problemTypes/impacts/metrics arrays', () => {
    const j = {
      containers: {
        cna: { problemTypes: [{ x: 1 }], impacts: [{ y: 2 }], metrics: [{ z: 3 }] },
      },
    }
    const out = S.cveFixForVulndesk(j)
    expect(out.containers.cna.problemTypes).toEqual([{ x: 1 }])
    expect(out.containers.cna.impacts).toEqual([{ y: 2 }])
    // metrics with no recognized cvss object still gets the GENERAL scenario added
    expect(out.containers.cna.metrics).toEqual([{ z: 3, scenarios: [{ lang: 'en', value: 'GENERAL' }] }])
  })

  it('upgrades a v3.0 metric while applying the full fix via snapshot', () => {
    const j = {
      containers: {
        cna: {
          descriptions: [{ lang: 'en', value: 'A flaw' }],
          metrics: [{ cvssV3_0: { vectorString: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', version: '3.0' } }],
        },
      },
    }
    expect(S.cveFixForVulndesk(j)).toMatchSnapshot()
  })
})
