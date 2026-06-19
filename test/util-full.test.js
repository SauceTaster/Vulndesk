import { describe, it, expect } from 'vitest'

// The CVE transform layer (public/js/util.js). This file is the highest-value
// characterization target: it is required server-side (routes/onedoc.js) and
// will be consolidated into @vulndesk/core. These tests lock CURRENT behavior
// (including quirks/bugs) so the upcoming refactors surface any regression.
//
// The default export is the `textUtil` object. In Node, the module also tacks
// the otherwise file-local helpers (orderKeys, cloneJSON) and the `cvssjs`
// object onto the export — so they are reachable as textUtil.orderKeys etc.
//
// NOT COVERED HERE (require a real DOM/browser, intentionally skipped):
//   - getDocuments  (uses global fetch / network)
//   - copyToClipboard (uses navigator.clipboard; also not exported)
//   - jsonView's array branch with >=1 element recurses on the whole array and
//     throws RangeError (characterized below as a throw, not skipped).
//
// NOT DUPLICATED (already covered by test/cve-transforms.test.js): the basic
// happy-path of reduceJSON / getMITREJSON / getPR / getAffectedProductString /
// fileSize. Here we go deep on EVERYTHING ELSE and on the edge cases of those.
import textUtil from '../public/js/util.js'

// -------------------------------------------------------------------------
// jsonView
// -------------------------------------------------------------------------
describe('jsonView', () => {
  it('returns scalars unchanged (string, number, null)', () => {
    expect(textUtil.jsonView('hello')).toBe('hello')
    expect(textUtil.jsonView(42)).toBe(42)
    expect(textUtil.jsonView(null)).toBe(null)
  })

  it('renders a flat object as nested <div> blocks', () => {
    expect(textUtil.jsonView({ a: 1, b: 'x' })).toBe(
      '<div><div><b>a</b>: 1</div><div><b>b</b>: x</div></div>'
    )
  })

  it('renders a nested object recursively', () => {
    expect(textUtil.jsonView({ a: { b: 2 } })).toBe(
      '<div><div><b>a</b>: <div><div><b>b</b>: 2</div></div></div></div>'
    )
  })

  it('renders an empty object as an empty <div>', () => {
    expect(textUtil.jsonView({})).toBe('<div></div>')
  })

  it('renders an empty array as an empty <table>', () => {
    expect(textUtil.jsonView([])).toBe('<table></table>')
  })

  it('CURRENT BEHAVIOR: a non-empty array recurses on the whole array and overflows the stack', () => {
    // Bug locked as characterization: jsonView passes `obj` (the array) to
    // this.jsonView instead of the element, so any array with >=1 item never
    // terminates. Refactors must not silently "fix" this without noticing.
    expect(() => textUtil.jsonView([1])).toThrow(RangeError)
  })

  it('snapshot of a representative object structure', () => {
    expect(textUtil.jsonView({ id: 'CVE-1', meta: { lang: 'eng' } })).toMatchSnapshot()
  })
})

// -------------------------------------------------------------------------
// mergeJSON
// -------------------------------------------------------------------------
describe('mergeJSON', () => {
  it('deep-merges nested objects, adding new keys', () => {
    expect(textUtil.mergeJSON({ a: 1, b: { c: 2 } }, { b: { d: 3 }, e: 4 })).toEqual({
      a: 1,
      b: { c: 2, d: 3 },
      e: 4,
    })
  })

  it('overwrites a scalar with a scalar', () => {
    expect(textUtil.mergeJSON({ a: 1 }, { a: 2 })).toEqual({ a: 2 })
  })

  it('overwrites an object target with a scalar add', () => {
    expect(textUtil.mergeJSON({ a: { x: 1 } }, { a: 5 })).toEqual({ a: 5 })
  })

  it('overwrites a scalar target with an object add', () => {
    expect(textUtil.mergeJSON({ a: 5 }, { a: { x: 1 } })).toEqual({ a: { x: 1 } })
  })

  it('merging two empty objects yields an empty object', () => {
    expect(textUtil.mergeJSON({}, {})).toEqual({})
  })

  it('isObject treats an empty target object as NOT-an-object, so add replaces it', () => {
    // target[key] is {} (no own keys) -> isObject false -> overwrite branch.
    expect(textUtil.mergeJSON({ a: {} }, { a: { b: 1 } })).toEqual({ a: { b: 1 } })
  })

  it('an empty add object overwrites a populated target value', () => {
    expect(textUtil.mergeJSON({ a: { b: 1 } }, { a: {} })).toEqual({ a: {} })
  })

  it('guards against __proto__ pollution (prototype is not modified)', () => {
    const target = {}
    textUtil.mergeJSON(target, JSON.parse('{"__proto__":{"polluted":1}}'))
    expect(({}).polluted).toBeUndefined()
    expect(target).toEqual({})
  })

  it('skips the constructor key but keeps sibling keys', () => {
    const out = textUtil.mergeJSON({}, { constructor: { x: 1 }, normal: 9 })
    expect(Object.prototype.hasOwnProperty.call(out, 'constructor')).toBe(false)
    expect(out.normal).toBe(9)
  })

  it('returns the same target reference (mutating merge)', () => {
    const base = { a: 1 }
    const out = textUtil.mergeJSON(base, { b: 2 })
    expect(out).toBe(base)
    expect(base).toEqual({ a: 1, b: 2 })
  })
})

// -------------------------------------------------------------------------
// deep_value
// -------------------------------------------------------------------------
describe('deep_value', () => {
  it('resolves a deep dotted path to a leaf', () => {
    expect(textUtil.deep_value({ a: { b: { c: 42 } } }, 'a.b.c')).toBe(42)
  })

  it('resolves a partial path to a sub-object', () => {
    expect(textUtil.deep_value({ a: { b: { c: 42 } } }, 'a.b')).toEqual({ c: 42 })
  })

  it('returns undefined when the path runs past a scalar', () => {
    expect(textUtil.deep_value({ a: 1 }, 'a.b.c')).toBeUndefined()
  })

  it('returns undefined for a missing top-level key', () => {
    expect(textUtil.deep_value({ a: 1 }, 'x')).toBeUndefined()
  })

  it('resolves a single-segment path', () => {
    expect(textUtil.deep_value({ a: 1 }, 'a')).toBe(1)
  })

  it('indexes into arrays via numeric path segments', () => {
    expect(textUtil.deep_value({ a: [10, 20] }, 'a.1')).toBe(20)
  })
})

// -------------------------------------------------------------------------
// cloneJSON
// -------------------------------------------------------------------------
describe('cloneJSON', () => {
  it('passes through null and undefined unchanged', () => {
    expect(textUtil.cloneJSON(null)).toBe(null)
    expect(textUtil.cloneJSON(undefined)).toBe(undefined)
  })

  it('passes through primitives unchanged', () => {
    expect(textUtil.cloneJSON('')).toBe('')
    expect(textUtil.cloneJSON('hi')).toBe('hi')
    expect(textUtil.cloneJSON(5)).toBe(5)
    expect(textUtil.cloneJSON(true)).toBe(true)
  })

  it('CURRENT BEHAVIOR: an empty array clones to null', () => {
    expect(textUtil.cloneJSON([])).toBe(null)
  })

  it('clones a populated array element-by-element', () => {
    expect(textUtil.cloneJSON([1, 2, 3])).toEqual([1, 2, 3])
    expect(textUtil.cloneJSON([[1], [2]])).toEqual([[1], [2]])
  })

  it('drops empty-string and null object values', () => {
    expect(textUtil.cloneJSON({ a: 1, b: '', c: null, d: 'x' })).toEqual({ a: 1, d: 'x' })
  })

  it('drops a key whose value is an empty array (clones to null then dropped)', () => {
    expect(textUtil.cloneJSON({ a: 1, b: [] })).toEqual({ a: 1 })
  })

  it('preserves falsy-but-meaningful values 0 and false', () => {
    expect(textUtil.cloneJSON({ a: 0, b: false })).toEqual({ a: 0, b: false })
  })

  it('produces a deeply independent copy (mutating the clone does not affect the source)', () => {
    const src = { a: { b: [1, 2] } }
    const clone = textUtil.cloneJSON(src)
    clone.a.b.push(3)
    expect(src).toEqual({ a: { b: [1, 2] } })
    expect(clone).toEqual({ a: { b: [1, 2, 3] } })
    expect(clone).not.toBe(src)
    expect(clone.a).not.toBe(src.a)
  })
})

// -------------------------------------------------------------------------
// orderKeys
// -------------------------------------------------------------------------
describe('orderKeys', () => {
  it('sorts top-level keys alphabetically', () => {
    const out = textUtil.orderKeys({ c: 1, a: 2, b: 3 })
    expect(Object.keys(out)).toEqual(['a', 'b', 'c'])
    expect(out).toEqual({ a: 2, b: 3, c: 1 })
  })

  it('sorts nested object keys recursively', () => {
    const out = textUtil.orderKeys({ z: { y: 1, x: 2 }, a: { c: 3, b: 4 } })
    expect(Object.keys(out)).toEqual(['a', 'z'])
    expect(Object.keys(out.a)).toEqual(['b', 'c'])
    expect(Object.keys(out.z)).toEqual(['x', 'y'])
  })

  it('mutates in place and returns the same reference', () => {
    const o = { b: 1, a: 2 }
    const r = textUtil.orderKeys(o)
    expect(r).toBe(o)
    expect(Object.keys(r)).toEqual(['a', 'b'])
  })

  it('recurses into objects inside arrays (arrays are Objects)', () => {
    const out = textUtil.orderKeys({ list: [{ b: 1, a: 2 }] })
    expect(Object.keys(out.list[0])).toEqual(['a', 'b'])
    expect(out.list[0]).toEqual({ a: 2, b: 1 })
  })
})

// -------------------------------------------------------------------------
// timeSince  (uses internal `new Date()`; we pass fixed offsets from "now"
// so the relative interval is deterministic regardless of when tests run).
// -------------------------------------------------------------------------
describe('timeSince', () => {
  const now = Date.now()
  const ago = (sec) => new Date(now - sec * 1000)

  it('reports seconds for very recent dates', () => {
    expect(textUtil.timeSince(new Date(now))).toBe('0 seconds')
    expect(textUtil.timeSince(ago(1))).toBe('1 seconds')
    expect(textUtil.timeSince(ago(59))).toBe('59 seconds')
  })

  it('CURRENT BEHAVIOR: the > 1 thresholds make 1 unit fall through to the smaller unit', () => {
    // 119s => minutes interval = 1, which is NOT > 1, so it reports seconds.
    expect(textUtil.timeSince(ago(119))).toBe('119 seconds')
    // 3600s => hours interval = 1 (not > 1) so it reports minutes (=60).
    expect(textUtil.timeSince(ago(3600))).toBe('60 minutes')
  })

  it('reports minutes once 2+ minutes elapse', () => {
    expect(textUtil.timeSince(ago(120))).toBe('2 minutes')
  })

  it('reports hours, days, months and years at their 2-unit boundaries', () => {
    expect(textUtil.timeSince(ago(7200))).toBe('2 hours')
    expect(textUtil.timeSince(ago(2 * 86400))).toBe('2 days')
    expect(textUtil.timeSince(ago(2 * 2592000))).toBe('2 months')
    expect(textUtil.timeSince(ago(2 * 31536000))).toBe('2 years')
  })

  it('CURRENT BEHAVIOR: a future date yields negative seconds', () => {
    expect(textUtil.timeSince(new Date(now + 10000))).toBe('-10 seconds')
  })
})

// -------------------------------------------------------------------------
// nextPatchDay  (returns a Date for the 2nd <weekday> of the next quarter
// boundary month). We assert local Y/M/D/weekday components to stay
// timezone-independent.
// -------------------------------------------------------------------------
describe('nextPatchDay', () => {
  const comp = (d) => [d.getFullYear(), d.getMonth(), d.getDate(), d.getDay()]

  it('returns a Date instance', () => {
    expect(textUtil.nextPatchDay('2024-01-01', 3)).toBeInstanceOf(Date)
  })

  it('finds the 2nd Wednesday of the current quarter-boundary month (Jan -> Jan 10 2024)', () => {
    expect(comp(textUtil.nextPatchDay('2024-01-01', 3))).toEqual([2024, 0, 10, 3])
  })

  it('rolls forward to the next quarter boundary when needed (Feb -> Apr 10 2024)', () => {
    expect(comp(textUtil.nextPatchDay('2024-02-15', 3))).toEqual([2024, 3, 10, 3])
  })

  it('crosses the year boundary (Dec 2024 -> Jan 8 2025)', () => {
    expect(comp(textUtil.nextPatchDay('2024-12-25', 3))).toEqual([2025, 0, 8, 3])
  })

  it('handles mid-quarter June -> Jul 10 2024', () => {
    expect(comp(textUtil.nextPatchDay('2024-06-19', 3))).toEqual([2024, 6, 10, 3])
  })

  it('supports an arbitrary weekday (2nd Tuesday after Mar 2025 -> Apr 8 2025)', () => {
    expect(comp(textUtil.nextPatchDay('2025-03-10', 2))).toEqual([2025, 3, 8, 2])
  })

  it('supports a Monday weekday (Sep 2024 -> 2nd Monday Oct 14 2024)', () => {
    expect(comp(textUtil.nextPatchDay('2024-09-01', 1))).toEqual([2024, 9, 14, 1])
  })
})

// -------------------------------------------------------------------------
// diffline  (character-level inline diff producing {lhs, rhs} token arrays;
// t:0 = unchanged, t:1 = changed span).
// -------------------------------------------------------------------------
describe('diffline', () => {
  it('marks identical lines as a single unchanged token on each side', () => {
    expect(textUtil.diffline('hello', 'hello')).toEqual({
      lhs: [{ t: 0, str: 'hello' }],
      rhs: [{ t: 0, str: 'hello' }],
    })
  })

  it('isolates a single-character substitution in the middle', () => {
    expect(textUtil.diffline('abcXef', 'abcYef')).toEqual({
      lhs: [{ t: 0, str: 'abc' }, { t: 1, str: 'X' }, { t: 0, str: 'ef' }],
      rhs: [{ t: 0, str: 'abc' }, { t: 1, str: 'Y' }, { t: 0, str: 'ef' }],
    })
  })

  it('represents an insertion (lhs unchanged, rhs gains a span)', () => {
    expect(textUtil.diffline('abc', 'abXc')).toEqual({
      lhs: [{ t: 0, str: 'abc' }],
      rhs: [{ t: 0, str: 'ab' }, { t: 1, str: 'X' }, { t: 0, str: 'c' }],
    })
  })

  it('represents a deletion (lhs gains a span, rhs unchanged)', () => {
    expect(textUtil.diffline('abXc', 'abc')).toEqual({
      lhs: [{ t: 0, str: 'ab' }, { t: 1, str: 'X' }, { t: 0, str: 'c' }],
      rhs: [{ t: 0, str: 'abc' }],
    })
  })

  it('handles two empty lines', () => {
    expect(textUtil.diffline('', '')).toEqual({
      lhs: [{ t: 0, str: '' }],
      rhs: [{ t: 0, str: '' }],
    })
  })

  it('handles an empty left side vs non-empty right side', () => {
    expect(textUtil.diffline('', 'abc')).toEqual({
      lhs: [{ t: 0, str: '' }],
      rhs: [{ t: 0, str: '' }, { t: 1, str: 'abc' }, { t: 0, str: '' }],
    })
  })

  it('isolates a leading-character substitution', () => {
    expect(textUtil.diffline('Xabc', 'Yabc')).toEqual({
      lhs: [{ t: 0, str: '' }, { t: 1, str: 'X' }, { t: 0, str: 'abc' }],
      rhs: [{ t: 0, str: '' }, { t: 1, str: 'Y' }, { t: 0, str: 'abc' }],
    })
  })
})

// -------------------------------------------------------------------------
// getAffectedProductString — exhaustive version_affected operator coverage,
// version_name, platform, multi vendor/product, and edge cases.
// (cve-transforms.test.js only snapshots one simple shape.)
// -------------------------------------------------------------------------
describe('getAffectedProductString — operators, platform, edges', () => {
  const cve = (versions) => ({
    affects: {
      vendor: {
        vendor_data: [
          {
            vendor_name: 'Acme',
            product: {
              product_data: [{ product_name: 'Widget', version: { version_data: versions } }],
            },
          },
        ],
      },
    },
  })

  it('renders every version_affected operator (and the !/? prefixed variants) — snapshot', () => {
    const out = textUtil.getAffectedProductString(
      cve([
        { version_value: '1.0', version_affected: '=' },
        { version_value: '2.0', version_affected: '<' },
        { version_value: '3.0', version_affected: '>' },
        { version_value: '4.0', version_affected: '<=' },
        { version_value: '5.0', version_affected: '>=' },
        { version_value: '6.0', version_affected: '!' },
        { version_value: '7.0', version_affected: '?' },
        { version_value: '8.0', version_affected: '!<' },
        { version_value: '9.0', version_affected: '?<' },
        { version_value: '10.0', version_affected: '?>' },
        { version_value: '11.0', version_affected: '!<=' },
        { version_value: '12.0', version_affected: '?<=' },
        { version_value: '13.0', version_affected: '!>=' },
        { version_value: '14.0', version_affected: '?>=' },
      ])
    )
    expect(out).toMatchSnapshot()
  })

  it('classifies = as affected, ! as unaffected, ? as unknown (exact text)', () => {
    expect(
      textUtil.getAffectedProductString(
        cve([
          { version_value: '1.0', version_affected: '=' },
          { version_value: '6.0', version_affected: '!' },
          { version_value: '7.0', version_affected: '?' },
        ])
      )
    ).toBe(
      'This issue affects:\nAcme Widget\n1.0.\n\n' +
        'This issue does not affect:\nAcme Widget\n6.0.\n\n' +
        'It is not known whether this issue affects:\nAcme Widget\n7.0.'
    )
  })

  it('includes version_name in the prefix and appends platform with " on "', () => {
    expect(
      textUtil.getAffectedProductString(
        cve([
          { version_value: '1.0', version_affected: '<', version_name: 'Pro', platform: 'Linux' },
          { version_value: '2.0', version_affected: '=', platform: 'Windows' },
        ])
      )
    ).toBe(
      'This issue affects:\nAcme Widget\nWidget Pro versions earlier than 1.0 on Linux;\n2.0 on Windows.'
    )
  })

  it('defaults to "affected" when version_affected is absent (raw version_value, platform still appended)', () => {
    expect(
      textUtil.getAffectedProductString(
        cve([{ version_value: '1.0' }, { version_value: '2.0', platform: 'macOS' }])
      )
    ).toBe('This issue affects:\nAcme Widget\n1.0;\n2.0 on macOS.')
  })

  it('an unrecognized operator falls through to the raw version_value', () => {
    expect(
      textUtil.getAffectedProductString(cve([{ version_value: '9.9', version_affected: '~~~' }]))
    ).toBe('This issue affects:\nAcme Widget\n9.9.')
  })

  it('returns an empty string when there is no vendor data', () => {
    expect(
      textUtil.getAffectedProductString({ affects: { vendor: { vendor_data: [] } } })
    ).toBe('')
  })

  it('groups multiple vendors and products — snapshot', () => {
    const out = textUtil.getAffectedProductString({
      affects: {
        vendor: {
          vendor_data: [
            {
              vendor_name: 'Acme',
              product: {
                product_data: [
                  {
                    product_name: 'Widget',
                    version: { version_data: [{ version_value: '1.0', version_affected: '<' }] },
                  },
                  {
                    product_name: 'Gadget',
                    version: { version_data: [{ version_value: '2.0', version_affected: '=' }] },
                  },
                ],
              },
            },
            {
              vendor_name: 'Globex',
              product: {
                product_data: [
                  {
                    product_name: 'Thing',
                    version: { version_data: [{ version_value: '3.0', version_affected: '!' }] },
                  },
                ],
              },
            },
          ],
        },
      },
    })
    expect(out).toMatchSnapshot()
  })
})

// -------------------------------------------------------------------------
// affectedTable / appliesTo / affectedYesNo
//
// CURRENT BEHAVIOR under the vitest (ESM/strict) module context: all three
// functions contain the statement `var prefix = vn = "";` which assigns to an
// undeclared identifier `vn`. In strict mode that throws
// `ReferenceError: vn is not defined` as soon as the first version row is
// processed. (Loaded as loose CommonJS via plain `node`, the same line silently
// creates a global instead — but vitest runs the module in strict mode, and
// that is the environment whose behavior we are locking.)
//
// These tests therefore characterize the throw, plus the one path that does NOT
// reach the offending line (empty vendor_data) and so returns normally.
// -------------------------------------------------------------------------
const affectsHelper = (versions) => ({
  vendor: {
    vendor_data: [
      {
        vendor_name: 'Acme',
        product: {
          product_data: [{ product_name: 'Widget', version: { version_data: versions } }],
        },
      },
    ],
  },
})

describe('affectedTable (strict-mode behavior)', () => {
  const cve = (versions) => ({ affects: affectsHelper(versions) })

  it('throws ReferenceError("vn is not defined") when any version row is present', () => {
    expect(() => textUtil.affectedTable(cve([{ version_value: '1.0' }]))).toThrow(ReferenceError)
    expect(() => textUtil.affectedTable(cve([{ version_value: '1.0' }]))).toThrow('vn is not defined')
  })

  it('throws even with version_affected / platform / version_name supplied', () => {
    expect(() =>
      textUtil.affectedTable(
        cve([{ version_value: '1.0', version_affected: '<', version_name: 'Pro', platform: 'Linux' }])
      )
    ).toThrow(ReferenceError)
  })

  it('does NOT throw and returns {} when vendor_data is empty (offending line unreached)', () => {
    expect(textUtil.affectedTable({ affects: { vendor: { vendor_data: [] } } })).toEqual({})
  })

  it('does NOT throw when a product has an empty version_data list (returns the empty product map)', () => {
    const out = textUtil.affectedTable({
      affects: {
        vendor: {
          vendor_data: [
            {
              vendor_name: 'Acme',
              product: { product_data: [{ product_name: 'Widget', version: { version_data: [] } }] },
            },
          ],
        },
      },
    })
    expect(out).toEqual({ Acme: { Widget: {} } })
  })
})

describe('appliesTo (strict-mode behavior)', () => {
  it('throws ReferenceError("vn is not defined") when any version row is present', () => {
    expect(() => textUtil.appliesTo(affectsHelper([{ version_value: '1.0' }]))).toThrow(ReferenceError)
    expect(() => textUtil.appliesTo(affectsHelper([{ version_value: '1.0' }]))).toThrow('vn is not defined')
  })

  it('does NOT throw and returns [] when vendor_data is empty', () => {
    expect(textUtil.appliesTo({ vendor: { vendor_data: [] } })).toEqual([])
  })

  it('does NOT throw and returns [] when version_data is empty', () => {
    expect(
      textUtil.appliesTo({
        vendor: {
          vendor_data: [
            {
              vendor_name: 'Acme',
              product: { product_data: [{ product_name: 'Widget', version: { version_data: [] } }] },
            },
          ],
        },
      })
    ).toEqual([])
  })
})

describe('affectedYesNo (strict-mode behavior)', () => {
  it('throws ReferenceError("vn is not defined") when any version row is present', () => {
    expect(() => textUtil.affectedYesNo(affectsHelper([{ version_value: '1.0' }]))).toThrow(ReferenceError)
    expect(() => textUtil.affectedYesNo(affectsHelper([{ version_value: '1.0' }]))).toThrow('vn is not defined')
  })

  it('does NOT throw and returns empty buckets when vendor_data is empty', () => {
    expect(textUtil.affectedYesNo({ vendor: { vendor_data: [] } })).toEqual({
      yes: [],
      no: [],
      unknown: [],
    })
  })

  it('does NOT throw and returns empty buckets when version_data is empty', () => {
    expect(
      textUtil.affectedYesNo({
        vendor: {
          vendor_data: [
            {
              vendor_name: 'Acme',
              product: { product_data: [{ product_name: 'Widget', version: { version_data: [] } }] },
            },
          ],
        },
      })
    ).toEqual({ yes: [], no: [], unknown: [] })
  })
})

// -------------------------------------------------------------------------
// reduceJSON — deeper edges beyond cve-transforms.test.js's happy path.
// -------------------------------------------------------------------------
describe('reduceJSON — deep edges', () => {
  it('orders keys with no description/impact present', () => {
    const out = textUtil.reduceJSON({ b: 2, a: 1 })
    expect(Object.keys(out)).toEqual(['a', 'b'])
    expect(out).toEqual({ a: 1, b: 2 })
  })

  it('drops impact when cvss.baseScore === 0, keeps it otherwise', () => {
    expect(textUtil.reduceJSON({ impact: { cvss: { baseScore: 0.0 } } })).not.toHaveProperty('impact')
    expect(textUtil.reduceJSON({ impact: { cvss: { baseScore: 5 } } })).toEqual({
      impact: { cvss: { baseScore: 5 } },
    })
  })

  it('keeps impact with no cvss block, or with cvss but no baseScore', () => {
    expect(textUtil.reduceJSON({ impact: { other: 1 } })).toEqual({ impact: { other: 1 } })
    // baseScore undefined !== 0, so impact (and its empty cvss) survives.
    expect(textUtil.reduceJSON({ impact: { cvss: {} } })).toEqual({ impact: { cvss: {} } })
  })

  it('skips description entries with no lang, and merges same-lang values in first-seen order', () => {
    const out = textUtil.reduceJSON({
      description: {
        description_data: [
          { lang: 'eng', value: 'a' },
          { value: 'no-lang' },
          { lang: 'eng', value: 'b' },
          { lang: 'fra', value: 'c' },
        ],
      },
    })
    expect(out.description.description_data).toEqual([
      { lang: 'eng', value: 'a\nb' },
      { lang: 'fra', value: 'c' },
    ])
  })

  it('CURRENT BEHAVIOR: an empty description_data array is dropped by the clone, leaving description as {}', () => {
    expect(textUtil.reduceJSON({ description: { description_data: [] } })).toEqual({
      description: {},
    })
  })

  it('orders nested object keys and does not mutate the input (keeps CNA_private on the original)', () => {
    const input = { z: 1, a: { y: 2, b: 3 }, CNA_private: { x: 1 } }
    const snapshot = JSON.stringify(input)
    const out = textUtil.reduceJSON(input)
    expect(Object.keys(out)).toEqual(['a', 'z'])
    expect(Object.keys(out.a)).toEqual(['b', 'y'])
    expect(out).not.toHaveProperty('CNA_private')
    // input is untouched
    expect(JSON.stringify(input)).toBe(snapshot)
    expect(Object.prototype.hasOwnProperty.call(input, 'CNA_private')).toBe(true)
  })
})

// -------------------------------------------------------------------------
// getMITREJSON — edges beyond the basic object case.
// -------------------------------------------------------------------------
describe('getMITREJSON — edges', () => {
  it('serializes arrays with two-space indentation', () => {
    expect(textUtil.getMITREJSON([1, 2])).toBe('[\n  1,\n  2\n]')
  })

  it('serializes scalars and null', () => {
    expect(textUtil.getMITREJSON('str')).toBe('"str"')
    expect(textUtil.getMITREJSON(null)).toBe('null')
  })

  it('serializes an empty object', () => {
    expect(textUtil.getMITREJSON({})).toBe('{}')
  })
})

// -------------------------------------------------------------------------
// getPR — edges beyond the basic extraction.
// -------------------------------------------------------------------------
describe('getPR — edges', () => {
  it('returns an empty array when solution is missing or empty', () => {
    expect(textUtil.getPR({})).toEqual([])
    expect(textUtil.getPR({ solution: '' })).toEqual([])
  })

  it('extracts a single PR number', () => {
    expect(textUtil.getPR({ solution: 'See PR 42.' })).toEqual(['42'])
  })

  it('splits "and"/"or"-joined PR lists into individual numbers', () => {
    expect(textUtil.getPR({ solution: 'PRs 1, 2 and 3 or 4' })).toEqual(['1', '2', '3', '4'])
  })

  it('returns empty when no "PR" token is present', () => {
    expect(textUtil.getPR({ solution: 'no pull requests here' })).toEqual([])
  })

  it('is case-insensitive on the PR token', () => {
    expect(textUtil.getPR({ solution: 'prs 7' })).toEqual(['7'])
  })
})

// -------------------------------------------------------------------------
// cvssjs — the CVSS calculator/vector helpers (exported in Node).
// Pure, headless, deterministic. console.log calls inside `m`/severity are
// harmless noise.
// -------------------------------------------------------------------------
describe('cvssjs.severityLevel', () => {
  const cases = [
    [0, 'NONE'],
    [0.1, 'LOW'],
    [3.9, 'LOW'],
    [4.0, 'MEDIUM'],
    [6.9, 'MEDIUM'],
    [7.0, 'HIGH'],
    [8.9, 'HIGH'],
    [9.0, 'CRITICAL'],
    [10, 'CRITICAL'],
  ]
  it.each(cases)('score %s -> %s', (score, label) => {
    expect(textUtil.cvssjs.severityLevel(score)).toBe(label)
  })
})

describe('cvssjs.severity', () => {
  it('returns the matching band object for in-range scores', () => {
    expect(textUtil.cvssjs.severity(0)).toEqual({ name: 'NONE', bottom: 0.0, top: 0.0 })
    expect(textUtil.cvssjs.severity(5)).toEqual({ name: 'MEDIUM', bottom: 4.0, top: 6.9 })
    expect(textUtil.cvssjs.severity(7.5)).toEqual({ name: 'HIGH', bottom: 7.0, top: 8.9 })
    expect(textUtil.cvssjs.severity(9.5)).toEqual({ name: 'CRITICAL', bottom: 9.0, top: 10.0 })
  })

  it('returns the undefined sentinel band for out-of-range scores', () => {
    const sentinel = { name: '?', bottom: 'Not', top: 'defined' }
    expect(textUtil.cvssjs.severity(-1)).toEqual(sentinel)
    expect(textUtil.cvssjs.severity(11)).toEqual(sentinel)
  })
})

describe('cvssjs.roundUp1', () => {
  it('rounds up to one decimal place per the CVSS spec', () => {
    expect(textUtil.cvssjs.roundUp1(4.0)).toBe(4)
    expect(textUtil.cvssjs.roundUp1(4.02)).toBe(4.1)
    expect(textUtil.cvssjs.roundUp1(4.05)).toBe(4.1)
    expect(textUtil.cvssjs.roundUp1(0)).toBe(0)
    expect(textUtil.cvssjs.roundUp1(9.999)).toBe(10)
  })
})

describe('cvssjs vector strings', () => {
  it('builds a CVSS 3.1 vector string', () => {
    expect(
      textUtil.cvssjs.vector3({
        attackVector: 'NETWORK',
        attackComplexity: 'LOW',
        privilegesRequired: 'NONE',
        userInteraction: 'NONE',
        scope: 'UNCHANGED',
        confidentialityImpact: 'HIGH',
        integrityImpact: 'HIGH',
        availabilityImpact: 'HIGH',
      })
    ).toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')
  })

  it('builds a CVSS 2 vector string', () => {
    expect(
      textUtil.cvssjs.vector2({
        accessVector: 'NETWORK',
        accessComplexity: 'LOW',
        authentication: 'NONE',
        confidentialityImpact: 'PARTIAL',
        integrityImpact: 'PARTIAL',
        availabilityImpact: 'PARTIAL',
      })
    ).toBe('AV:N/AC:L/Au:N/C:P/I:P/A:P')
  })

  it('builds a CVSS 4.0 vector string', () => {
    expect(
      textUtil.cvssjs.vector4({
        attackVector: 'NETWORK',
        attackComplexity: 'LOW',
        attackRequirements: 'NONE',
        privilegesRequired: 'NONE',
        userInteraction: 'NONE',
        vulnConfidentialityImpact: 'HIGH',
        vulnIntegrityImpact: 'HIGH',
        vulnAvailabilityImpact: 'HIGH',
        subConfidentialityImpact: 'NONE',
        subIntegrityImpact: 'NONE',
        subAvailabilityImpact: 'NONE',
      })
    ).toBe('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N')
  })
})

describe('cvssjs.calculate3', () => {
  it('computes a full CVSS 3.1 base score (9.8 for a worst-case network vector)', () => {
    expect(
      textUtil.cvssjs.calculate3({
        attackVector: 'NETWORK',
        attackComplexity: 'LOW',
        privilegesRequired: 'NONE',
        userInteraction: 'NONE',
        scope: 'UNCHANGED',
        confidentialityImpact: 'HIGH',
        integrityImpact: 'HIGH',
        availabilityImpact: 'HIGH',
      })
    ).toBe('9.8')
  })

  it('returns "?" when a required metric is missing', () => {
    expect(textUtil.cvssjs.calculate3({ attackVector: 'NETWORK' })).toBe('?')
  })

  it('applies the scope-changed coefficient', () => {
    expect(
      textUtil.cvssjs.calculate3({
        attackVector: 'NETWORK',
        attackComplexity: 'LOW',
        privilegesRequired: 'LOW',
        userInteraction: 'REQUIRED',
        scope: 'CHANGED',
        confidentialityImpact: 'LOW',
        integrityImpact: 'LOW',
        availabilityImpact: 'NONE',
      })
    ).toBe('5.4')
  })
})

describe('cvssjs.calculate2', () => {
  it('computes a CVSS 2 base score', () => {
    expect(
      textUtil.cvssjs.calculate2({
        accessVector: 'NETWORK',
        accessComplexity: 'LOW',
        authentication: 'NONE',
        confidentialityImpact: 'PARTIAL',
        integrityImpact: 'PARTIAL',
        availabilityImpact: 'PARTIAL',
      })
    ).toBe('7.5')
  })

  it('returns numeric 0 when total impact is zero', () => {
    expect(
      textUtil.cvssjs.calculate2({
        accessVector: 'NETWORK',
        accessComplexity: 'LOW',
        authentication: 'NONE',
        confidentialityImpact: 'NONE',
        integrityImpact: 'NONE',
        availabilityImpact: 'NONE',
      })
    ).toBe(0)
  })
})
