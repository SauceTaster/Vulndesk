import { describe, it, expect } from 'vitest'

// CHARACTERIZATION (golden-master) tests for the `cvssjs` calculator.
//
// `cvssjs` is exported from public/js/util.js as `module.exports.cvssjs`. In
// vitest's ESM interop we can pull it out via the default export
// (`textUtil.cvssjs`) or, equivalently, as a named import. We assert the
// equivalence below and then use the named binding everywhere.
//
// PURPOSE: lock down EXACTLY what the code does TODAY so the upcoming refactor
// that consolidates CVE transforms into @vulndesk/core surfaces any regression.
// Every expected value here was observed by running the real code, NOT guessed.
//
// API surface (probed): the object exposes NO `calculate`, `severityRating`,
// `vectorString`, or `cvss_version` methods. The real methods are:
//   - calculate3(cvss) -> CVSS v3.0/3.1 base score as a STRING (e.g. "9.8"),
//       or "?" for missing metrics, or "NaN" for unknown metric values, or a
//       TypeError instance when the argument itself is null/undefined.
//   - calculate2(cvss) -> CVSS v2 base score as a STRING, EXCEPT it returns the
//       NUMBER 0 (not "0.0") when impact is exactly 0.
//   - severity(score)      -> the matching CVSSseveritys entry object.
//   - severityLevel(score) -> severity name string.
//   - roundUp1(input)      -> CVSS v3.1 "round up to one decimal" helper.
//   - vector4/vector3/vector2(cvss) -> build the textual vector strings.
// It also carries data tables: vectorMap4/3/2, metricMap4, Weight, valueMap,
// w2, CVSSseveritys.

import textUtil from '../public/js/util.js'
import { cvssjs } from '../public/js/util.js'

const c = cvssjs

// Convenience builders so each test reads as a recognisable CVSS vector.
function v3(over = {}) {
  return {
    attackVector: 'NETWORK',
    attackComplexity: 'LOW',
    privilegesRequired: 'NONE',
    userInteraction: 'NONE',
    scope: 'UNCHANGED',
    confidentialityImpact: 'HIGH',
    integrityImpact: 'HIGH',
    availabilityImpact: 'HIGH',
    ...over,
  }
}
function v2(over = {}) {
  return {
    accessVector: 'NETWORK',
    accessComplexity: 'LOW',
    authentication: 'NONE',
    confidentialityImpact: 'COMPLETE',
    integrityImpact: 'COMPLETE',
    availabilityImpact: 'COMPLETE',
    ...over,
  }
}

describe('cvssjs — module / export shape', () => {
  it('is the same object via default-export property and named export', () => {
    expect(textUtil.cvssjs).toBe(cvssjs)
  })

  it('is a plain object exposing exactly the expected own keys (snapshot)', () => {
    expect(typeof c).toBe('object')
    expect(Object.keys(c)).toMatchSnapshot()
  })

  it('exposes the real method set and NOT the legacy/aliased names', () => {
    expect(typeof c.calculate3).toBe('function')
    expect(typeof c.calculate2).toBe('function')
    expect(typeof c.severity).toBe('function')
    expect(typeof c.severityLevel).toBe('function')
    expect(typeof c.roundUp1).toBe('function')
    expect(typeof c.vector4).toBe('function')
    expect(typeof c.vector3).toBe('function')
    expect(typeof c.vector2).toBe('function')
    // These names do NOT exist on the object today.
    expect(c.calculate).toBeUndefined()
    expect(c.severityRating).toBeUndefined()
    expect(c.vectorString).toBeUndefined()
    expect(c.cvss_version).toBeUndefined()
  })
})

describe('cvssjs — data tables (lock the weight/map constants)', () => {
  it('vectorMap4 maps long metric names to abbreviations (snapshot)', () => {
    expect(c.vectorMap4).toMatchSnapshot()
  })
  it('metricMap4 maps abbreviations back to long metric names (snapshot)', () => {
    expect(c.metricMap4).toMatchSnapshot()
  })
  it('vectorMap3 / vectorMap2 (snapshot)', () => {
    expect(c.vectorMap3).toMatchSnapshot()
    expect(c.vectorMap2).toMatchSnapshot()
  })
  it('Weight table for v3 (snapshot)', () => {
    expect(c.Weight).toMatchSnapshot()
  })
  it('w2 table for v2 (snapshot)', () => {
    expect(c.w2).toMatchSnapshot()
  })
  it('valueMap and CVSSseveritys (snapshot)', () => {
    expect(c.valueMap).toMatchSnapshot()
    expect(c.CVSSseveritys).toMatchSnapshot()
  })
  it('CVSSseveritys boundary values are exactly as recorded', () => {
    expect(c.CVSSseveritys.map((s) => [s.name, s.bottom, s.top])).toEqual([
      ['NONE', 0.0, 0.0],
      ['LOW', 0.1, 3.9],
      ['MEDIUM', 4.0, 6.9],
      ['HIGH', 7.0, 8.9],
      ['CRITICAL', 9.0, 10.0],
    ])
  })
  it('a representative Weight lookup matches', () => {
    expect(c.Weight.attackVector.NETWORK).toBe(0.85)
    expect(c.Weight.attackVector.PHYSICAL).toBe(0.2)
    expect(c.Weight.scope.UNCHANGED).toBe(6.42)
    expect(c.Weight.scope.CHANGED).toBe(7.52)
    expect(c.Weight.privilegesRequired.UNCHANGED.LOW).toBe(0.62)
    expect(c.Weight.privilegesRequired.CHANGED.LOW).toBe(0.68)
  })
})

describe('calculate3 — well-known CVSS v3.1 vectors → canonical base scores', () => {
  it('AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 (Critical)', () => {
    expect(c.calculate3(v3())).toBe('9.8')
  })

  it('AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N = 0.0 (None)', () => {
    const cvss = v3({
      attackComplexity: 'HIGH',
      privilegesRequired: 'HIGH',
      userInteraction: 'REQUIRED',
      confidentialityImpact: 'NONE',
      integrityImpact: 'NONE',
      availabilityImpact: 'NONE',
    })
    expect(c.calculate3(cvss)).toBe('0.0')
  })

  it('AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H = 7.8 (local privilege escalation)', () => {
    const cvss = v3({ attackVector: 'LOCAL', privilegesRequired: 'LOW' })
    expect(c.calculate3(cvss)).toBe('7.8')
  })

  it('AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N = 6.1 (reflected XSS, changed scope)', () => {
    const cvss = v3({
      userInteraction: 'REQUIRED',
      scope: 'CHANGED',
      confidentialityImpact: 'LOW',
      integrityImpact: 'LOW',
      availabilityImpact: 'NONE',
    })
    expect(c.calculate3(cvss)).toBe('6.1')
  })

  it('AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = 7.5 (info disclosure)', () => {
    const cvss = v3({ integrityImpact: 'NONE', availabilityImpact: 'NONE' })
    expect(c.calculate3(cvss)).toBe('7.5')
  })

  it('AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = 6.5 (adjacent network)', () => {
    const cvss = v3({
      attackVector: 'ADJACENT_NETWORK',
      integrityImpact: 'NONE',
      availabilityImpact: 'NONE',
    })
    expect(c.calculate3(cvss)).toBe('6.5')
  })

  it('AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L = 3.5 (physical, low)', () => {
    const cvss = v3({
      attackVector: 'PHYSICAL',
      attackComplexity: 'HIGH',
      privilegesRequired: 'HIGH',
      userInteraction: 'REQUIRED',
      confidentialityImpact: 'LOW',
      integrityImpact: 'LOW',
      availabilityImpact: 'LOW',
    })
    expect(c.calculate3(cvss)).toBe('3.5')
  })

  it('AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L = 4.3 (low availability only)', () => {
    const cvss = v3({
      userInteraction: 'REQUIRED',
      confidentialityImpact: 'NONE',
      integrityImpact: 'NONE',
      availabilityImpact: 'LOW',
    })
    expect(c.calculate3(cvss)).toBe('4.3')
  })

  it('returns a STRING type, not a number, for valid scores', () => {
    expect(typeof c.calculate3(v3())).toBe('string')
  })
})

describe('calculate3 — Scope:Changed behavior (records current quirks)', () => {
  it('AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H = 9.9 (NOTE: NIST canonical is 10.0)', () => {
    // This is a CHARACTERIZATION test: the code returns "9.9" here even though
    // the official NIST calculator yields 10.0 for this vector. We lock the
    // CURRENT (slightly off) behavior so a refactor that "fixes" it is visible.
    const cvss = v3({ privilegesRequired: 'LOW', scope: 'CHANGED' })
    expect(c.calculate3(cvss)).toBe('9.9')
  })

  it('changed scope with all-NONE impacts collapses to 0.0', () => {
    const cvss = v3({
      scope: 'CHANGED',
      confidentialityImpact: 'NONE',
      integrityImpact: 'NONE',
      availabilityImpact: 'NONE',
    })
    expect(c.calculate3(cvss)).toBe('0.0')
  })
})

describe('calculate3 — CVSS v3.0-style vectors (same algorithm)', () => {
  it('AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H scores the same as v3.1 input', () => {
    const cvss = v3({ userInteraction: 'REQUIRED', scope: 'CHANGED' })
    expect(c.calculate3(cvss)).toBe('9.6')
  })

  it('AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (local, no privileges) = 8.4', () => {
    const cvss = v3({ attackVector: 'LOCAL' })
    expect(c.calculate3(cvss)).toBe('8.4')
  })
})

describe('calculate3 — malformed / partial / null input (lock the failure modes)', () => {
  it('empty object → "?" (a required metric is missing)', () => {
    expect(c.calculate3({})).toBe('?')
  })

  it('partial vector (only attackVector) → "?"', () => {
    expect(c.calculate3({ attackVector: 'NETWORK' })).toBe('?')
  })

  it("a metric present as empty string '' → \"?\"", () => {
    expect(c.calculate3(v3({ attackVector: '' }))).toBe('?')
  })

  it('a metric present as null → "?"', () => {
    expect(c.calculate3(v3({ attackVector: null }))).toBe('?')
  })

  it('an unknown metric value (e.g. attackVector:"BOGUS") → the string "NaN"', () => {
    // Weight lookup returns undefined → arithmetic produces NaN → "NaN".toFixed.
    const r = c.calculate3(v3({ attackVector: 'BOGUS' }))
    expect(r).toBe('NaN')
    expect(typeof r).toBe('string')
  })

  it('undefined argument → returns a TypeError instance (not thrown)', () => {
    const r = c.calculate3(undefined)
    expect(r).toBeInstanceOf(TypeError)
  })

  it('null argument → returns a TypeError instance (not thrown)', () => {
    const r = c.calculate3(null)
    expect(r).toBeInstanceOf(TypeError)
  })

  it('every required metric absent except an invalid scope still short-circuits to "?"', () => {
    // scope is part of this.Weight, so a missing scope alone trips the "?" guard.
    const cvss = v3()
    delete cvss.scope
    expect(c.calculate3(cvss)).toBe('?')
  })
})

describe('calculate2 — well-known CVSS v2 vectors', () => {
  it('AV:N/AC:L/Au:N/C:C/I:C/A:C = 10.0 (critical)', () => {
    expect(c.calculate2(v2())).toBe('10.0')
  })

  it('AV:N/AC:M/Au:N/C:P/I:N/A:N = 4.3 (medium, partial confidentiality)', () => {
    const cvss = v2({
      accessComplexity: 'MEDIUM',
      confidentialityImpact: 'PARTIAL',
      integrityImpact: 'NONE',
      availabilityImpact: 'NONE',
    })
    expect(c.calculate2(cvss)).toBe('4.3')
  })

  it('AV:L/AC:H/Au:M/C:P/I:P/A:P = 3.4 (local, multi-auth)', () => {
    const cvss = v2({
      accessVector: 'LOCAL',
      accessComplexity: 'HIGH',
      authentication: 'MULTIPLE',
      confidentialityImpact: 'PARTIAL',
      integrityImpact: 'PARTIAL',
      availabilityImpact: 'PARTIAL',
    })
    expect(c.calculate2(cvss)).toBe('3.4')
  })

  it('all-NONE impacts → returns the NUMBER 0 (not the string "0.0")', () => {
    const cvss = v2({
      confidentialityImpact: 'NONE',
      integrityImpact: 'NONE',
      availabilityImpact: 'NONE',
    })
    const r = c.calculate2(cvss)
    expect(r).toBe(0)
    expect(typeof r).toBe('number')
  })

  it('non-zero impact result is returned as a STRING', () => {
    expect(typeof c.calculate2(v2())).toBe('string')
  })

  it('AV:N/AC:L/Au:N/C:P/I:P/A:P = 7.5 (classic network partial)', () => {
    const cvss = v2({
      confidentialityImpact: 'PARTIAL',
      integrityImpact: 'PARTIAL',
      availabilityImpact: 'PARTIAL',
    })
    expect(c.calculate2(cvss)).toBe('7.5')
  })
})

describe('severityLevel — threshold boundaries (string name)', () => {
  // Implementation: 0 → NONE; <=3.9 → LOW; <=6.9 → MEDIUM; <=8.9 → HIGH; else CRITICAL.
  it('exactly 0 → NONE', () => {
    expect(c.severityLevel(0)).toBe('NONE')
  })
  it('0.1 → LOW (just above None)', () => {
    expect(c.severityLevel(0.1)).toBe('LOW')
  })
  it('3.9 → LOW (top of Low)', () => {
    expect(c.severityLevel(3.9)).toBe('LOW')
  })
  it('4.0 → MEDIUM (bottom of Medium)', () => {
    expect(c.severityLevel(4.0)).toBe('MEDIUM')
  })
  it('5.5 → MEDIUM (mid)', () => {
    expect(c.severityLevel(5.5)).toBe('MEDIUM')
  })
  it('6.9 → MEDIUM (top of Medium)', () => {
    expect(c.severityLevel(6.9)).toBe('MEDIUM')
  })
  it('7.0 → HIGH (bottom of High)', () => {
    expect(c.severityLevel(7.0)).toBe('HIGH')
  })
  it('8.9 → HIGH (top of High)', () => {
    expect(c.severityLevel(8.9)).toBe('HIGH')
  })
  it('9.0 → CRITICAL (bottom of Critical)', () => {
    expect(c.severityLevel(9.0)).toBe('CRITICAL')
  })
  it('10.0 → CRITICAL (max)', () => {
    expect(c.severityLevel(10.0)).toBe('CRITICAL')
  })
  it('string "0" → NONE (uses == 0 loose compare)', () => {
    expect(c.severityLevel('0')).toBe('NONE')
  })
})

describe('severity — returns the matching CVSSseveritys entry object', () => {
  it('0.0 → NONE entry', () => {
    expect(c.severity(0.0)).toEqual({ name: 'NONE', bottom: 0.0, top: 0.0 })
  })
  it('0.1 → LOW entry (bottom edge)', () => {
    expect(c.severity(0.1)).toEqual({ name: 'LOW', bottom: 0.1, top: 3.9 })
  })
  it('3.9 → LOW entry (top edge)', () => {
    expect(c.severity(3.9)).toEqual({ name: 'LOW', bottom: 0.1, top: 3.9 })
  })
  it('4.0 → MEDIUM entry', () => {
    expect(c.severity(4.0)).toEqual({ name: 'MEDIUM', bottom: 4.0, top: 6.9 })
  })
  it('6.9 → MEDIUM entry (top edge)', () => {
    expect(c.severity(6.9)).toEqual({ name: 'MEDIUM', bottom: 4.0, top: 6.9 })
  })
  it('7.0 → HIGH entry', () => {
    expect(c.severity(7.0)).toEqual({ name: 'HIGH', bottom: 7.0, top: 8.9 })
  })
  it('8.9 → HIGH entry (top edge)', () => {
    expect(c.severity(8.9)).toEqual({ name: 'HIGH', bottom: 7.0, top: 8.9 })
  })
  it('9.0 → CRITICAL entry', () => {
    expect(c.severity(9.0)).toEqual({ name: 'CRITICAL', bottom: 9.0, top: 10.0 })
  })
  it('10.0 → CRITICAL entry (top edge)', () => {
    expect(c.severity(10.0)).toEqual({ name: 'CRITICAL', bottom: 9.0, top: 10.0 })
  })

  it('a value in the 3.9<x<4.0 GAP → the "?" not-defined object (quirk)', () => {
    // The band edges leave a gap between 3.9 and 4.0; values there match no band.
    expect(c.severity(3.95)).toEqual({ name: '?', bottom: 'Not', top: 'defined' })
  })
  it('negative score (-1) → the "?" not-defined object', () => {
    expect(c.severity(-1)).toEqual({ name: '?', bottom: 'Not', top: 'defined' })
  })
  it('out-of-range high score (11) → the "?" not-defined object', () => {
    expect(c.severity(11)).toEqual({ name: '?', bottom: 'Not', top: 'defined' })
  })
})

describe('roundUp1 — CVSS v3.1 round-half-up-to-one-decimal helper', () => {
  it('0 → 0', () => {
    expect(c.roundUp1(0)).toBe(0)
  })
  it('1.0 (exact at 1e5 granularity) → 1', () => {
    expect(c.roundUp1(1.0)).toBe(1)
  })
  it('1.01 → 1.1 (rounds up to next tenth)', () => {
    expect(c.roundUp1(1.01)).toBe(1.1)
  })
  it('1.001 → 1.1 (any remainder rounds up)', () => {
    expect(c.roundUp1(1.001)).toBe(1.1)
  })
  it('4.025 → 4.1', () => {
    expect(c.roundUp1(4.025)).toBe(4.1)
  })
  it('9.799 → 9.8', () => {
    expect(c.roundUp1(9.799)).toBe(9.8)
  })
  it('9.8 → 9.8 (already a clean tenth)', () => {
    expect(c.roundUp1(9.8)).toBe(9.8)
  })
  it('3.55 → 3.6', () => {
    expect(c.roundUp1(3.55)).toBe(3.6)
  })
  it('0.05 → 0.1', () => {
    expect(c.roundUp1(0.05)).toBe(0.1)
  })
  it('0.001 → 0.1', () => {
    expect(c.roundUp1(0.001)).toBe(0.1)
  })
  it('2.5 → 2.5 (clean)', () => {
    expect(c.roundUp1(2.5)).toBe(2.5)
  })
  it('6.451 → 6.5', () => {
    expect(c.roundUp1(6.451)).toBe(6.5)
  })
})

describe('vector4 — builds the CVSS:4.0 vector string', () => {
  it('full base metrics → canonical-ordered 4.0 vector', () => {
    const cvss = {
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
    }
    expect(c.vector4(cvss)).toBe(
      'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
    )
  })

  it('skips NOT_DEFINED values and applies valueMap (GREEN→Green, AMBER→Amber)', () => {
    const cvss = {
      attackVector: 'NETWORK',
      exploitMaturity: 'NOT_DEFINED',
      providerUrgency: 'GREEN',
      Recovery: 'AMBER',
    }
    expect(c.vector4(cvss)).toBe('CVSS:4.0/AV:N/R:Amber/U:Green')
  })

  it('empty object → bare prefix "CVSS:4.0"', () => {
    expect(c.vector4({})).toBe('CVSS:4.0')
  })

  it('uses first character for non-valueMap values', () => {
    expect(c.vector4({ attackVector: 'PHYSICAL' })).toBe('CVSS:4.0/AV:P')
  })
})

describe('vector3 — builds the CVSS:3.1 vector string (first-char of each value)', () => {
  it('full base metrics → canonical 3.1 vector', () => {
    expect(c.vector3(v3())).toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')
  })

  it('empty object → bare prefix "CVSS:3.1"', () => {
    expect(c.vector3({})).toBe('CVSS:3.1')
  })

  it('ignores keys not present in vectorMap3', () => {
    expect(c.vector3({ attackVector: 'NETWORK', somethingElse: 'FOO' })).toBe(
      'CVSS:3.1/AV:N',
    )
  })

  it('UNCHANGED scope yields S:U, CHANGED yields S:C', () => {
    expect(c.vector3(v3({ scope: 'CHANGED' }))).toContain('/S:C')
    expect(c.vector3(v3({ scope: 'UNCHANGED' }))).toContain('/S:U')
  })
})

describe('vector2 — builds the CVSS v2 vector string (no prefix, "/"-joined)', () => {
  it('full base metrics → AV:N/AC:L/Au:N/C:C/I:C/A:C', () => {
    expect(c.vector2(v2())).toBe('AV:N/AC:L/Au:N/C:C/I:C/A:C')
  })

  it('empty object → empty string', () => {
    expect(c.vector2({})).toBe('')
  })

  it('partial input → only the mapped, present metrics', () => {
    expect(c.vector2({ accessVector: 'LOCAL', integrityImpact: 'PARTIAL' })).toBe(
      'AV:L/I:P',
    )
  })

  it('authentication uses the two-letter abbreviation "Au"', () => {
    expect(c.vector2({ authentication: 'SINGLE' })).toBe('Au:S')
  })
})

describe('round-trip-ish: calculate3 score feeds severity / severityLevel', () => {
  it('9.8 critical vector → "9.8" → CRITICAL', () => {
    const score = Number(c.calculate3(v3()))
    expect(score).toBe(9.8)
    expect(c.severityLevel(score)).toBe('CRITICAL')
    expect(c.severity(score)).toEqual({ name: 'CRITICAL', bottom: 9.0, top: 10.0 })
  })

  it('0.0 none vector → 0 → NONE', () => {
    const noneVec = v3({
      attackComplexity: 'HIGH',
      privilegesRequired: 'HIGH',
      userInteraction: 'REQUIRED',
      confidentialityImpact: 'NONE',
      integrityImpact: 'NONE',
      availabilityImpact: 'NONE',
    })
    const score = Number(c.calculate3(noneVec))
    expect(score).toBe(0)
    expect(c.severityLevel(score)).toBe('NONE')
  })

  it('7.5 info-disclosure vector → HIGH', () => {
    const score = Number(c.calculate3(v3({ integrityImpact: 'NONE', availabilityImpact: 'NONE' })))
    expect(score).toBe(7.5)
    expect(c.severityLevel(score)).toBe('HIGH')
  })
})
