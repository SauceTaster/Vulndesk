import { describe, it, expect } from 'vitest'

// CommonJS module: import as default, then call .hash / .compare.
// This is the hand-rolled PBKDF2 password hashing that BetterAuth will replace,
// so we lock its exact current behavior here as a golden master.
import pbkdf2 from '../lib/pbkdf2.js'

// --- promisified helpers -------------------------------------------------
// hash(password, cb) -> cb(err, base64String)
function hash(password) {
  return new Promise((resolve, reject) => {
    pbkdf2.hash(password, (err, result) => (err ? reject(err) : resolve(result)))
  })
}

// compare(password, shadow, cb) -> cb(err, bool)
// NOTE: for malformed (truthy) shadows the implementation throws *synchronously*
// while reading buffer offsets, so callers must wrap in try/catch. We expose a
// "safe" variant that captures either a callback result or a synchronous throw.
function compare(password, shadow) {
  return new Promise((resolve, reject) => {
    pbkdf2.compare(password, shadow, (err, ok) => (err ? reject(err) : resolve(ok)))
  })
}

function compareSafe(password, shadow) {
  return new Promise((resolve) => {
    try {
      pbkdf2.compare(password, shadow, (err, ok) =>
        resolve({ threw: false, cbErr: err ? err.message : null, ok }),
      )
    } catch (ex) {
      resolve({ threw: true, error: ex.message })
    }
  })
}

// A fixed golden-master hash produced by this implementation for password
// "hunter2". Because the salt is embedded in the encoded string, this exact
// string must always verify against "hunter2" regardless of run.
const FIXED_HUNTER2 =
  'AAAAAQAAABAAAYj3FWp5Wl2RIJnQFEoF0/ANYiI1a+O+5D/562c+O8CYel54zauLfvabdXD9mSHs/Y0q'

// Encoded header for every hash from this module:
// version=1 (0x00000001) + saltLength=16 (0x00000010) + iterations=100599 (0x000188f7)
const HEADER12_HEX = '0000000100000010000188f7'

describe('lib/pbkdf2 — module shape / API', () => {
  it('exports exactly hash and compare functions', () => {
    expect(Object.keys(pbkdf2).sort()).toEqual(['compare', 'hash'])
    expect(typeof pbkdf2.hash).toBe('function')
    expect(typeof pbkdf2.compare).toBe('function')
  })

  it('hash is a 2-arg (password, callback) function', () => {
    expect(pbkdf2.hash.length).toBe(2)
  })

  it('compare is a 3-arg (password, shadow, callback) function', () => {
    expect(pbkdf2.compare.length).toBe(3)
  })
})

describe('lib/pbkdf2 — hash(): basic behavior', () => {
  it('hashing a password yields a non-empty string', async () => {
    const h = await hash('hunter2')
    expect(typeof h).toBe('string')
    expect(h.length).toBeGreaterThan(0)
  })

  it('the hash is distinct from the plaintext password', async () => {
    const h = await hash('hunter2')
    expect(h).not.toBe('hunter2')
    expect(h.includes('hunter2')).toBe(false)
  })

  it('invokes the callback with a null error on success', async () => {
    const result = await new Promise((resolve) => {
      pbkdf2.hash('hunter2', (err, h) => resolve({ err, h }))
    })
    expect(result.err).toBeNull()
    expect(typeof result.h).toBe('string')
  })

  it('produces a base64 string of length 80 for a typical password', async () => {
    const h = await hash('hunter2')
    expect(h.length).toBe(80)
  })

  it('decodes to a 60-byte buffer (12 header + 16 salt + 32 hash)', async () => {
    const h = await hash('hunter2')
    const buf = Buffer.from(h, 'base64')
    expect(buf.length).toBe(60)
  })
})

describe('lib/pbkdf2 — hash(): encoded structure / golden header', () => {
  it('embeds version=1 in the first 4 bytes (big-endian)', async () => {
    const buf = Buffer.from(await hash('hunter2'), 'base64')
    expect(buf.readUInt32BE(0)).toBe(1)
  })

  it('embeds salt length=16 in bytes 4..8 (big-endian)', async () => {
    const buf = Buffer.from(await hash('hunter2'), 'base64')
    expect(buf.readUInt32BE(4)).toBe(16)
  })

  it('embeds iteration count=100599 in bytes 8..12 (big-endian)', async () => {
    const buf = Buffer.from(await hash('hunter2'), 'base64')
    expect(buf.readUInt32BE(8)).toBe(100599)
  })

  it('the 12-byte header is identical across different passwords', async () => {
    const a = Buffer.from(await hash('alpha'), 'base64')
    const b = Buffer.from(await hash('bravo'), 'base64')
    expect(a.subarray(0, 12).equals(b.subarray(0, 12))).toBe(true)
  })

  it('the 12-byte header has the exact golden hex value', async () => {
    const buf = Buffer.from(await hash('anything'), 'base64')
    expect(buf.subarray(0, 12).toString('hex')).toBe(HEADER12_HEX)
  })

  it('the salt (bytes 12..28) differs between two hashes of different passwords', async () => {
    const a = Buffer.from(await hash('alpha'), 'base64')
    const b = Buffer.from(await hash('bravo'), 'base64')
    expect(a.subarray(12, 28).equals(b.subarray(12, 28))).toBe(false)
  })
})

describe('lib/pbkdf2 — random salt: same password, different hashes', () => {
  it('hashing the SAME password twice yields DIFFERENT encoded strings', async () => {
    const a = await hash('samepw')
    const b = await hash('samepw')
    expect(a).not.toBe(b)
  })

  it('both independently-salted hashes still verify the original password', async () => {
    const a = await hash('samepw')
    const b = await hash('samepw')
    expect(await compare('samepw', a)).toBe(true)
    expect(await compare('samepw', b)).toBe(true)
  })

  it('the differing bytes are in the salt region, not the header', async () => {
    const a = Buffer.from(await hash('samepw'), 'base64')
    const b = Buffer.from(await hash('samepw'), 'base64')
    expect(a.subarray(0, 12).equals(b.subarray(0, 12))).toBe(true) // header same
    expect(a.subarray(12, 28).equals(b.subarray(12, 28))).toBe(false) // salt differs
  })
})

describe('lib/pbkdf2 — compare(): correct vs wrong password', () => {
  it('compare(correctPassword, hash) resolves true', async () => {
    const h = await hash('hunter2')
    expect(await compare('hunter2', h)).toBe(true)
  })

  it('compare(wrongPassword, hash) resolves false', async () => {
    const h = await hash('hunter2')
    expect(await compare('wrongpw', h)).toBe(false)
  })

  it('compare passes a null error to its callback on a successful match', async () => {
    const h = await hash('hunter2')
    const result = await new Promise((resolve) => {
      pbkdf2.compare('hunter2', h, (err, ok) => resolve({ err, ok }))
    })
    expect(result.err).toBeNull()
    expect(result.ok).toBe(true)
  })

  it('compare passes a null error to its callback on a mismatch', async () => {
    const h = await hash('hunter2')
    const result = await new Promise((resolve) => {
      pbkdf2.compare('nope', h, (err, ok) => resolve({ err, ok }))
    })
    expect(result.err).toBeNull()
    expect(result.ok).toBe(false)
  })

  it('comparison is case-sensitive', async () => {
    const h = await hash('Hunter2')
    expect(await compare('Hunter2', h)).toBe(true)
    expect(await compare('hunter2', h)).toBe(false)
  })

  it('comparison is whitespace-sensitive', async () => {
    const h = await hash('secret')
    expect(await compare('secret', h)).toBe(true)
    expect(await compare('secret ', h)).toBe(false)
    expect(await compare(' secret', h)).toBe(false)
  })
})

describe('lib/pbkdf2 — fixed golden-master hash (deterministic verification)', () => {
  it('a previously-generated hash still verifies its original password', async () => {
    expect(await compare('hunter2', FIXED_HUNTER2)).toBe(true)
  })

  it('the fixed hash rejects a near-miss (different case)', async () => {
    expect(await compare('Hunter2', FIXED_HUNTER2)).toBe(false)
  })

  it('the fixed hash rejects a near-miss (trailing space)', async () => {
    expect(await compare('hunter2 ', FIXED_HUNTER2)).toBe(false)
  })

  it('the fixed hash rejects a unicode lookalike', async () => {
    expect(await compare('hünter2', FIXED_HUNTER2)).toBe(false)
  })

  it('the fixed hash decodes to the exact golden structure', async () => {
    const buf = Buffer.from(FIXED_HUNTER2, 'base64')
    expect(buf.length).toBe(60)
    expect(buf.readUInt32BE(0)).toBe(1) // version
    expect(buf.readUInt32BE(4)).toBe(16) // salt length
    expect(buf.readUInt32BE(8)).toBe(100599) // iterations
    expect(buf.subarray(12, 28).toString('hex')).toBe('156a795a5d912099d0144a05d3f00d62') // salt
  })

  it('matches the recorded golden snapshot string', () => {
    expect(FIXED_HUNTER2).toMatchSnapshot()
  })
})

describe('lib/pbkdf2 — empty-string password behavior', () => {
  it('hashing an empty string still PRODUCES a valid 80-char hash', async () => {
    const h = await hash('')
    expect(typeof h).toBe('string')
    expect(h.length).toBe(80)
    const buf = Buffer.from(h, 'base64')
    expect(buf.length).toBe(60)
    expect(buf.readUInt32BE(0)).toBe(1)
    expect(buf.readUInt32BE(4)).toBe(16)
    expect(buf.readUInt32BE(8)).toBe(100599)
  })

  it('but compare("", thatHash) returns FALSE — empty password short-circuits', async () => {
    const h = await hash('')
    // The guard `if (password && shadow)` treats '' as falsy, so verification
    // never runs and the callback fires false. This is the quirky lock-in.
    expect(await compare('', h)).toBe(false)
  })

  it('a non-empty password does NOT match an empty-password hash', async () => {
    const h = await hash('')
    expect(await compare('x', h)).toBe(false)
  })

  it('two empty-password hashes are distinct (random salt) yet both un-verifiable via compare', async () => {
    const a = await hash('')
    const b = await hash('')
    expect(a).not.toBe(b)
    expect(await compare('', a)).toBe(false)
    expect(await compare('', b)).toBe(false)
  })
})

describe('lib/pbkdf2 — compare(): falsy inputs short-circuit to (null, false)', () => {
  it('compare(null, null) -> false, no error, no throw', async () => {
    const r = await compareSafe(null, null)
    expect(r).toEqual({ threw: false, cbErr: null, ok: false })
  })

  it('compare(undefined, undefined) -> false, no error, no throw', async () => {
    const r = await compareSafe(undefined, undefined)
    expect(r).toEqual({ threw: false, cbErr: null, ok: false })
  })

  it('compare(validPassword, null shadow) -> false', async () => {
    const r = await compareSafe('pw', null)
    expect(r).toEqual({ threw: false, cbErr: null, ok: false })
  })

  it('compare(validPassword, undefined shadow) -> false', async () => {
    const r = await compareSafe('pw', undefined)
    expect(r).toEqual({ threw: false, cbErr: null, ok: false })
  })

  it('compare(null password, valid hash) -> false', async () => {
    const r = await compareSafe(null, FIXED_HUNTER2)
    expect(r).toEqual({ threw: false, cbErr: null, ok: false })
  })

  it('compare(validPassword, empty-string shadow) -> false', async () => {
    const r = await compareSafe('pw', '')
    expect(r).toEqual({ threw: false, cbErr: null, ok: false })
  })

  it('compare(empty-string password, valid hash) -> false', async () => {
    const r = await compareSafe('', FIXED_HUNTER2)
    expect(r).toEqual({ threw: false, cbErr: null, ok: false })
  })

  it('compare(0, 0) -> false (numeric falsy)', async () => {
    const r = await compareSafe(0, 0)
    expect(r).toEqual({ threw: false, cbErr: null, ok: false })
  })

  it('compare(false, false) -> false (boolean falsy)', async () => {
    const r = await compareSafe(false, false)
    expect(r).toEqual({ threw: false, cbErr: null, ok: false })
  })
})

describe('lib/pbkdf2 — compare(): malformed (truthy) shadow throws SYNCHRONOUSLY', () => {
  // Truthy but structurally invalid shadows cause Buffer offset reads to throw
  // synchronously (NOT via the callback). We lock that this is the current
  // behavior — the function is not defensive against garbage shadows.
  it('a non-base64 short string ("garbage") throws an offset-out-of-range error', async () => {
    const r = await compareSafe('pw', 'garbage')
    expect(r.threw).toBe(true)
    expect(r.error).toMatch(/offset.*out of range/i)
  })

  it('a tiny valid-base64 shadow ("AA") throws a memory-bounds error', async () => {
    const r = await compareSafe('pw', 'AA')
    expect(r.threw).toBe(true)
    expect(r.error).toMatch(/outside buffer bounds/i)
  })

  it('a single-char shadow ("a") throws', async () => {
    const r = await compareSafe('pw', 'a')
    expect(r.threw).toBe(true)
    expect(typeof r.error).toBe('string')
  })

  it('a punctuation shadow ("!!!") throws', async () => {
    const r = await compareSafe('pw', '!!!')
    expect(r.threw).toBe(true)
    expect(typeof r.error).toBe('string')
  })

  it('a truncated copy of a real hash (header only) throws', async () => {
    const r = await compareSafe('pw', FIXED_HUNTER2.slice(0, 8))
    expect(r.threw).toBe(true)
  })
})

describe('lib/pbkdf2 — hash()/compare() round-trips for varied passwords', () => {
  it('round-trips a long (1000-char) password', async () => {
    const long = 'x'.repeat(1000)
    const h = await hash(long)
    expect(Buffer.from(h, 'base64').length).toBe(60)
    expect(await compare(long, h)).toBe(true)
    expect(await compare('x'.repeat(999), h)).toBe(false)
  })

  it('round-trips a unicode/emoji password', async () => {
    const uni = 'pä$$wörд🔒'
    const h = await hash(uni)
    expect(await compare(uni, h)).toBe(true)
    expect(await compare('pa$$word', h)).toBe(false)
  })

  it('round-trips a password with spaces and special characters', async () => {
    const pw = 'p@ss w0rd! #$%^&*()'
    const h = await hash(pw)
    expect(await compare(pw, h)).toBe(true)
  })

  it('accepts a Buffer as the password and matches the equivalent string', async () => {
    const h = await hash(Buffer.from('bufferpw'))
    expect(typeof h).toBe('string')
    expect(await compare('bufferpw', h)).toBe(true)
  })

  it('a single-character password round-trips', async () => {
    const h = await hash('a')
    expect(await compare('a', h)).toBe(true)
    expect(await compare('b', h)).toBe(false)
  })

  it('hashes of two different passwords do not cross-verify', async () => {
    const ha = await hash('alpha')
    const hb = await hash('bravo')
    expect(await compare('alpha', ha)).toBe(true)
    expect(await compare('bravo', hb)).toBe(true)
    expect(await compare('alpha', hb)).toBe(false)
    expect(await compare('bravo', ha)).toBe(false)
  })
})
