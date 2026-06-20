// Characterization (golden-master) tests for the Express app (app.js).
//
// These integration tests run the REAL app against an in-memory MongoDB via
// supertest. They lock down the CURRENT request/response behavior so that the
// upcoming refactors (MongoDB -> DocumentDB, Passport/sessions -> BetterAuth,
// CSS -> Tailwind, a frontend bundler, consolidating CVE transforms into
// @vulndesk/core) surface ANY regression. We are recording what the code does
// TODAY, not judging correctness.
//
// IMPORTANT setup detail discovered by probing: config/conf.js builds
// `conf.database` from MONGO_* env vars, NOT from DATABASE_URL. So setting
// DATABASE_URL alone does nothing. We require the conf module first and point
// `conf.database` at the in-memory server's URI BEFORE requiring app.js (app.js
// reads conf at require-time and connects immediately).

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { createRequire } from 'module'

const require = createRequire(import.meta.url)
// Load the app's TypeScript graph the way it runs in production — under tsx's
// Node require hook — rather than through vite. This keeps the dynamically
// required .js plugin configs in CommonJS/sloppy mode and resolves the .ts
// source modules, matching real runtime semantics exactly.
require('tsx/cjs/api').register()
const request = require('supertest')

let mem
let app
let mongoose
let User
let pbkdf2

// A minimal, well-formed PUBLISHED CVE Record Format 5.x record (mirrors the
// fixture used in test/core-validate.test.js; probed to validate as { valid:true }).
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
      descriptions: [
        { lang: 'en', value: 'A sufficiently long test vulnerability description.' },
      ],
      affected: [
        { vendor: 'Acme', product: 'Widget', versions: [{ version: '1.0', status: 'affected' }] },
      ],
      references: [{ url: 'https://example.com/advisory' }],
    },
  },
}

const TEST_USER = {
  name: 'Test User',
  username: 'testuser',
  email: 'test@example.com',
  emoji: 'fox',
  rawPassword: 'Sup3rSecret!',
  priv: 0,
}

// Pull the _csrf hidden input value out of a rendered login form.
function parseCsrf(html) {
  const m =
    html.match(/name=['"]_csrf['"][^>]*value=['"]([^'"]+)['"]/) ||
    html.match(/value=['"]([^'"]+)['"][^>]*name=['"]_csrf['"]/)
  return m ? m[1] : null
}

beforeAll(async () => {
  const { MongoMemoryServer } = require('mongodb-memory-server')
  mem = await MongoMemoryServer.create()
  const uri = mem.getUri('vulndesk')

  // env that app.js / session config reads at require-time
  process.env.DATABASE_URL = uri
  process.env.SESSION_SECRET = 'test-secret'
  process.env.NODE_ENV = 'test'

  // conf.database is derived from MONGO_* vars, so override it directly to point
  // the app at the in-memory server. This mutates the in-memory required module,
  // not any source file.
  const conf = require('../config/conf')
  conf.database = uri

  // Require the app (via the tsx hook registered above) AFTER env + conf are
  // set so it connects to our test DB. tsx and the test share Node's require
  // cache, so this conf mutation is the same instance the app reads.
  app = require('../app.ts')
  mongoose = require('mongoose')
  User = require('../models/user.ts')
  pbkdf2 = require('../lib/pbkdf2.ts')

  // The global ensureConnected middleware returns 500 until mongoose is ready,
  // so wait for the connection to be fully open before issuing any request.
  if (mongoose.connection.readyState !== 1) {
    await mongoose.connection.asPromise()
  }

  // Seed a single privileged user for the authenticated / stretch tests.
  const hash = await new Promise((res, rej) =>
    pbkdf2.hash(TEST_USER.rawPassword, (e, h) => (e ? rej(e) : res(h)))
  )
  await User.create({
    name: TEST_USER.name,
    username: TEST_USER.username,
    email: TEST_USER.email,
    emoji: TEST_USER.emoji,
    password: hash,
    priv: TEST_USER.priv,
  })
}, 60000)

afterAll(async () => {
  if (mongoose) await mongoose.disconnect()
  if (mem) await mem.stop()
}, 30000)

// ---------------------------------------------------------------------------
// Login page (public, GET /users/login)
// ---------------------------------------------------------------------------
describe('GET /users/login (public login page)', () => {
  it('responds 200', async () => {
    const res = await request(app).get('/users/login')
    expect(res.status).toBe(200)
  })

  it('returns an HTML content-type', async () => {
    const res = await request(app).get('/users/login')
    expect(res.headers['content-type']).toMatch(/text\/html/)
  })

  it('renders a login form posting to /users/login', async () => {
    const res = await request(app).get('/users/login')
    expect(res.text).toMatch(/<form[^>]*method=['"]?POST['"]?/i)
    expect(res.text).toMatch(/action=['"]\/users\/login['"]/)
  })

  it('includes a username and password field', async () => {
    const res = await request(app).get('/users/login')
    expect(res.text).toMatch(/name=['"]username['"]/)
    expect(res.text).toMatch(/name=['"]password['"]/)
  })

  it('embeds a CSRF hidden input with a non-empty token', async () => {
    const res = await request(app).get('/users/login')
    expect(res.text).toMatch(/name=['"]_csrf['"]/)
    const token = parseCsrf(res.text)
    expect(typeof token).toBe('string')
    expect(token.length).toBeGreaterThan(0)
  })

  it('sets a session cookie (connect.sid)', async () => {
    const res = await request(app).get('/users/login')
    const cookies = res.headers['set-cookie'] || []
    expect(cookies.join(';')).toMatch(/connect\.sid=/)
  })

  it('marks the session cookie HttpOnly and SameSite=Lax', async () => {
    const res = await request(app).get('/users/login')
    const cookies = (res.headers['set-cookie'] || []).join(';')
    expect(cookies).toMatch(/HttpOnly/i)
    expect(cookies).toMatch(/SameSite=Lax/i)
  })
})

// ---------------------------------------------------------------------------
// Authentication gate: unauthenticated access to protected routes
// ---------------------------------------------------------------------------
describe('unauthenticated access to protected routes redirects to /users/login', () => {
  it('GET /home -> 302 /users/login', async () => {
    const res = await request(app).get('/home')
    expect(res.status).toBe(302)
    expect(res.headers['location']).toBe('/users/login')
  })

  it('GET /users/list -> 302 /users/login', async () => {
    const res = await request(app).get('/users/list')
    expect(res.status).toBe(302)
    expect(res.headers['location']).toBe('/users/login')
  })

  it('GET /users/list/json -> 302 /users/login', async () => {
    const res = await request(app).get('/users/list/json')
    expect(res.status).toBe(302)
    expect(res.headers['location']).toBe('/users/login')
  })

  it('GET /users/list/css -> 302 /users/login', async () => {
    const res = await request(app).get('/users/list/css')
    expect(res.status).toBe(302)
    expect(res.headers['location']).toBe('/users/login')
  })

  it('GET /users/profile -> 302 /users/login', async () => {
    const res = await request(app).get('/users/profile')
    expect(res.status).toBe(302)
    expect(res.headers['location']).toBe('/users/login')
  })

  it('GET /home/stats -> 302 /users/login', async () => {
    const res = await request(app).get('/home/stats')
    expect(res.status).toBe(302)
    expect(res.headers['location']).toBe('/users/login')
  })

  // Characterization quirk: the bare /cve path currently 404s (the cve5 section
  // router registers no matching route for it), whereas /nvd hits the auth gate
  // and 302s. We record both observed behaviors exactly as they are today.
  it('GET /cve -> 404 (cve section bare path has no matching route)', async () => {
    const res = await request(app).get('/cve')
    expect(res.status).toBe(404)
  })

  it('GET /nvd -> 302 /users/login (nvd section route is auth-gated)', async () => {
    const res = await request(app).get('/nvd')
    expect(res.status).toBe(302)
    expect(res.headers['location']).toBe('/users/login')
  })

  it('GET /nvd/list -> 302 /users/login', async () => {
    const res = await request(app).get('/nvd/list')
    expect(res.status).toBe(302)
    expect(res.headers['location']).toBe('/users/login')
  })
})

// ---------------------------------------------------------------------------
// /api/validate authentication gate (unauthenticated)
// ---------------------------------------------------------------------------
describe('POST /api/validate is behind ensureAuthenticated', () => {
  it('unauthenticated POST -> 302 /users/login', async () => {
    const res = await request(app).post('/api/validate').send({ foo: 'bar' })
    expect(res.status).toBe(302)
    expect(res.headers['location']).toBe('/users/login')
  })

  it('unauthenticated POST with a valid record body still -> 302 /users/login', async () => {
    const res = await request(app).post('/api/validate').send(validRecord)
    expect(res.status).toBe(302)
    expect(res.headers['location']).toBe('/users/login')
  })

  it('unauthenticated POST with empty body -> 302 /users/login', async () => {
    const res = await request(app).post('/api/validate').send({})
    expect(res.status).toBe(302)
    expect(res.headers['location']).toBe('/users/login')
  })

  it('GET /api/validate -> 404 (only POST is defined)', async () => {
    const res = await request(app).get('/api/validate')
    expect(res.status).toBe(404)
  })
})

// ---------------------------------------------------------------------------
// Root and homepage redirect
// ---------------------------------------------------------------------------
describe('GET / (root)', () => {
  it('redirects 302 to the configured homepage (/home)', async () => {
    const res = await request(app).get('/')
    expect(res.status).toBe(302)
    expect(res.headers['location']).toBe('/home')
  })
})

// ---------------------------------------------------------------------------
// Logout (public)
// ---------------------------------------------------------------------------
describe('GET /users/logout', () => {
  it('redirects 302 to /users/login even when unauthenticated', async () => {
    const res = await request(app).get('/users/logout')
    expect(res.status).toBe(302)
    expect(res.headers['location']).toBe('/users/login')
  })
})

// ---------------------------------------------------------------------------
// 404 for unknown paths
// ---------------------------------------------------------------------------
describe('unknown paths return 404', () => {
  it('GET a nonexistent path -> 404', async () => {
    const res = await request(app).get('/totally-missing-xyz')
    expect(res.status).toBe(404)
  })

  it('the 404 body is the Express default "Cannot GET" page', async () => {
    const res = await request(app).get('/totally-missing-xyz')
    expect(res.text).toMatch(/Cannot GET \/totally-missing-xyz/)
  })

  it('POST to a nonexistent path -> 404', async () => {
    const res = await request(app).post('/totally-missing-xyz').send({})
    expect(res.status).toBe(404)
    expect(res.text).toMatch(/Cannot POST \/totally-missing-xyz/)
  })
})

// ---------------------------------------------------------------------------
// Security headers (helmet) and the deliberate ABSENCE of CORS / x-powered-by
// ---------------------------------------------------------------------------
describe('security headers (helmet)', () => {
  it('sets x-content-type-options: nosniff', async () => {
    const res = await request(app).get('/users/login')
    expect(res.headers['x-content-type-options']).toBe('nosniff')
  })

  it('does NOT send an access-control-allow-origin header', async () => {
    const res = await request(app).get('/users/login')
    expect(res.headers['access-control-allow-origin']).toBeUndefined()
  })

  it('disables x-powered-by', async () => {
    const res = await request(app).get('/users/login')
    expect(res.headers['x-powered-by']).toBeUndefined()
  })

  it('sets x-frame-options: SAMEORIGIN', async () => {
    const res = await request(app).get('/users/login')
    expect(res.headers['x-frame-options']).toBe('SAMEORIGIN')
  })

  it('sets a Strict-Transport-Security header', async () => {
    const res = await request(app).get('/users/login')
    expect(res.headers['strict-transport-security']).toMatch(/max-age=\d+/)
  })

  it('sets referrer-policy: no-referrer', async () => {
    const res = await request(app).get('/users/login')
    expect(res.headers['referrer-policy']).toBe('no-referrer')
  })

  it('sets cross-origin-opener-policy: same-origin', async () => {
    const res = await request(app).get('/users/login')
    expect(res.headers['cross-origin-opener-policy']).toBe('same-origin')
  })

  it('sets x-dns-prefetch-control: off', async () => {
    const res = await request(app).get('/users/login')
    expect(res.headers['x-dns-prefetch-control']).toBe('off')
  })

  it('does NOT set a content-security-policy (CSP disabled in helmet config)', async () => {
    const res = await request(app).get('/users/login')
    expect(res.headers['content-security-policy']).toBeUndefined()
  })

  it('exposes express-rate-limit headers (limit 200/min)', async () => {
    const res = await request(app).get('/users/login')
    expect(res.headers['x-ratelimit-limit']).toBe('200')
  })
})

// ---------------------------------------------------------------------------
// CSRF enforcement on the login POST
// ---------------------------------------------------------------------------
describe('CSRF protection on POST /users/login', () => {
  it('POST without a CSRF token -> 403', async () => {
    const agent = request.agent(app)
    await agent.get('/users/login') // establish a session
    const res = await agent
      .post('/users/login')
      .type('form')
      .send({ username: 'x', password: 'y' })
    expect(res.status).toBe(403)
  })

  it('403 with Accept: application/json returns the leaked error JSON (non-prod NODE_ENV)', async () => {
    const agent = request.agent(app)
    await agent.get('/users/login')
    const res = await agent
      .post('/users/login')
      .set('Accept', 'application/json')
      .type('form')
      .send({ username: 'x', password: 'y' })
    expect(res.status).toBe(403)
    expect(res.headers['content-type']).toMatch(/application\/json/)
    expect(res.body).toEqual({ ok: 0, msg: 'invalid csrf token' })
  })

  it('403 with Accept: text/html renders the Vulndesk splash page', async () => {
    const agent = request.agent(app)
    await agent.get('/users/login')
    const res = await agent
      .post('/users/login')
      .set('Accept', 'text/html')
      .type('form')
      .send({ username: 'x', password: 'y' })
    expect(res.status).toBe(403)
    expect(res.headers['content-type']).toMatch(/text\/html/)
    expect(res.text).toMatch(/Vulndesk/)
  })
})

// ---------------------------------------------------------------------------
// Full login flow (Passport local + CSRF) and authenticated behavior — STRETCH
// ---------------------------------------------------------------------------
describe('login flow + authenticated requests (stretch)', () => {
  it('valid credentials with CSRF -> 302 /home', async () => {
    const agent = request.agent(app)
    const page = await agent.get('/users/login')
    const token = parseCsrf(page.text)
    const res = await agent
      .post('/users/login')
      .type('form')
      .send({ _csrf: token, username: TEST_USER.username, password: TEST_USER.rawPassword })
    expect(res.status).toBe(302)
    expect(res.headers['location']).toBe('/home')
  })

  it('wrong password with CSRF -> 302 /users/login', async () => {
    const agent = request.agent(app)
    const page = await agent.get('/users/login')
    const token = parseCsrf(page.text)
    const res = await agent
      .post('/users/login')
      .type('form')
      .send({ _csrf: token, username: TEST_USER.username, password: 'wrong-password' })
    expect(res.status).toBe(302)
    expect(res.headers['location']).toBe('/users/login')
  })

  it('unknown username with CSRF -> 302 /users/login', async () => {
    const agent = request.agent(app)
    const page = await agent.get('/users/login')
    const token = parseCsrf(page.text)
    const res = await agent
      .post('/users/login')
      .type('form')
      .send({ _csrf: token, username: 'nobody', password: 'whatever' })
    expect(res.status).toBe(302)
    expect(res.headers['location']).toBe('/users/login')
  })

  it('after login, GET /users/list -> 200', async () => {
    const agent = request.agent(app)
    const page = await agent.get('/users/login')
    const token = parseCsrf(page.text)
    await agent
      .post('/users/login')
      .type('form')
      .send({ _csrf: token, username: TEST_USER.username, password: TEST_USER.rawPassword })
    const res = await agent.get('/users/list')
    expect(res.status).toBe(200)
  })

  it('authenticated POST /api/validate with a valid record -> { valid: true, errors: [], messages: [] }', async () => {
    const agent = request.agent(app)
    const page = await agent.get('/users/login')
    const token = parseCsrf(page.text)
    await agent
      .post('/users/login')
      .type('form')
      .send({ _csrf: token, username: TEST_USER.username, password: TEST_USER.rawPassword })

    const res = await agent.post('/api/validate').send(validRecord)
    expect(res.status).toBe(200)
    expect(res.body).toEqual({ valid: true, errors: [], messages: [] })
  })

  it('authenticated POST /api/validate with an invalid record -> valid:false with errors and messages', async () => {
    const agent = request.agent(app)
    const page = await agent.get('/users/login')
    const token = parseCsrf(page.text)
    await agent
      .post('/users/login')
      .type('form')
      .send({ _csrf: token, username: TEST_USER.username, password: TEST_USER.rawPassword })

    const res = await agent.post('/api/validate').send({ dataType: 'CVE_RECORD' })
    expect(res.status).toBe(200)
    expect(res.body.valid).toBe(false)
    expect(Array.isArray(res.body.errors)).toBe(true)
    expect(res.body.errors.length).toBeGreaterThan(0)
    expect(Array.isArray(res.body.messages)).toBe(true)
    expect(res.body.messages.length).toBe(res.body.errors.length)
    // messages are AJV error one-liners formatted by @vulndesk/core.formatErrors
    expect(typeof res.body.messages[0]).toBe('string')
  })

  it('authenticated POST /api/validate with an empty object -> valid:false', async () => {
    const agent = request.agent(app)
    const page = await agent.get('/users/login')
    const token = parseCsrf(page.text)
    await agent
      .post('/users/login')
      .type('form')
      .send({ _csrf: token, username: TEST_USER.username, password: TEST_USER.rawPassword })

    const res = await agent.post('/api/validate').send({})
    expect(res.status).toBe(200)
    expect(res.body.valid).toBe(false)
    expect(res.body.errors.length).toBeGreaterThan(0)
  })

  it('username login is effectively case-insensitive — "TestUser" logs in to /home', async () => {
    // The User schema declares `username: { lowercase: true }`, so the stored
    // value is lowercased and an uppercase submission still authenticates and
    // redirects to /home. This records the CURRENT (case-insensitive) behavior.
    const agent = request.agent(app)
    const page = await agent.get('/users/login')
    const token = parseCsrf(page.text)
    const res = await agent
      .post('/users/login')
      .type('form')
      .send({ _csrf: token, username: 'TestUser', password: TEST_USER.rawPassword })
    expect(res.status).toBe(302)
    expect(res.headers['location']).toBe('/home')
  })

  it('after login, GET /users/list/json returns a JSON enum payload', async () => {
    const agent = request.agent(app)
    const page = await agent.get('/users/login')
    const token = parseCsrf(page.text)
    await agent
      .post('/users/login')
      .type('form')
      .send({ _csrf: token, username: TEST_USER.username, password: TEST_USER.rawPassword })

    const res = await agent.get('/users/list/json')
    expect(res.status).toBe(200)
    expect(res.headers['content-type']).toMatch(/application\/json/)
    expect(res.body).toHaveProperty('default')
    expect(res.body).toHaveProperty('enum')
    expect(Array.isArray(res.body.enum)).toBe(true)
  })

  it('after login, GET /users/list/css returns text/css emoji rules', async () => {
    const agent = request.agent(app)
    const page = await agent.get('/users/login')
    const token = parseCsrf(page.text)
    await agent
      .post('/users/login')
      .type('form')
      .send({ _csrf: token, username: TEST_USER.username, password: TEST_USER.rawPassword })

    const res = await agent.get('/users/list/css')
    expect(res.status).toBe(200)
    expect(res.headers['content-type']).toMatch(/text\/css/)
  })
})

// ---------------------------------------------------------------------------
// Static assets served from /public
// ---------------------------------------------------------------------------
describe('static file serving from /public', () => {
  it('a missing static asset falls through to 404', async () => {
    const res = await request(app).get('/this-asset-does-not-exist.js')
    expect(res.status).toBe(404)
  })
})
