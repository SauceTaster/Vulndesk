// Run the full Vulndesk server against a throwaway in-memory MongoDB, with a
// seeded admin user — zero external setup. For local evaluation / "does it work".
//   node scripts/dev-mem.cjs    (admin / testpass on http://localhost:3555)
const { MongoMemoryServer } = require('mongodb-memory-server')

;(async () => {
  const mem = await MongoMemoryServer.create()
  const uri = mem.getUri('vulndesk')

  process.env.NODE_ENV = process.env.NODE_ENV || 'development'
  process.env.SESSION_SECRET = process.env.SESSION_SECRET || 'dev-only-secret'

  // Point the (require-time) config at the in-memory DB before app.js loads it.
  const conf = require('../config/conf')
  conf.database = uri

  // app.js connects mongoose on require but only binds a port when run directly
  // (require.main === module) so supertest can import it — so we listen here.
  const app = require('../app.js')

  const mongoose = require('mongoose')
  await mongoose.connection.asPromise()

  app.listen(conf.serverPort, conf.serverHost, () => {
    console.log('Server started at http://' + conf.serverHost + ':' + conf.serverPort)
  })

  // Seed an admin so you can log in.
  const User = require('../models/user')
  const pbkdf2 = require('../lib/pbkdf2.js')
  const hash = await new Promise((res, rej) =>
    pbkdf2.hash('testpass', (e, h) => (e ? rej(e) : res(h)))
  )
  await User.findOneAndUpdate(
    { username: 'admin' },
    { name: 'Admin', username: 'admin', email: 'admin@example.com', emoji: '🛡️', password: hash, priv: 0, group: 'dev' },
    { upsert: true, setDefaultsOnInsert: true }
  )
  console.log('SEEDED: admin / testpass   (in-memory Mongo: ' + uri + ')')
})().catch((e) => {
  console.error('dev-mem failed:', e)
  process.exit(1)
})
