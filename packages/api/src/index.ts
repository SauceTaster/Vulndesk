import { serve } from '@hono/node-server'
import { createDb } from '@vulndesk/db'
import { createApp } from './app.js'

const connectionString = process.env.DATABASE_URL
if (!connectionString) {
  // eslint-disable-next-line no-console
  console.error('DATABASE_URL is required to start the Vulndesk API.')
  process.exit(1)
}

const db = createDb(connectionString)
const app = createApp(db)
const port = Number(process.env.PORT ?? 3000)

serve({ fetch: app.fetch, port }, (info) => {
  // eslint-disable-next-line no-console
  console.log(
    `Vulndesk API on http://localhost:${info.port}  (docs: /docs · spec: /openapi.json)`
  )
})
