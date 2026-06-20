import { serve } from '@hono/node-server'
import app from './app.js'

const port = Number(process.env.PORT ?? 3000)

serve({ fetch: app.fetch, port }, (info) => {
  // eslint-disable-next-line no-console
  console.log(
    `Vulndesk API on http://localhost:${info.port}  (docs: /docs · spec: /openapi.json)`
  )
})
