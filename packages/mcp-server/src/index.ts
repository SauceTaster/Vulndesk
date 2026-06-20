#!/usr/bin/env node
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { createServer } from './server.js'

async function main(): Promise<void> {
  const server = createServer()
  const transport = new StdioServerTransport()
  await server.connect(transport)
  // Logs must go to stderr — stdout is the MCP protocol channel.
  console.error('Vulndesk MCP server running on stdio')
}

main().catch((err) => {
  console.error('Fatal error starting Vulndesk MCP server:', err)
  process.exit(1)
})
