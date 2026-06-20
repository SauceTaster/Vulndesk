# @vulndesk/mcp-server

A [Model Context Protocol](https://modelcontextprotocol.io) server that exposes
[`@vulndesk/core`](../core) to LLM clients for **assisted CVE/advisory authoring**.

> 🚧 Building in public — early. v1 is stateless (validation + schema).
> Authenticated document tools (create / list / comment) land with the data +
> authz layer and will be gated by the same RBAC model.

## What it exposes

**Tools**
- `validate_cve_record` — validate a CVE Record Format 5.x record against the
  official CVE JSON Schema. Accepts a JSON object or a JSON string; returns
  `{ valid, errorCount, errors[] }`.

**Resources**
- `cve5://schema` — the canonical CVE Record Format 5.x JSON Schema, so a model
  can learn the exact shape before drafting a record.

## Run it

```bash
# from the monorepo (builds @vulndesk/core + this package on install)
npm install
node packages/mcp-server/dist/index.js   # speaks MCP over stdio
```

## Use it from an MCP client

Add to your client's MCP config (e.g. Claude Desktop / Claude Code
`mcpServers`). Until it's published to npm, point at the built bin:

```json
{
  "mcpServers": {
    "vulndesk": {
      "command": "node",
      "args": ["/absolute/path/to/Vulndesk/packages/mcp-server/dist/index.js"]
    }
  }
}
```

Then ask your assistant to draft a CVE record and call `validate_cve_record` to
check it against the official schema before you publish.

## Develop

```bash
npm run -w @vulndesk/mcp-server build       # tsup -> dist (ESM bin + types)
npm run -w @vulndesk/mcp-server typecheck   # tsc --noEmit
npm test                                    # vitest (test/mcp-server.test.js)
```
