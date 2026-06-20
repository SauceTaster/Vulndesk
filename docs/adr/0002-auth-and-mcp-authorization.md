# ADR-0002: Authentication, authorization & MCP token validation

- **Status:** Accepted
- **Date:** 2026-06-20
- **Deciders:** SauceTaster (maintainer)
- **Refines:** the auth section of [ADR-0001](./0001-modern-typescript-stack.md)
- **Evidence:** read against the current BetterAuth docs (organization, MCP, OAuth
  Provider, JWT, Hono integration) and the MCP authorization spec — see References.

## Context

Vulndesk is multi-tenant (organizations → teams → members) and exposes an HTTP API
plus an MCP server. We need: real authn, multi-tenant RBAC (replacing today's
broken single-trust-tier `priv` model), and MCP access that conforms to the
OAuth-2.1-resource-server model. This ADR pins the **concrete, docs-verified**
BetterAuth API so implementation is execution, not research.

## Decision

### Plugins (server)

BetterAuth is the **OAuth 2.1 authorization server**, mounted inside the Hono API:

```ts
import { betterAuth } from 'better-auth'
import { jwt, organization } from 'better-auth/plugins'
import { oauthProvider } from '@better-auth/oauth-provider'
import { drizzleAdapter } from 'better-auth/adapters/drizzle'

export const auth = betterAuth({
  database: drizzleAdapter(db, { provider: 'pg' }),
  plugins: [
    jwt(),                       // JWKS-verifiable JWTs at /.well-known/jwks (must precede consumers)
    oauthProvider({              // OAuth 2.1 AS — supersedes mcp() AND oidcProvider()
      loginPage: '/sign-in',
      consentPage: '/consent',
      allowDynamicClientRegistration: true,         // RFC 7591 (MCP clients)
      allowUnauthenticatedClientRegistration: true, // public MCP clients
      validAudiences: [MCP_RESOURCE_URI, API_RESOURCE_URI], // RFC 8707 audience binding
      // Embed tenant context so resource servers authorize statelessly:
      customAccessTokenClaims: ({ referenceId }) => ({ org: referenceId }),
    }),
    organization({ ac, roles, teams: { enabled: true, allowRemovingAllTeams: false } }),
  ],
})
```

**Why `oauthProvider`, not `mcp()`/`oidcProvider()`:** the current docs state `mcp()`
"will soon be deprecated in favor of the OAuth Provider Plugin," and `oauthProvider`
explicitly **replaces both**, unifying endpoints under `/oauth2/*`. We do not build
on a deprecated surface.

### RBAC model (organization plugin)

```ts
import { createAccessControl } from 'better-auth/plugins/access'
import { defaultStatements, adminAc, memberAc, ownerAc } from 'better-auth/plugins/organization/access'

const statement = {
  ...defaultStatements,                              // organization, member, invitation, team
  advisory: ['create', 'read', 'update', 'delete', 'publish'],
} as const
const ac = createAccessControl(statement)

const roles = {
  owner:  ac.newRole({ ...ownerAc.statements,  advisory: ['create','read','update','delete','publish'] }),
  admin:  ac.newRole({ ...adminAc.statements,  advisory: ['create','read','update','delete','publish'] }),
  member: ac.newRole({ ...memberAc.statements, advisory: ['create','read','update'] }),
  viewer: ac.newRole({ advisory: ['read'] }),        // the audit-S2 read-only tier, as a real role
}
```

Enforce server-side with `auth.api.hasPermission({ headers, body: { permissions: { advisory: ['publish'] } } })`.
Start with **static roles**; `dynamicAccessControl` (DB-stored custom roles) is a
later, additive switch — not v1.

### Hono mount

```ts
app.use('/api/auth/*', cors({ origin: WEB_ORIGIN, credentials: true,
  allowHeaders: ['Content-Type', 'Authorization'], allowMethods: ['GET','POST','OPTIONS'] })) // BEFORE routes
app.on(['POST', 'GET'], '/api/auth/*', (c) => auth.handler(c.req.raw))
app.use('*', async (c, next) => {                    // session middleware
  const session = await auth.api.getSession({ headers: c.req.raw.headers })
  c.set('user', session?.user ?? null)
  c.set('session', session?.session ?? null)
  await next()
})
// Hono Variables typed via typeof auth.$Infer.Session.user/session
```

### MCP server as OAuth 2.1 resource server

The MCP server validates tokens **statelessly** against the AS's JWKS — it never
shares BetterAuth's DB/session:

```ts
import { verifyAccessToken } from 'better-auth/oauth2'
const payload = await verifyAccessToken(bearer, {
  verifyOptions: { issuer: AS_URL, audience: MCP_RESOURCE_URI }, // RFC 8707, canonical URI, no trailing slash
  scopes: ['advisory:read'],
})
// authorize from payload.org (+ role/scope claims); reject any token whose aud != us
```

- Serve **RFC 9728 Protected Resource Metadata** at `/.well-known/oauth-protected-resource`
  via `oAuthProtectedResourceMetadata(auth)` (or BetterAuth's **`mcpAuthOfficial`**
  adapter, which targets the official MCP SDK that `@vulndesk/mcp-server` already uses).
- 401 with `WWW-Authenticate: Bearer resource_metadata="…"`; 403 `insufficient_scope`.
- **Auth applies to the HTTP (Streamable-HTTP) MCP transport.** The current **stdio**
  bin stays for local/trusted use (no OAuth over stdio); authed document tools ship
  on the HTTP transport guarded by the above.

### Database

BetterAuth owns its tables (`user`, `session`, `account`, `verification`,
`organization`, `member`, `invitation`, `team`, `teamMember`, the oauth/jwks tables;
`session` gains `activeOrganizationId`/`activeTeamId`). Generate them with
`npx @better-auth/cli generate` into the Drizzle schema and keep them in the
committed migration set (ADR-0001 §2.4). Our domain tables (`documents`, `comments`,
`files`) carry `org_id` and are protected by Postgres RLS in addition to
`hasPermission` checks.

## Consequences

- One AS (BetterAuth) issues JWTs that the API and the MCP server both verify
  statelessly via JWKS — no per-call DB lookup, no shared session coupling.
- The org/role lives in the token (`customAccessTokenClaims`), so resource-server
  authz is a claim check; defense-in-depth remains RLS + `hasPermission`.
- Enterprise SSO (OIDC/SAML via BetterAuth SSO plugin) and the MCP
  Enterprise-Managed-Auth (ID-JAG) extension are kept-open seams, not v1.

### Risks / follow-ups

- ⚠️ **`@better-auth/oauth-provider` is new/moving** — pin exact helper signatures
  (`oauthProvider`, `verifyAccessToken`, `oAuthProtectedResourceMetadata`,
  `mcpAuthOfficial`) against the installed `.d.ts` before coding; re-check each bump.
- ⚠️ **RFC 8707 audience binding** must match exactly (client `resource` param ↔
  token `aud` ↔ RS expected audience; canonical URI, no trailing slash) or every
  request 401s. Cover with a test.
- Keep the generated BetterAuth Drizzle tables in migrations whenever plugins change
  (e.g. `organizationRole` if dynamic AC is later enabled).
- `jwt()` must be registered before `oauthProvider` or tokens are opaque and the RS
  can't verify offline.

## References

- BetterAuth: [organization](https://better-auth.com/docs/plugins/organization) ·
  [MCP](https://better-auth.com/docs/plugins/mcp) ·
  [OAuth Provider](https://better-auth.com/docs/plugins/oauth-provider) ·
  [JWT](https://better-auth.com/docs/plugins/jwt) ·
  [Hono](https://better-auth.com/docs/integrations/hono)
- MCP [authorization spec](https://modelcontextprotocol.io/specification/draft/basic/authorization) ·
  [RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728) ·
  [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html)
