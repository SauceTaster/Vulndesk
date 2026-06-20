# @vulndesk/db

The Vulndesk data layer — **Drizzle ORM on PostgreSQL** — plus the one-way
**Mongo→Postgres migrator**. This is the "off Mongo" brick (see
[ADR-0003](../../docs/adr/0003-self-host-first-and-editor.md)).

> Single-tenant for self-host (ADR-0003). Multi-tenant `org_id`/RLS is a deferred,
> additive change (ADR-0002).

## Schema

- `users` (mirrors the legacy user model; `password_hash` is the existing pbkdf2 hash)
- `documents` — `body jsonb` (the CVE/advisory record), promoted `cve_id`/`state`,
  unique `(section, doc_id)`, GIN `jsonb_path_ops` for `@>` containment
- `comments`, `files` — normalized out of the legacy embedded arrays, FK to `documents`

Every row carries `legacy_mongo_id` so the migrator is **idempotent** (re-runnable).

## Usage

```ts
import { createDb, documents } from '@vulndesk/db'
const db = createDb(process.env.DATABASE_URL!) // postgres.js
```

Migrating from Mongo (the caller owns the mongoose cursor; this package does not
depend on mongoose):

```ts
import { migrateDocs } from '@vulndesk/db'
await migrateDocs(db, 'cve5', mongoCursor, { idPath: 'cveMetadata.cveId' })
```

## Migrations

```bash
npm run -w @vulndesk/db db:generate   # diff schema -> committed SQL (drizzle/)
npm run -w @vulndesk/db db:migrate    # apply to $DATABASE_URL
```

Tests run against **PGlite** (Postgres-in-WASM) applying the same committed
migrations — `test/db.test.js`.
