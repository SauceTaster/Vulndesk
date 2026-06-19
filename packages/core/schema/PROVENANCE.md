# Vendored CVE Record Format schema

`CVE_Record_Format.json` and its referenced sub-schemas (`imports/cvss/*`,
`tags/*`) are the **canonical, structural** CVE Record Format 5.x JSON Schemas,
vendored verbatim from the upstream CVE Project:

- Source: <https://github.com/CVEProject/cve-schema> (`schema/`), `main` branch.
- Fetched: 2026-06-19.
- Draft: JSON Schema draft-07.

These are distinct from `default/cve5/cve5.schema.json` in the app, which is the
same format **extended with JSONEditor UI keywords** (`options`, `format: grid`,
runtime `$ref`s to `/users/list/json`, …) and is therefore not directly usable
for headless AJV validation. Keeping the pristine structural schema here is the
"split the schema" step from the modernization roadmap.

To refresh: re-fetch the files from the upstream `schema/` tree and update the
"Fetched" date above.
