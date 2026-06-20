// Ambient module declarations for the server's untyped runtime dependencies,
// so the TypeScript port type-checks. (These packages ship no types; the
// querymen + json-patch-extended layers are slated for replacement anyway.)
declare module 'querymen'
declare module 'json-patch-extended'
declare module 'express-messages'
declare module 'sanitize-filename'

// The browser CVE-transform layer is required server-side by routes/onedoc.
// It is plain JS outside the TS project; type it loosely here.
declare module '*/public/js/util.js' {
  const textUtil: any
  export = textUtil
}
