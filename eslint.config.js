const js = require('@eslint/js')
const globals = require('globals')
const prettier = require('eslint-config-prettier')

// Linting currently targets the server-side code and tests. The browser/editor
// assets under public/ and the vendored schema/plugin assets under default/ are
// intentionally excluded — they are modernized as part of the frontend phase.
module.exports = [
  {
    ignores: [
      'node_modules/**',
      'packages/*/node_modules/**',
      'standalone/**',
      'public/**',
      'default/**',
      'custom/**',
      'coverage/**',
      // Build/migration utilities — linted in a later pass (some use octal
      // literals / implicit globals that need their own cleanup).
      'scripts/**',
    ],
  },
  js.configs.recommended,
  {
    files: [
      'app.js',
      'init-vulndesk.js',
      'routes/**/*.js',
      'models/**/*.js',
      'config/**/*.js',
      'lib/**/*.js',
      'packages/**/*.js',
    ],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'commonjs',
      globals: { ...globals.node },
    },
    rules: {
      // no-undef stays an error: it catches the class of bug Phase 1 fixed
      // (e.g. an undeclared `next` in a route handler).
      'no-undef': 'error',
      // Legacy code has many unused locals; surface them without failing CI.
      'no-unused-vars': 'warn',
      'no-redeclare': 'warn',
      'no-empty': 'warn',
      // Cosmetic / low-risk in legacy code — warn rather than block (touching
      // regexes and prototype-method access risks behavior changes).
      'no-useless-escape': 'warn',
      'no-prototype-builtins': 'warn',
    },
  },
  {
    files: ['test/**/*.js', 'vitest.config.js', 'eslint.config.js'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: { ...globals.node },
    },
    rules: {
      'no-unused-vars': 'warn',
    },
  },
  prettier,
]
