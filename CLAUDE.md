# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Charon is a privacy-enabling account management and SSO solution built with Go backend and Vue.js/TypeScript frontend.
It implements OAuth 2.0 and OpenID Connect standards with support for multiple identities per user, organizational
management, and third-party authentication providers.

## Development

### Backend (Go)

- `make` - Build the complete application with embedded frontend
- `make build` - Build backend binary with embedded frontend dist files

### Frontend (Node/TypeScript/Vue)

- `npm install` - Install frontend dependencies
- `npm run serve` - Start Vite dev server (runs on port 5173, proxied through backend on 8080)
- `npm run build` - Build frontend for production (output to `dist/`)

### Internationalization (i18n)

- `npm run generate-vue-i18n` - Generate TypeScript definitions for vue-i18n from `src/locales/en.json`

**Important**: The file `src/vue-i18n.d.ts` is automatically generated and should NOT be edited manually.
To update internationalization TypeScript definitions:

1. Modify `src/locales/en.json` with your locale changes
2. Run `npm run generate-vue-i18n` to regenerate the TypeScript definitions
3. The script `generate-vue-i18n.js` uses Vue i18n Global resource schema approach for type safety

### Testing and Quality

- `make test` - Run Go tests with coverage
- `make test-ci` - Run tests with CI output formats
- `npm run test-ci` - Run frontend tests with Vitest (CI mode - exits after completion)
- `npm run test` - Run frontend tests with Vitest (watch mode - never exits, do NOT use in CI)
- `npm run coverage` - Generate frontend test coverage

### Linting and Formatting

- `make lint` - Run Go linter (golangci-lint) with auto-fix
- `make fmt` - Format Go code with gofumpt and goimports
- `npm run lint` - Run ESLint on frontend code
- `npm run lint-style` - Run Stylelint on CSS/Vue files
- `npm run lint-vue` - Run Vue TypeScript compiler check
- `npm run fmt` - Format frontend code with Prettier

### Backend Code Style

- **Comments**: All comments must end with dots for consistency.
- **Error Handling**: When error is `errors.E`, use `errE` as variable name and assertion should be of
  form `require.NoError(t, errE, "% -+#.1v", errE)`.
- **CI Commands**: For backend-only changes, run these commands to match CI validation:
  - `make lint` - Go linter (golangci-lint) with auto-fix
  - `make fmt` - Go code formatting with gofumpt and goimports
  - `make test` - Go tests with coverage
  - `make lint-docs` - Documentation linting (affects whole repo)
  - `make audit` - Go security audit with nancy

### Frontend Code Style

- **Comments**: All comments must end with dots for consistency
- **Import Convention**: Always use `@/` alias for internal imports, never relative paths (`./`, `../`)
- **Import Organization**: Type imports for external packages must be at the top with `import type`, followed by
  empty line, then type imports for local packages, followed by empty line, then regular imports for external packages,
  followed by empty line, then regular imports for local packages; each group sorted in alphabetical order
- **Internationalization**: All user-facing text must use vue-i18n with global scope
  - **useI18n**: Always use `useI18n({ useScope: 'global' })` instead of `useI18n()`
  - **i18n-t components**: Always include `scope="global"` attribute: `<i18n-t keypath="..." scope="global">`
  - Technical terms like "passkey" should be extracted into translatable strings but not translated across languages
  - **Never put HTML in translated strings** - HTML formatting must always be in Vue templates, not translation files
    - ❌ Wrong: `"message": "<strong>Success!</strong> Operation completed"`
    - ✅ Correct: `"message": "{strong} Operation completed"` with `<i18n-t>` template interpolation
- **TypeScript**: Strict typing enabled with vue-i18n message schema validation
- **Formatting**: Always run `npm run fmt` after making changes to maintain consistent code formatting
  - Use double quotes (`"`) for strings, not single quotes (`'`)
  - Multi-line Vue template attributes should break after `>` and before `<` on closing tags
  - Files should end with newlines
  - Consistent spacing and indentation per Prettier configuration
- **CI Commands**: For frontend-only changes, run these commands to match CI validation:
  - `npm run lint` - ESLint with auto-fix
  - `npm run lint-vue` - Vue TypeScript compilation check
  - `npm run lint-style` - Stylelint with auto-fix
  - `npm run fmt` - Prettier formatting
  - `npm run test-ci` - Frontend tests with coverage
  - `make lint-docs` - Documentation linting (affects whole repo)
  - `npm audit` - Security audit

### Development Architecture

- Backend serves as proxy to Vite dev server in development mode (`-D` flag)
- Production builds embed frontend files into Go binary via `embed.FS`
- Hot module replacement works through backend proxy during development
- TypeScript strict mode enabled
- Uses Vue 3 Composition API (Options API disabled via `__VUE_OPTIONS_API__: false`)

### Development Setup Requirements

- Go 1.25+ required
- Node.js 24+ required
- TLS certificates needed (recommend mkcert for local development)
- CompileDaemon for backend auto-reload during development

## Architecture

### Backend

- **Entry Point**: `cmd/charon/main.go` - CLI setup and configuration parsing
- **Core Service**: Root-level Go files implement the main application logic
- **Authentication**: Multiple auth flows supported - password, passkey (WebAuthn), OIDC providers
- **OIDC Implementation**: Full OAuth 2.0 and OpenID Connect provider using Fosite library
- **Data Models**: Organizations, Applications, Identities, Users with complex relationships
- **Configuration**: Extensive CLI flags and environment variables via Kong library

### Key Backend Components

- `auth_*.go` - Authentication flow implementations
- `oidc_*.go` - OpenID Connect endpoints and logic
- `organization.go`, `identity.go`, `account.go` - Core data models
- `config.go` - Application configuration and CLI setup
- `init.go` - System initialization and bootstrapping

### Frontend (Vue 3 + TypeScript)

- **Framework**: Vue 3 with Composition API and TypeScript
- **Build Tool**: Vite for development and production builds
- **Styling**: Tailwind CSS with custom components
- **Router**: Vue Router for SPA navigation
- **API Layer**: Custom fetch wrappers in `src/api.ts`
- **Internationalization**: Vue-i18n v11 with precompiled messages (English and Slovenian support)

### Frontend Structure

- `src/views/` - Main page components
- `src/partials/` - Reusable page sections
- `src/components/` - UI components (Button, Input, etc.)
- `src/locales/` - Translation files (en.json, sl.json)
- `src/i18n.ts` - Vue-i18n configuration
- `src/types.d.ts` - TypeScript type definitions
- `src/flow.ts`, `src/auth.ts` - Authentication flow logic

### Authentication Flows

- Multiple authentication methods: password (with Argon2id), WebAuthn passkeys, OIDC providers
- Complex flow state management between frontend and backend
- Support for organization-scoped authentication and multiple user identities

### Security Features

- HTTPS required (HTTP/2 support)
- WebAuthn for passwordless authentication
- Argon2id password hashing with WASM frontend implementation
- CSRF protection and secure session management
- OIDC-compliant token handling
