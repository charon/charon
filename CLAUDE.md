# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Charon is a privacy-enabling account management and SSO solution built with Go backend and Vue.js/TypeScript frontend.
It implements OAuth 2.0 and OpenID Connect standards with support for multiple identities per user, organizational
management, and third-party authentication providers.

## Development Commands

### Backend Development

- `make` - Build the complete application with embedded frontend
- `make build` - Build backend binary with embedded frontend dist files
- `make watch` - Auto-rebuild and restart backend on file changes (requires CompileDaemon)
- `./charon -D -k localhost+2.pem -K localhost+2-key.pem` - Run backend in development mode with TLS

### Frontend Development

- `npm install` - Install frontend dependencies
- `npm run serve` - Start Vite dev server (runs on port 5173, proxied through backend on 8080)
- `npm run build` - Build frontend for production (output to `dist/`)

### Testing and Quality

- `make test` - Run Go tests with coverage
- `make test-ci` - Run tests with CI output formats
- `npm run test` - Run frontend tests with Vitest
- `npm run coverage` - Generate frontend test coverage

### Linting and Formatting

- `make lint` - Run Go linter (golangci-lint) with auto-fix
- `make fmt` - Format Go code with gofumpt and goimports
- `npm run lint` - Run ESLint on frontend code
- `npm run lint-style` - Run Stylelint on CSS/Vue files
- `npm run lint-vue` - Run Vue TypeScript compiler check
- `npm run fmt` - Format frontend code with Prettier

## Architecture

### Backend (Go)

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

### Backend Code Style

- **CI Commands**: For backend-only changes, run these commands to match CI validation:
  - `make lint` - Go linter (golangci-lint) with auto-fix
  - `make fmt` - Go code formatting with gofumpt and goimports
  - `make test` - Go tests with coverage
  - `make lint-docs` - Documentation linting (affects whole repo)
  - `make audit` - Go security audit with nancy

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

### Frontend Code Style

- **Import Convention**: Always use `@/` alias for internal imports, never relative paths (`./`, `../`)
- **Import Organization**: Type imports must be at the top with `import type`, followed by empty line, then regular imports
- **Internationalization**: All user-facing text must use `useI18n()` composition API with precompiled messages
  - Never translate technical terms like "passkey" - hardcode them directly in components
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

## Development Setup Requirements

- Go 1.23+ required
- Node.js 20+ required  
- TLS certificates needed (recommend mkcert for local development)
- CompileDaemon for backend auto-reload during development
