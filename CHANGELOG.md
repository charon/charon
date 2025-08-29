# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Documentation for running Charon.
- Documentation for using Charon Dashboard.

## [0.5.0] - 2025-08-29

### Added

- Access token type (HMAC or JWT) can be configured for OIDC clients.
- Lifespan for access tokens, ID tokens, and refresh tokens can be configured for OIDC clients.
- Internationalization support with English and Slovenian locales.
  [#8](https://gitlab.com/charon/charon/-/issues/8)
- Activity log for users to see actions related to their identities.
- Activity log for organization admins to see actions related to their organizations.
- Support for organization admins to block identities and accounts. Blocking is logged
  in the activity log for transparency.

## [0.4.0] - 2025-06-16

### Added

- Organization admins can list users which authenticated in their community and see which apps they used.
- Users can list organizations and apps they have authenticated to, and corresponding identities they used.
  Similarly, for each identity they can see to which organizations and apps they have authenticated.

### Changed

- Go 1.23.10 or newer is required.

## [0.3.0] - 2025-04-21

### Added

- Support for sharing identities between users. Identities can be shared at two levels:
  "users" (can use the identity) and "admins" (can modify the identity and join organizations).
- Support for sharing administration of organizations and application templates between users.

### Changed

- Charon Dashboard is now an OIDC application which uses the same authentication flow as
  other applications. Users can now use multiple identities with it as well.
- Go 1.23.6 or newer is required.

## [0.2.0] - 2024-09-17

### Added

- Support for managing multiple identities per user.
- Support for selecting an identity when authenticating to an application.

### Changed

- Go 1.23 or newer is required.

## [0.1.0] - 2024-02-15

### Added

- Users are able to authenticate themselves to Charon.
- Developers are able to create application templates.
- Admins are able to create organizations and enable applications in them.
- Users are able to authenticate to applications in organizations.

[unreleased]: https://gitlab.com/charon/charon/-/compare/v0.5.0...main
[0.5.0]: https://gitlab.com/charon/charon/-/compare/v0.4.0...v0.5.0
[0.4.0]: https://gitlab.com/charon/charon/-/compare/v0.3.0...v0.4.0
[0.3.0]: https://gitlab.com/charon/charon/-/compare/v0.2.0...v0.3.0
[0.2.0]: https://gitlab.com/charon/charon/-/compare/v0.1.0...v0.2.0
[0.1.0]: https://gitlab.com/charon/charon/-/tags/v0.1.0

<!-- markdownlint-disable-file MD024 -->
