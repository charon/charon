# Charon

A privacy-enabling account management and SSO solution. For end-users, it allows aggregating multiple existing
authenticators (Facebook, Google, etc.) in one place and managing different (and potentially multiple) identities
exposed to apps. Apps do not have to worry about user management nor multi-tenancy. And admins of organizations
(communities, tenants, domains, realms) using those apps can manage all users in one place, with tools to address any abuse.

## Current roadmap (in progress)

- Basic SSO: Initial implementation of a basic SSO supporting apps, users, organizations, developers, and admins.
  - Users are able to authenticate themselves to Charon
  - Developers are able to register apps
  - Admins are able to create organizations and enable apps in them
  - Users are able to authenticate to apps in organizations
- Multiple identities per user: Add support for users to have multiple identities they can choose between to
  expose to apps.
  - Support for managing multiple identities per user
  - Support for selecting an identity when authenticating to an app
- Identity sharing: Support for sharing identities between users.
- User management: Various management interfaces in Charon.
  - Admins can list users which authenticated in their organization, and which apps they used
  - Users can list organizations and apps they have authenticated to, and corresponding identities they used
- Handling abuse: Implement abuse handling process.
  - Provide a way for users and apps to file a complaint about an identity
  - Organization admins can review those complaints and request primary identity reveal and all corresponding
    identities used in the organization
  - Whole process has a public audit page where everyone can see if admin decided to request reveal or not
    (but identities are visible only to the admin)

Goals:

- Security first with great user experience.
- Beautiful and intuitive UI/UX.
- Account creation and management from both user's perspective and admin's perspective.
- Standard compliant OAuth and OpenID Connect provider.
- Account can be part of multiple organizations, with different identities for different organizations.
- Each organization can use multiple apps.
- User can authorize all apps in an organization, or individual apps.
- Allowing users to link many other authentication providers to their accounts.
- U2F support.
- Stable reactivity-enabled API, which is used by Charon's frontend as well.
- Support for identity impersonation, multiple identites per app, and ad-hoc anonymous identites.
  [#1](https://gitlab.com/charon/charon/issues/1)
- Everything is logged and auditable.

## Future features

- Proactive pushing of changes to all apps authorized for a user.
- User invitation workflow with reminders.
- Centralized management of organizations and roles inside organizations.
- Federation: other authentication providers can be other Charon instances.
- Integration with identify verification providers without exposing details to apps
  (i.e., app just learns that user has been verified, is unique user, and has satisfied KYC
  requirements, without learning anything more about the user beyond what user exposes in their identity).
- Support for melding of multiple accounts and identities into one. [#1](https://gitlab.com/charon/charon/issues/1)
- Virtual accounts which can be only impersonated. [#2](https://gitlab.com/charon/charon/issues/2)
- Proxy to log all access and allow/deny high-level access to an app and app's APIs.
- Scoped API tokens to delegate further.
- Scoped subaccounts. [#3](https://gitlab.com/charon/charon/issues/3)
- Internationalization and localization.
- E-mail proxying.

## Installation

You can run Charon behind a reverse proxy (which should support HTTP2), or simply run it directly
(it is safe to do so). Charon is compiled into one backend binary which has frontend files embedded
and they are served by the backend as well.

Currently, Charon is under development and you have to build the binary yourself. After cloning
the repository, run:

```sh
make
```

This will create `charon` binary.

It requires [Go](https://golang.org/) 1.23 or newer.
Node 20 or newer is required as well.

Automatic media type detection uses file extensions and a file extension database has to be available
on the system.
On Alpine this can be `mailcap` package.
On Debina/Ubuntu `media-types` package.

## Usage

To run Charon you need a HTTPS TLS certificate (as required by HTTP2). When running locally
you can use [mkcert](https://github.com/FiloSottile/mkcert), a tool to create a local CA
keypair which is then used to create a TLS certificate. Use Go 1.23.10 or newer.

```sh
go install filippo.io/mkcert@latest
mkcert -install
mkcert localhost 127.0.0.1 ::1
```

This creates two files, `localhost+2.pem` and `localhost+2-key.pem`, which you can provide to Charon as:

```sh
./charon -k localhost+2.pem -K localhost+2-key.pem ...
```

Temporary accepted self-signed certificates are not recommended because
[not all browser features work](https://stackoverflow.com/questions/74161355/are-any-web-features-not-available-in-browsers-when-using-self-signed-certificat).
If you want to use a self-signed certificate instead of `mkcert`, add the certificate to
your browser's certificate store.

## Development

During Charon development run backend and frontend as separate processes. During development the backend
proxies frontend requests to Vite, which in turn compiles frontend files and serves them, hot-reloading
the frontend as necessary.

### Backend

The backend is implemented in [Go](https://golang.org/) (requires 1.23 or newer)
and provides a HTTP2 API. Node 20 or newer is required as well.

Then clone the repository and run:

```sh
make
./charon -D -k localhost+2.pem -K localhost+2-key.pem
```

`localhost+2.pem` and `localhost+2-key.pem` are files of a TLS certificate
generated as described in the [Usage section](#usage).
Backend listens at [https://localhost:8080/](https://localhost:8080/).

`-D` CLI flag makes the backend proxy unknown requests (non-API requests)
to the frontend. In this mode any placeholders in HTML files are not rendered.
Charon also expects a secret and private keys to use. During development, you can
use self-generated ones with the `-D` CLI flag.

Because SMTP is not configured during development, e-mails (with codes) will be printed out to the console instead.

You can also run `make watch` to reload the backend on file changes. You have to install
[CompileDaemon](https://github.com/githubnemo/CompileDaemon) first:

```sh
go install github.com/githubnemo/CompileDaemon@latest
```

### Frontend

The frontend is implemented in [TypeScript](https://www.typescriptlang.org/) and
[Vue](https://vuejs.org/) and during development we use [Vite](https://vitejs.dev/).
Vite compiles frontend files and serves them. It also watches for changes in frontend files,
recompiles them, and hot-reloads the frontend as necessary. Node 20 or newer is required.

To install all dependencies and run frontend for development:

```sh
npm install
npm run serve
```

Open [https://localhost:8080/](https://localhost:8080/) in your browser, which will connect
you to the backend which then proxies unknown requests (non-API requests) to the frontend.

## Related projects

- [Keycloak](https://www.keycloak.org) – enterprise grade, very similar to goals of this project, but: this project
  aims to have one account for multiple realms (which we call organizations),
  with custom identites per realm (i.e., the hierarchy/control is different from Keycloak), moreover, it aims to be
  much simpler in scope, and with admin interface being usable by end-users to manage
  their organizations (Keycloak's admin interface, when enabled for end-users, is quite technical)
- [StackExchange](https://stackexchange.com/) – an inspiration for this project with its centralized standard-based
  account system spawning multiple organizations,
  but not available as a stand-alone open source system
- [Sandstorm](https://sandstorm.io/) – another inspiration for this project as it demonstrates how you can decouple
  user management from apps, making app integration easy, while having a trusted, non-customizable and independent
  UI for both users and admins; it offers a structure similar to what Charon is targeting (organizations of users
  having instances of apps); moreover, it similarly removes everything related to authentication and permissions
  out of apps: apps just have to trust a HTTP header which provides information about the current user; their user
  management is tightly integrated with the platform while Charon is stand-alone (and thus more reusable as a building
  block) with additional features around privacy and abuse control
- [Google Account](https://en.wikipedia.org/wiki/Google_Account) – another inspiration of great user flows and quality,
  but not open source and thus not reusable, moreover, accounts are not shared
  between domains (which we call organizations) but are tied to a domain, something which we want to change with this
  project (in Charon, you have only one account but multiple identities for different domains)
- [Ory](https://www.ory.sh/) – open source identity infrastructure supporting OAuth and OpenID Connect, with focus
  on standard compliance, with this project it shares the realization
  of a need for [identity infrastructure service](https://www.ory.sh/docs/next/kratos/concepts/) solutions, but this
  project is innovating with multiple identities per account,
  auditable impersonation, and proactive pushing of changes to apps
- [Gravitee AM](https://gravitee.io/products/am/) – lightweight and easy to use system, but it does not support
  organizations nor impersonation
- [Auth0](https://auth0.com/) – cloud service providing seamless integration of authentication and authorization
  for apps, hiding the fact that it is being used from the user,
  but this project aims to be visible to all stakeholders (users, apps, admins), allowing them to control their
  aspect of its use, moreover, it allows admins (of an organization)
  to be a different entity from developers of apps
- [Gluu](https://gluu.org) – open source identity infrastructure, seems to be pretty extensive and can support
  impersonation, but not multiple user identities
- [Apple ID SSO](https://support.apple.com/guide/deployment/intro-to-single-sign-on-depfdbf18f55/web) – a closed
  source and centralized SSO service which does enable users to hide their e-mail address from apps by proxying them
- [GoTrue](https://github.com/netlify/gotrue) – small service for handling user registration and authentication,
  very low level and without user interface
- [Casdoor](https://casdoor.org/) – open source authentication service combinings users, organizations and
  applications in a similar this project does, but does not enable users to control their identity exposed to apps
- [Mozilla Persona](https://en.wikipedia.org/wiki/Mozilla_Persona) – was an identity provider integrated with Firefox
  browser, but it did not gain enough traction; this project is more than an identity provider adds many other
  features for both users and app developers
- [Eartho](https://github.com/earthodev/eartho) – shares similar goals with Charon, both serving
  as a trusted authentication intermediary, but they have different focuses. Charon aims to
  support multiple identities you freely create and choose between.

## GitHub mirror

There is also a [read-only GitHub mirror available](https://github.com/charon/charon),
if you need to fork the project there.

## Acknowledgements

This project was funded through the [NGI Zero Entrust](https://nlnet.nl/entrust/), a
fund established by NLnet with financial support from the European Commission's
[Next Generation Internet](https://ngi.eu/) programme, under the aegis of DG Communications
Networks, Content and Technology under grant agreement No 101069594.
