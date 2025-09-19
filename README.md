# Charon

A privacy-enabling account management and SSO solution. For end-users, it allows aggregating multiple existing
authenticators (Facebook, Google, etc.) in one place and managing different (and potentially multiple) identities
exposed to apps. Apps do not have to worry about user management nor multi-tenancy. And admins of organizations
(communities, tenants, domains, realms) using those apps can manage all users in one place, with tools to address any abuse.

**WARNING: This project is still in development. Do not use in production.**

## Features

- Supports multiple authentication mechanisms: username/e-mail & password, one-time codes,
  passkeys, OIDC. Providers officially supported: Google, Facebook.
- It uses a separation between accounts (a set of credentials the user has to sign-in into Charon) and identities (how
  the user presents themselves to apps).
- It supports individual and shared identities. Shared identities are those which are used by multiple users.
  Of course it provides tools to manage permissions over shared identities.
- Supports multiple organizations which can share users and applications, but from the perspective of each organization
  those users and applications are separate, do not share IDs and are managed independently.
- Organization admins can manage users and applications in their organizations.
- App developers can manage application templates for their apps which can then be used in organizations.
- It provides abuse handling tools for organization admins, e.g., to block users and accounts.
- It gives users the control over their identities and personal data.
- It does not differentiate between sign-in and sign-up – both are the same flow for the user.
- It supports internationalization and localization.

### Planned features

- More authentication mechanisms: SAML, recovery codes.
- Proactive pushing of changes to all apps authorized for a user.
- User invitation workflow with reminders.
- Management of roles inside organizations in one place.
- Integration with identify verification providers without exposing details to apps
  (i.e., app just learns that user has been verified, is unique user, and has satisfied KYC
  requirements, without learning anything more about the user beyond what user exposes in their identity).
- Support for melding of multiple accounts into one.
- E-mail proxying.

## Installation

You can run Charon behind a reverse proxy (which should support HTTP2), or simply run it directly
(it is safe to do so). Charon is compiled into one backend binary which has frontend files embedded
and they are served by the backend as well.

The [releases page](https://gitlab.com/charon/charon/-/releases)
contains a list of stable versions. Each includes:

- A statically compiled binary.
- Docker images.

### Static binary

The latest stable statically compiled binary for Linux (amd64) is available at:

[`https://gitlab.com/charon/charon/-/releases/permalink/latest/downloads/linux-amd64/charon`](https://gitlab.com/charon/charon/-/releases/permalink/latest/downloads/linux-amd64/charon)

You can also download older versions on the [releases page](https://gitlab.com/charon/charon/-/releases).

The latest successfully built development (`main` branch) binary is available at:

[`https://gitlab.com/charon/charon/-/jobs/artifacts/main/raw/charon-linux-amd64?job=docker`](https://gitlab.com/charon/charon/-/jobs/artifacts/main/raw/charon-linux-amd64?job=docker)

### Docker

Docker images for stable versions are available as:

`registry.gitlab.com/charon/charon/tag/<version>:latest`

`<version>` is a version string with `.` replaced with `-`. E.g., `v0.1.0` becomes `v0-1-0`.

The docker image contains only Charon binary, which is image's entrypoint.
If you need a shell as well, then use the debug version of the image:

`registry.gitlab.com/charon/charon/tag/<version>:latest-debug`

In that case you have to override the entrypoint (i.e., `--entrypoint sh` argument to `docker run`).

The latest successfully built development (`main` branch) image is available as:

`registry.gitlab.com/charon/charon/branch/main:latest`

generated in the current directory as described above:

## Usage

Create a file with a secret used for session and OIDC HMAC.
It has to be base64 (URL encoding, no padding) encoded 32 bytes with `chs-` prefix.

```sh
echo "chs-$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=')" > .hmac.secret
export SECRET_PATH=.hmac.secret
```

You should generate a RSA private key and convert it to JWK format. For conversion
to JWK you can use [jwker](https://github.com/jphastings/jwker).

```sh
go install github.com/jphastings/jwker/cmd/jwker@latest
openssl genpkey -algorithm RSA -out rsa-key.pem -pkeyopt rsa_keygen_bits:2048
jwker rsa-key.pem .rsa-key.jwk
rm rsa-key.pem
export OIDC_KEYS_RSA_PATH=.rsa-key.jwk
```

Next, to run Charon you need a HTTPS TLS certificate (as required by HTTP2). When running locally
you can use [mkcert](https://github.com/FiloSottile/mkcert), a tool to create a local CA
keypair which is then used to create a TLS certificate.

```sh
go install filippo.io/mkcert@latest
mkcert -install
mkcert localhost 127.0.0.1 ::1
```

This creates two files, `localhost+2.pem` and `localhost+2-key.pem`, which you can provide to Charon as:

```sh
./charon -k localhost+2.pem -K localhost+2-key.pem
```

When running using Docker, you have to provide them (and `.hmac.secret` and `.rsa-key.jwk` files)
to the container through a volume, e.g.:

```sh
docker run -d --name charon -p 8080:8080 -v "$(pwd):/data" \
 registry.gitlab.com/charon/charon/branch/main:latest \
 -k /data/localhost+2.pem -K /data/localhost+2-key.pem \
 --secret=/data/.hmac.secret --oidc.keys.rsa=/data/.rsa-key.jwk
```

Open [https://localhost:8080/](https://localhost:8080/) in your browser to access the web interface.

Temporary accepted self-signed certificates are not recommended because
[not all browser features work](https://stackoverflow.com/questions/74161355/are-any-web-features-not-available-in-browsers-when-using-self-signed-certificat).
If you want to use a self-signed certificate instead of `mkcert`, add the certificate to
your browser's certificate store.

When running it directly publicly on the Internet (it is safe to do so), Charon is able to
obtain a HTTPS TLS certificate from [Let's Encrypt](https://letsencrypt.org) automatically:

```sh
docker run -d --name charon -p 443:8080 -v "$(pwd):/data" \
 registry.gitlab.com/charon/charon/branch/main:latest \
 --secret=/data/.hmac.secret --oidc.keys.rsa=/data/.rsa-key.jwk \
 --domain public.domain.example.com -E name@example.com -C /data/letsencrypt
```

Charon would then be available at `https://public.domain.example.com`.

When using Let's Encrypt you accept its Terms of Service.

Charon sends e-mails (with codes) to users. For that it needs a SMTP server. Use `--mail.host`
and `--mail.from` CLI flags to configure it. Without SMTP server configured,
Charon logs e-mails to the console instead (use `docker logs charon` to see them).

### Charon Dashboard

Charon contains an embedded web application to manage organizations and applications.
When you open Charon in your browser you in fact see this web application. Sign-in into
it to start using it.

#### Creating your organization

After signing-in into Charon Dashboard, you can create your organization.
Click on "Organizations" and then "Create".

For users to be able to sign-in into your applications, you have to add applications
to your organization. But to be able to do that, you first need an application template
for the application.

### Creating an application template

Let's use [OpenID Connect Debugger](https://oidcdebugger.com/) as an example.
Choose "Application templates" in Charon Dashboard and then click "Create".
Enter "OpenID Connect Debugger" as name and create the template.

Charon supports that applications have three types of OIDC clients:

- public client: a client which is accessible on the web, but cannot have secrets
  (e.g., a frontend-only application)
- backend client: a client which is accessible on the web and can have secrets
  (e.g., a backend of the application)
- service client: a client which is not accessible on the web and can have secrets
  (e.g., a worker of the application)

For OpenID Connect Debugger add a public client and for OIDC redirect URI template
enter `{uriBase}/debug`. This is the location to which OIDC flow redirects and which
OpenID Connect Debugger app expects. Click "Update" to save the template.

`{uriBase}` is a default variable placeholder. If you do not need it, you can
remove it (but first you have to remove all uses of it). Or if you need more
variables, you can add them. Variables enable that applications are configured
and customized for each organization.

### Adding an application template to your organization

Now back on the Charon Dashboard page for your organization you should see
OpenID Connect Debugger under available applications. Click "Add" to add it
to your organization. You have to configure `uriBase` variable. Set it to
`https://oidcdebugger.com` exactly (no trailing `/` so that it will be
reconstructed to exactly `https://oidcdebugger.com/debug`).
Click "Activate" and then "Update". Note down the generated client ID.

Note that now that OpenID Connect Debugger application template exists
in Charon, anyone else can add it as application to their organization,
too.

### Signing-in into your application

Open [OpenID Connect Debugger](https://oidcdebugger.com/) and enter:

- Authorize URI: `https://localhost:8080/auth/oidc/authorize`
- Redirect URI: `https://oidcdebugger.com/debug`
- Client ID: the client ID generated previously
- Enable "Use PKCE".
- Token URI: `https://localhost:8080/api/auth/oidc/token`

On the bottom of the page click "Send request" to start the OIDC sign-in flow.
You will be redirected to Charon. Note that Charon is now asking you to sign-in
into OpenID Connect Debugger from your organization. Sign-in into Charon,
select the identity, and then complete the flow. You will be redirected back
to OpenID Connect Debugger which should tell you that the sign-in was successful
and it will obtain access and ID tokens.

In a real application, access token would be used by the application to know
that the user is authorized to access the application (and its API endpoints),
while ID token would provide to the application information about the user
(i.e., about their identity).

### Managing users

To see users which joined your organization, click "Manage" on the Charon
Dashboard page for your organization. There you can see that you joined
the organization and used OpenID Connect Debugger application.

Similarly, you can inspect activity log for your organization by clicking
"Activity" on the Charon Dashboard page for your organization.
You will see there that you joined the organization and signed-in into
OpenID Connect Debugger as well.

## Configuration

Charon can be configured through CLI arguments and a config file. CLI arguments have precedence
over the config file. Config file is a YAML file with the structure corresponding to the structure of
CLI flags and commands. Run `./charon --help` for list of available flags.

## Development

During Charon development run backend and frontend as separate processes. During development the backend
proxies frontend requests to Vite, which in turn compiles frontend files and serves them, hot-reloading
the frontend as necessary.

### Backend

The backend is implemented in [Go](https://golang.org/) (requires 1.23 or newer)
and provides a HTTP2 API. Node 20 or newer is required as well.

Automatic media type detection uses file extensions and a file extension database has
to be available on the system.
On Alpine this can be `mailcap` package.
On Debian/Ubuntu `media-types` package.

Then clone the repository and run:

```sh
make charon
./charon -D -k localhost+2.pem -K localhost+2-key.pem
```

`localhost+2.pem` and `localhost+2-key.pem` are files of a TLS certificate
generated as described in the [Usage section](#usage).
Backend listens at [https://localhost:8080/](https://localhost:8080/).

`-D` CLI flag makes the backend proxy unknown requests (non-API requests)
to the frontend. In this mode any placeholders in HTML files are not rendered.
Charon also expects a secret and private keys to use. During development, you can
use self-generated ones with the `-D` CLI flag.

Because SMTP is not configured during development, e-mails (with codes) will be printed
out to the console instead.

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
- [Casdoor](https://casdoor.org/) – open source authentication service combining users, organizations and
  applications in a similar this project does, but does not enable users to control their identity exposed to apps
- [Mozilla Persona](https://en.wikipedia.org/wiki/Mozilla_Persona) – was an identity provider integrated with Firefox
  browser, but it did not gain enough traction; this project is more than an identity provider adds many other
  features for both users and app developers
- [Eartho](https://github.com/earthodev/eartho) – shares similar goals with Charon, both serving
  as a trusted authentication intermediary, but they have different focuses; Charon aims to
  support multiple identities you freely create and choose between
- [Hanko](https://www.hanko.io/) – is an open source authentication and user management solution supporting many
  authentication mechanisms, it includes reusable web components for authentication and as such it provides a simple
  and self-contained way to integrate standard authentication into your solution; Charon aims to innovate
  around authentication and innovation and its goal is to push standard practices forward and as such its focus is
  on new ways to increase privacy and control for users while mitigating risks and abuses; at the same time it
  is designed from the ground up to support multiple organizations and applications with users and identities
  being potentially shared between them, while admins stay in control of their own organizations
- [Zitadel](https://zitadel.com/) – another open source all-batteries-included solution similar to Hanko
  while Charon is a more experimental project innovating in this space
- [Permit.io](https://www.permit.io/) – is a fullstack, plug-and-play application-level authorization solution;
  it is a good inspiration for Charon on how easy permission management can be done
- [passbolt](https://www.passbolt.com/) – is a collaborative password manager; Charon also aims to support
  sharing access but it attempts to do that by removing the need for passwords for multiple apps, replacing them
  with just access to the Charon itself, but downside is that then apps have to integrate with Charon and to
  ease that Charon has the concept of application templates
- [Wivi](https://yivi.app/en/) – a mobile app which gives user control over their identity and which information
  about their identity it shares with apps, at the same time it removes the need for passwords; it is similar
  to Charon in the sense that it can share with an app assertions about the user (e.g., user is older than 18)
  without revealing the exact data about the user to the app (e.g., user's birthdate)
- [Canaille](https://canaille.yaal.coop/) – another open source identity and authorization management solution
  with focus on being lightweight and easy to integrate; Charon is similar but also wants to support multiple
  organizations and shared users across them

## GitHub mirror

There is also a [read-only GitHub mirror available](https://github.com/charon/charon),
if you need to fork the project there.

## Acknowledgements

This project was funded through the [NGI Zero Entrust](https://nlnet.nl/entrust/), a
fund established by [NLnet](https://nlnet.nl/) with financial support from the European Commission's
[Next Generation Internet](https://ngi.eu/) programme, under the aegis of DG Communications
Networks, Content and Technology under grant agreement No 101069594.
