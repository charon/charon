# Charon

A privacy-enabling account management and SSO solution. For end-users, it allows aggregating multiple existing
authenticators (Facebook, Google, etc.) in one place and managing different (and potentially multiple) identities
exposed to apps. Apps do not have to worry about user management nor multi-tenancy. And admins of communities
(tenants, domains, realms) using those apps can manage all users in one place, with tools to address any abuse.

## Current roadmap (in progress)

- Basic SSO: Initial implementation of a basic SSO supporting apps, users, communities, developers, and admins.
  - Users are able to authenticate themselves to Charon
  - Developers are able to register apps
  - Admins are able to create communities and enable apps in them
  - Users are able to authenticate to apps in communities
- Multiple identities per user: Add support for users to have multiple identities they can choose between to
  expose to apps.
  - Support for managing multiple identities per user
  - Support for selecting an identity when authenticating to an app
- User impersonation: Implement user impersonation as a way to communicate to apps the relation between users
  and identities.
  - Expose relation between identity and user in JWTs send to apps, when not hidden by the user
- User management: Various management interfaces in Charon.
  - Admins can list users which authenticated in their community, and which apps they used
  - Users can list communities and apps they have authenticated to, and corresponding identities they used
- Handling abuse: Implement abuse handling process.
  - Provide a way for users and apps to file a complaint about an identity
  - Community admins can review those complaints and request primary identity reveal and all corresponding
    identities used in the community
  - Whole process has a public audit page where everyone can see if admin decided to request reveal or not
    (but identities are visible only to the admin)

Goals:

- Security first with great user experience.
- Beautiful and intuitive UI/UX.
- Account creation and management from both user's perspective and admin's perspective.
- Standard compliant OAuth and OpenID Connect provider.
- Account can be part of multiple communities, with different identities for different communities.
- Each community can use multiple apps.
- User can authorize all apps in a community, or individual apps.
- Allowing users to link many other authentication providers to their accounts.
- U2F support.
- Stable reactivity-enabled API, which is used by Charon's frontend as well.
- Support for identity impersonation, multiple identites per app, and ad-hoc anonymous identites.
  [#1](https://gitlab.com/charon/charon/issues/1)
- Everything is logged and auditable.

## Future features

- Proactive pushing of changes to all apps authorized for a user.
- User invitation workflow with reminders.
- Centralized management communities and roles inside communities.
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

## Related projects

- [Keycloak](https://www.keycloak.org) – enterprise grade, very similar to goals of this project, but: this project
  aims to have one account for multiple realms (which we call communities),
  with custom identites per realm (i.e., the hierarchy/control is different from Keycloak), moreover, it aims to be
  much simpler in scope, and with admin interface being usable by end-users to manage
  their communities (Keycloak's admin interface, when enabled for end-users, is quite technical)
- [StackExchange](https://stackexchange.com/) – an inspiration for this project with its centralized standard-based
  account system spawning multiple communities,
  but not available as a stand-alone open source system
- [Sandstorm](https://sandstorm.io/) – another inspiration for this project as it demonstrates how you can decouple
  user management from apps, making app integration easy, while having a trusted, non-customizable and independent
  UI for both users and admins; it offers a structure similar to what Charon is targeting (communities of users
  having instances of apps); moreover, it similarly removes everything related to authentication and permissions
  out of apps: apps just have to trust a HTTP header which provides information about the current user; their user
  management is tightly integrated with the platform while Charon is stand-alone (and thus more reusable as a building
  block) with additional features around privacy and abuse control
- [Google Account](https://en.wikipedia.org/wiki/Google_Account) – another inspiration of great user flows and quality,
  but not open source and thus not reusable, moreover, accounts are not shared
  between domains (which we call communities) but are tied to a domain, something which we want to change with this
  project (in Charon, you have only one account but multiple identities for different domains)
- [Ory](https://www.ory.sh/) – open source identity infrastructure supporting OAuth and OpenID Connect, with focus
  on standard compliance, with this project it shares the realization
  of a need for [identity infrastructure service](https://www.ory.sh/docs/next/kratos/concepts/) solutions, but this
  project is innovating with multiple identities per account,
  auditable impersonation, and proactive pushing of changes to apps
- [Gravitee AM](https://gravitee.io/products/am/) – lightweight and easy to use system, but it does not support
  communities nor impersonation
- [Auth0](https://auth0.com/) – cloud service providing seamless integration of authentication and authorization
  for apps, hiding the fact that it is being used from the user,
  but this project aims to be visible to all stakeholders (users, apps, admins), allowing them to control their
  aspect of its use, moreover, it allows admins (of a community)
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

## GitHub mirror

There is also a [read-only GitHub mirror available](https://github.com/charon/charon),
if you need to fork the project there.

## Funding

This project was funded through the [NGI Zero Entrust](https://nlnet.nl/entrust/), a
fund established by NLnet with financial support from the European Commission's
[Next Generation Internet](https://ngi.eu/) programme, under the aegis of DG Communications
Networks, Content and Technology under grant agreement No 101069594.
