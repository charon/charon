# Charon

A privacy-enabling account management and SSO solution. For end-users, it allows aggregating multiple existing authenticators (Facebook, Google, etc.)
in one place and managing different (and potentially multiple) identities exposed to apps. Apps do not have to worry about user management nor multi-tenancy.
And admins of communities (tenants, domains, realms) using those apps can manage all users in one place, with tools to address any abuse.

## Planned features

* Security first with great user experience.
* Beautiful and intuitive UI/UX.
* Account creation and management from both user's perspective and admin's perspective.
* Standard compliant OAuth and OpenID Connect provider.
* Account can be part of multiple communities, with different identities for differnet communities.
* Each community can use multiple apps.
* User can authorize all apps in a community, or individual apps.
* Proactive pushing of changes to all apps authorized for a user.
* User invitation workflow with reminders.
* Centralized management communities and roles inside communities.
* Allowing users to link many other authentication providers to their accounts.
* Federation: other authentication providers can be other Charon instances.
* U2F support.
* Integration with identify verification providers without exposing details to apps
  (i.e., app just learns that user has been verified, is unique user, and has satisfied KYC
  requirements, without learning anything more about the user beyond what user exposes in their identity).
* Support for melding of multiple accounts and identities into one. [#1](https://gitlab.com/charon/charon/issues/1)
* Stable reactivity-enabled API, which is used by Charon's frontend as well.
* Support for identity impersonation, multiple identites per app, and ad-hoc anonymous identites. [#1](https://gitlab.com/charon/charon/issues/1)
* Everything is logged and auditable.
* Virtual accounts which can be only impersonated. [#2](https://gitlab.com/charon/charon/issues/2)
* Proxy to log all access and allow/deny high-level access to an app and app's APIs.
* Scoped API tokens to delegate further.
* Scoped subaccounts. [#3](https://gitlab.com/charon/charon/issues/3)
* Internationalization and localization.
* E-mail proxying.

## Related projects

* [Keycloak](https://www.keycloak.org) – enterprise grade, very similar to goals of this project, but: this project aims to have one account for multiple realms (which we call communities),
  with custom identites per realm (i.e., the hierarchy/control is different from Keycloak), moreover, it aims to be much simpler in scope, and with admin interface being usable by end-users to manage
  their communities (Keycloak's admin interface, when enabled for end-users, is quite technical)
* [StackExchange](https://stackexchange.com/) – an inspiration for this project with its centralized standard-based account system spawning multiple communities,
  but not available as a stand-alone open source system
* [Google Account](https://en.wikipedia.org/wiki/Google_Account) – another inspiration of great user flows and quality, but not open source and thus not reusable, moreover, accounts are not shared
  between domains (which we call communities) but are tied to a domain, something which we want to change with this project (in Charon, you have only one account but multiple identities for
  different domains)
* [Ory](https://www.ory.sh/) – open source identity infrastructure supporting OAuth and OpenID Connect, with focus on standard compliance, with this project it shares the realization
  of a need for [identity infrastructure service](https://www.ory.sh/docs/next/kratos/concepts/) solutions, but this project is innovating with multiple identities per account,
  auditable impersonation, and proactive pushing of changes to apps
* [Gravitee AM](https://gravitee.io/products/am/) – lightweight and easy to use system, but it does not support communities nor impersonation
* [Auth0](https://auth0.com/) – cloud service providing seamless integration of authentication and authorization for apps, hiding the fact that it is being used from the user,
  but this project aims to be visible to all stakeholders (users, apps, admins), allowing them to control their aspect of its use, moreover, it allows admins (of a community)
  to be a different entity from developers of apps
* [Gluu](https://gluu.org) – open source identity infrastructure, seems to be pretty extensive and can support impersonation, but not multiple user identities
* [Apple ID SSO](https://support.apple.com/guide/deployment/intro-to-single-sign-on-depfdbf18f55/web) – a closed source and centralized SSO service which does enable users to hide their e-mail address from apps by proxying them
* [GoTrue](https://github.com/netlify/gotrue) – small service for handling user registration and authentication, very low level and without user interface
* [Casdoor](https://casdoor.org/) – open source authentication service combinings users, organizations and applications in a similar this project does, but does not enable users to control their identity exposed to apps
* [Mozilla Persona](https://en.wikipedia.org/wiki/Mozilla_Persona) – was an identity provider integrated with Firefox browser, but it did not gain enough traction; this project is more than an identity provider adds many other features for both users and app developers
