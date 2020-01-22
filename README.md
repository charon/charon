# Charon

A powerful open source account management and SSO solution. For end-users, it allows aggregating multiple existing authenticators (Facebook, Google, etc.)
in one place and managing different (and potentially multiple) profiles exposed do apps. Apps do not have to worry about user management nor multi-tenancy.
And admins of communities (tenants, domains, realms) using those apps can manage all users in one place.

## Planned features

* Security first with great user experience.
* Beautiful and intuitive UI/UX.
* Account creation and management from both user's perspective and admin's perspective.
* Standard compliant OAuth and OpenID Connect provider.
* Account can be part of multiple communities, with different profiles for differnet communities.
* Each community can use multiple apps.
* User can authorize all apps in a community, or individual apps.
* Proactive pushing of profile changes to all apps authorized for a user.
* User invitation workflow with reminders.
* Centralized management communities and roles inside communities.
* Allowing users to link many other authentication providers to their accounts.
* U2F support.
* Support for melding of multiple accounts and profiles into one.
* Stable GraphQL API.
* Support for profile impersonation.
* Everything is logged and auditable.

## Related projects

* [Keycloak](https://www.keycloak.org) – enterprise grade, very similar to goals of this project, but: this project aims to have one account for multiple realms (which we call communities),
  with custom profiles per realm (so the hierarchy/control is different between projects), moreover, it aims to be much simpler in scope, and with admin interface being usable by end-users to manage
  their communities (Keycloak's admin interface, when enabled for end-users, is quite technical)
* [Passport](http://www.passportjs.org/) – a low level library, this project uses it internally
* [StackExchange](https://stackexchange.com/) – an inspiration for this project with its centralized standard-based account system spawning multiple communities,
  but not available as a stand-alone open source system
* [Google Account](https://en.wikipedia.org/wiki/Google_Account) – another inspiration of great user flows and quality, but not open source and thus not reusable, moreover, accounts are not shared
  between domains (which we call communities) but are tied to a domain, something which we want to change with this project (in Charon, you have only one account but multiple profiles for
  different domains)
