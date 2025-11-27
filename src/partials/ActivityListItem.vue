<script setup lang="ts">
import type { Component, DeepReadonly } from "vue"

import type { Activity, ActivityRef, ApplicationTemplate, IdentityPublic, Organization, OrganizationApplicationPublic, OrganizationRef } from "@/types"

import { LocalScope } from "@allindevelopers/vue-local-scope"
import { CalculatorIcon, IdentificationIcon, LockClosedIcon, LockOpenIcon, ShieldCheckIcon, ShieldExclamationIcon, UserGroupIcon } from "@heroicons/vue/24/outline"
import { CalculatorIcon as CalculatorSolidIcon, IdentificationIcon as IdentificationSolidIcon, UserGroupIcon as UserGroupSolidIcon } from "@heroicons/vue/24/solid"
import { uniqWith } from "lodash-es"
import { readonly } from "vue"
import { useI18n } from "vue-i18n"

import { currentIdentityId } from "@/auth"
import WithDocument from "@/components/WithDocument.vue"
import { getProviderName } from "@/flow"
import { clone, equals, getFormattedTimestamp, getHomepage, getIdentityDisplayName } from "@/utils"

const props = defineProps<{
  item: ActivityRef
  organization?: OrganizationRef
}>()

const { t } = useI18n({ useScope: "global" })

function getActivityIcon(activityType: string): Component {
  switch (activityType) {
    case "signIn":
      return LockOpenIcon
    case "signOut":
      return LockClosedIcon
    case "identityCreate":
      return IdentificationIcon
    case "identityUpdate":
      return IdentificationSolidIcon
    case "organizationCreate":
      return UserGroupIcon
    case "organizationUpdate":
      return UserGroupSolidIcon
    case "applicationTemplateCreate":
      return CalculatorIcon
    case "applicationTemplateUpdate":
      return CalculatorSolidIcon
    case "identityBlocked":
    case "accountBlocked":
      return ShieldExclamationIcon
    case "identityUnblocked":
      return ShieldCheckIcon
    default:
      throw new Error(`unknown activity type: ${activityType}`)
  }
}

function getActivityDescription(activityType: string): string {
  switch (activityType) {
    case "signIn":
      return t("partials.ActivityListItem.signin")
    case "signOut":
      return t("partials.ActivityListItem.signout")
    case "identityCreate":
      return t("partials.ActivityListItem.identityCreate")
    case "identityUpdate":
      return t("partials.ActivityListItem.identityUpdate")
    case "organizationCreate":
      return t("partials.ActivityListItem.organizationCreate")
    case "organizationUpdate":
      return t("partials.ActivityListItem.organizationUpdate")
    case "applicationTemplateCreate":
      return t("partials.ActivityListItem.applicationTemplateCreate")
    case "applicationTemplateUpdate":
      return t("partials.ActivityListItem.applicationTemplateUpdate")
    case "identityBlocked":
      return t("partials.ActivityListItem.identityBlocked")
    case "accountBlocked":
      return t("partials.ActivityListItem.accountBlocked")
    case "identityUnblocked":
      return t("partials.ActivityListItem.identityUnblocked")
    default:
      throw new Error(`unknown activity type: ${activityType}`)
  }
}

function getChangeDescription(
  changeType: string,
  activityType: string,
  identitiesCount: number,
  organizationsCount: number,
  organizationApplicationsCount: number,
): string[] {
  switch (changeType) {
    case "otherData":
      return [t("partials.ActivityListItem.changes.otherData")]
    case "permissionsAdded":
      return [t("partials.ActivityListItem.changes.permissionsAdded")]
    case "permissionsRemoved":
      return [t("partials.ActivityListItem.changes.permissionsRemoved")]
    case "membershipAdded":
      if (activityType === "organizationUpdate") {
        return [t("partials.ActivityListItem.changes.applicationsAdded")]
      }
      if (activityType === "identityUpdate") {
        const changes: string[] = []
        if (props.organization) {
          if (identitiesCount > 0) {
            changes.push(t("partials.ActivityListItem.changes.identitiesAdded"))
          }
        } else {
          if (organizationsCount > 0) {
            changes.push(t("partials.ActivityListItem.changes.organizationsAdded"))
          }
        }
        if (organizationApplicationsCount > 0) {
          changes.push(t("partials.ActivityListItem.changes.applicationsAdded"))
        }
        if (changes.length > 0) {
          return changes
        }
      }
      throw new Error(`unknown change type context: ${changeType}`)
    case "membershipRemoved":
      if (activityType === "organizationUpdate") {
        return [t("partials.ActivityListItem.changes.applicationsRemoved")]
      }
      if (activityType === "identityUpdate") {
        const changes: string[] = []
        if (props.organization) {
          if (identitiesCount > 0) {
            changes.push(t("partials.ActivityListItem.changes.identitiesRemoved"))
          }
        } else {
          if (organizationsCount > 0) {
            changes.push(t("partials.ActivityListItem.changes.organizationsRemoved"))
          }
        }
        if (organizationApplicationsCount > 0) {
          changes.push(t("partials.ActivityListItem.changes.applicationsRemoved"))
        }
        if (changes.length > 0) {
          return changes
        }
      }
      throw new Error(`unknown change type context: ${changeType}`)
    case "membershipChanged":
      if (activityType === "organizationUpdate") {
        return [t("partials.ActivityListItem.changes.applicationsChanged")]
      }
      if (activityType === "identityUpdate") {
        return [t("partials.ActivityListItem.changes.organizationsChanged")]
      }
      throw new Error(`unknown change type context: ${changeType}`)
    case "membershipActivated":
      if (activityType === "organizationUpdate") {
        return [t("partials.ActivityListItem.changes.applicationsActivated")]
      }
      if (activityType === "identityUpdate") {
        return [t("partials.ActivityListItem.changes.organizationsActivated")]
      }
      throw new Error(`unknown change type context: ${changeType}`)
    case "membershipDisabled":
      if (activityType === "organizationUpdate") {
        return [t("partials.ActivityListItem.changes.applicationsDisabled")]
      }
      if (activityType === "identityUpdate") {
        return [t("partials.ActivityListItem.changes.organizationsDisabled")]
      }
      throw new Error(`unknown change type context: ${changeType}`)
    default:
      throw new Error(`unknown change type: ${changeType}`)
  }
}

function transformActivity(activity: DeepReadonly<Activity>): DeepReadonly<Activity> {
  const a = clone(activity)
  if (props.organization) {
    // We remove the organization prop from organizations so that it is not shown multiple times.
    a.organizations = (a.organizations || []).filter((o) => o.id !== props.organization!.id)
  }

  // When organization prop is provided, we always show the actor among identities.
  // We also add the actor if it is different from the current identity.
  if (a.actor && (props.organization || a.actor.identity.id !== currentIdentityId.value)) {
    // When organization prop is provided, we always show the actor among identities.
    a.identities = [a.actor].concat(...(a.identities || []))
    delete a.actor
  }

  if (a.identities) {
    // We remove duplicates because we want identities to be shown only once to the user.
    // Duplicates can happen when we prepend actor to identities. For identity updates,
    // they can happen because backend always prepends the identity that was updated.
    a.identities = uniqWith(a.identities, equals)
  }

  return import.meta.env.DEV ? readonly(a) : a
}

const WithActivityDocument = WithDocument<Activity>
const WithIdentityPublicDocument = WithDocument<IdentityPublic>
const WithOrganizationDocument = WithDocument<Organization>
const WithApplicationTemplateDocument = WithDocument<ApplicationTemplate>
const WithOrganizationApplicationDocument = WithDocument<OrganizationApplicationPublic>
</script>

<template>
  <WithActivityDocument
    :params="organization ? { id: organization.id, activityId: item.id } : { id: item.id }"
    :name="organization ? 'OrganizationActivityGet' : 'ActivityGet'"
  >
    <template #default="{ doc: originalDoc, url }">
      <LocalScope v-slot="{ doc }" :doc="transformActivity(originalDoc)">
        <div class="flex items-start gap-4" :data-url="url">
          <div class="flex h-8 w-8 shrink-0 items-center justify-center">
            <component :is="getActivityIcon(doc.type)" />
          </div>
          <div class="grow">
            <div class="flex flex-col gap-1">
              <h3 class="font-medium">{{ getActivityDescription(doc.type) }}</h3>
              <div v-if="doc.changes?.length" class="flex flex-row flex-wrap content-start items-start gap-1 text-sm">
                <template v-for="change in doc.changes" :key="change">
                  <span
                    v-for="(description, i) in getChangeDescription(
                      change,
                      doc.type,
                      doc.identities?.length || 0,
                      doc.organizations?.length || 0,
                      doc.organizationApplications?.length || 0,
                    )"
                    :key="i"
                    class="rounded-xs bg-slate-100 px-1.5 py-0.5 text-sm leading-none text-gray-600 shadow-xs"
                    >{{ description }}</span
                  >
                </template>
              </div>
              <div v-if="doc.providers?.length" class="flex flex-row flex-wrap content-start items-start gap-1 text-sm">
                <span v-for="provider in doc.providers" :key="provider" class="rounded-xs bg-slate-100 px-1.5 py-0.5 text-sm leading-none text-gray-600 shadow-xs">{{
                  getProviderName(t, provider)
                }}</span>
              </div>
              <div v-if="doc.identities?.length" class="text-sm text-slate-700">
                <i18n-t keypath="partials.ActivityListItem.entityLinks" scope="global">
                  <template #entity>{{ t("common.entities.identity", doc.identities.length) }}</template>
                  <template #links>
                    <template v-for="(organizationIdentity, i) in doc.identities" :key="`${organizationIdentity.organization.id}/${organizationIdentity.identity.id}`">
                      <template v-if="i > 0">, </template>
                      <WithIdentityPublicDocument
                        :params="{ id: organizationIdentity.organization.id, identityId: organizationIdentity.identity.id }"
                        name="OrganizationIdentity"
                      >
                        <template #default="{ doc: identityDoc, url: identityUrl }">
                          <router-link
                            :to="{ name: 'OrganizationIdentity', params: { id: organizationIdentity.organization.id, identityId: organizationIdentity.identity.id } }"
                            :data-url="identityUrl"
                            class="link"
                            >{{ getIdentityDisplayName(identityDoc) }}</router-link
                          >
                        </template>
                        <template #error="{ url: identityErrorUrl }">
                          <span :data-url="identityErrorUrl" class="text-error-600 italic">{{ t("common.data.loadingDataFailed") }}</span>
                        </template>
                      </WithIdentityPublicDocument>
                    </template>
                  </template>
                </i18n-t>
              </div>
              <div v-if="doc.organizations?.length" class="text-sm text-slate-700">
                <i18n-t keypath="partials.ActivityListItem.entityLinks" scope="global">
                  <template #entity>{{ t("common.entities.organization", doc.organizations.length) }}</template>
                  <template #links>
                    <template v-for="(org, i) in doc.organizations" :key="org.id">
                      <template v-if="i > 0">, </template>
                      <WithOrganizationDocument :params="{ id: org.id }" name="OrganizationGet">
                        <template #default="{ doc: orgDoc, url: orgUrl }">
                          <router-link :to="{ name: 'OrganizationGet', params: { id: org.id } }" :data-url="orgUrl" class="link">{{ orgDoc.name }}</router-link>
                        </template>
                        <template #error="{ url: orgErrorUrl }">
                          <span :data-url="orgErrorUrl" class="text-error-600 italic">{{ t("common.data.loadingDataFailed") }}</span>
                        </template>
                      </WithOrganizationDocument>
                    </template>
                  </template>
                </i18n-t>
              </div>
              <div v-if="doc.applicationTemplates?.length" class="text-sm text-slate-700">
                <i18n-t keypath="partials.ActivityListItem.entityLinks" scope="global">
                  <template #entity>{{ t("common.entities.applicationTemplate", doc.applicationTemplates.length) }}</template>
                  <template #links>
                    <template v-for="(applicationTemplate, i) in doc.applicationTemplates" :key="applicationTemplate.id">
                      <template v-if="i > 0">, </template>
                      <WithApplicationTemplateDocument :params="{ id: applicationTemplate.id }" name="ApplicationTemplateGet">
                        <template #default="{ doc: appDoc, url: appUrl }">
                          <router-link :to="{ name: 'ApplicationTemplateGet', params: { id: applicationTemplate.id } }" :data-url="appUrl" class="link">{{
                            appDoc.name
                          }}</router-link>
                        </template>
                        <template #error="{ url: appErrorUrl }">
                          <span :data-url="appErrorUrl" class="text-error-600 italic">{{ t("common.data.loadingDataFailed") }}</span>
                        </template>
                      </WithApplicationTemplateDocument>
                    </template>
                  </template>
                </i18n-t>
              </div>
              <div v-if="doc.organizationApplications?.length" class="text-sm text-slate-700">
                <i18n-t keypath="partials.ActivityListItem.entityLinks" scope="global">
                  <template #entity>{{ t("common.entities.app", doc.organizationApplications.length) }}</template>
                  <template #links>
                    <template v-for="(app, i) in doc.organizationApplications" :key="app.application.id">
                      <template v-if="i > 0">, </template>
                      <WithOrganizationApplicationDocument :params="{ id: app.organization.id, appId: app.application.id }" name="OrganizationApp">
                        <template #default="{ doc: appDoc, url: appUrl }">
                          <a :href="getHomepage(appDoc)" :data-url="appUrl" class="link">{{ appDoc.applicationTemplate.name }}</a>
                        </template>
                        <template #error="{ url: appErrorUrl }">
                          <span :data-url="appErrorUrl" class="text-error-600 italic">{{ t("common.data.loadingDataFailed") }}</span>
                        </template>
                      </WithOrganizationApplicationDocument>
                    </template>
                  </template>
                </i18n-t>
              </div>
              <div class="text-xs text-neutral-500">{{ getFormattedTimestamp(doc.timestamp) }}</div>
              <div class="text-xs text-neutral-500">Session: {{ doc.sessionId }}</div>
            </div>
          </div>
        </div>
      </LocalScope>
    </template>
    <template #error="{ url }">
      <div class="flex flex-row gap-4" :data-url="url">
        <div class="flex grow">
          <span class="text-error-600 italic">{{ t("common.data.loadingDataFailed") }}</span>
        </div>
      </div>
    </template>
  </WithActivityDocument>
</template>
