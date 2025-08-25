<script setup lang="ts">
import type { Activity, ActivityRef, Identity, Organization, ApplicationTemplate, OrganizationApplicationPublic, IdentityRef } from "@/types"
import type { DeepReadonly, FunctionalComponent } from "vue"

import { useI18n } from "vue-i18n"
import { LockClosedIcon, LockOpenIcon, IdentificationIcon, UserGroupIcon, CalculatorIcon } from "@heroicons/vue/24/outline"
import { IdentificationIcon as IdentificationSolidIcon, UserGroupIcon as UserGroupSolidIcon, CalculatorIcon as CalculatorSolidIcon } from "@heroicons/vue/24/solid"
import WithDocument from "@/components/WithDocument.vue"
import { getProviderName } from "@/flow"
import { getHomepage } from "@/utils"

const { t } = useI18n({ useScope: "global" })

defineProps<{
  item: ActivityRef
}>()

function getActivityIcon(activityType: string): FunctionalComponent {
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
    default:
      throw new Error(`unknown activity type: ${activityType}`)
  }
}

function getFormattedTimestamp(timestamp: string): string {
  const date = new Date(timestamp)
  return date.toLocaleString()
}

function getIdentityDisplayName(identity: Identity | DeepReadonly<Identity>): string {
  return identity.username || identity.email || identity.givenName || identity.fullName || identity.id
}

function getChangeDescription(changeType: string, activityType: string, organizationsCount: number, organizationApplicationsCount: number): string[] {
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
        if (organizationsCount > 0) {
          changes.push(t("partials.ActivityListItem.changes.organizationsAdded"))
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
        if (organizationsCount > 0) {
          changes.push(t("partials.ActivityListItem.changes.organizationsRemoved"))
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

function maybeRemoveDuplicatesOfFirst(activityType: string, identities: readonly IdentityRef[]): readonly IdentityRef[] {
  if (activityType !== "identityUpdate") {
    return identities
  }
  // For identity updates, we remove duplicates of the first identity because the first identity is always
  // the identity that was updated. Backend always prepends it. We want identities to be shown only once to the user.
  const firstIdentity = identities[0]
  return [firstIdentity].concat(...identities.slice(1).filter((i) => i.id !== firstIdentity.id))
}

const WithActivityDocument = WithDocument<Activity>
const WithIdentityDocument = WithDocument<Identity>
const WithOrganizationDocument = WithDocument<Organization>
const WithApplicationTemplateDocument = WithDocument<ApplicationTemplate>
const WithOrganizationApplicationDocument = WithDocument<OrganizationApplicationPublic>
</script>

<template>
  <WithActivityDocument :params="{ id: item.id }" name="ActivityGet">
    <template #default="{ doc, url }">
      <div class="flex items-start gap-4" :data-url="url">
        <div class="flex-shrink-0 w-8 h-8 flex items-center justify-center">
          <component :is="getActivityIcon(doc.type)" />
        </div>
        <div class="flex-grow">
          <div class="flex flex-col gap-1">
            <h3 class="font-medium">
              {{ getActivityDescription(doc.type) }}
            </h3>
            <div v-if="doc.changes" class="flex flex-row flex-wrap content-start items-start gap-1 text-sm">
              <template v-for="change in doc.changes" :key="change">
                <span
                  v-for="(description, i) in getChangeDescription(change, doc.type, doc.organizations?.length || 0, doc.organizationApplications?.length || 0)"
                  :key="i"
                  class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm text-sm leading-none"
                  >{{ description }}</span
                >
              </template>
            </div>
            <div v-if="doc.providers" class="flex flex-row flex-wrap content-start items-start gap-1 text-sm">
              <span v-for="provider in doc.providers" :key="provider" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm text-sm leading-none">{{
                getProviderName(t, provider)
              }}</span>
            </div>
            <div v-if="doc.identities" class="text-sm text-slate-700">
              <i18n-t keypath="partials.ActivityListItem.entityLinks" scope="global">
                <template #entity>{{ t("common.entities.identity", maybeRemoveDuplicatesOfFirst(doc.type, doc.identities).length) }}</template>
                <template #links>
                  <template v-for="(identity, i) in maybeRemoveDuplicatesOfFirst(doc.type, doc.identities)" :key="identity.id">
                    <template v-if="i > 0">, </template>
                    <WithIdentityDocument :params="{ id: identity.id }" name="IdentityGet">
                      <template #default="{ doc: identityDoc, url: identityUrl }">
                        <router-link :to="{ name: 'IdentityGet', params: { id: identity.id } }" :data-url="identityUrl" class="link">
                          {{ getIdentityDisplayName(identityDoc) }}
                        </router-link>
                      </template>
                      <template #error="{ url: identityErrorUrl }">
                        <span :data-url="identityErrorUrl" class="text-error-600 italic">{{ t("common.data.loadingDataFailed") }}</span>
                      </template>
                    </WithIdentityDocument>
                  </template>
                </template>
              </i18n-t>
            </div>
            <div v-if="doc.organizations" class="text-sm text-slate-700">
              <i18n-t keypath="partials.ActivityListItem.entityLinks" scope="global">
                <template #entity>{{ t("common.entities.organization", doc.organizations.length) }}</template>
                <template #links>
                  <template v-for="(organization, i) in doc.organizations" :key="organization.id">
                    <template v-if="i > 0">, </template>
                    <WithOrganizationDocument :params="{ id: organization.id }" name="OrganizationGet">
                      <template #default="{ doc: orgDoc, url: orgUrl }">
                        <router-link :to="{ name: 'OrganizationGet', params: { id: organization.id } }" :data-url="orgUrl" class="link">
                          {{ orgDoc.name }}
                        </router-link>
                      </template>
                      <template #error="{ url: orgErrorUrl }">
                        <span :data-url="orgErrorUrl" class="text-error-600 italic">{{ t("common.data.loadingDataFailed") }}</span>
                      </template>
                    </WithOrganizationDocument>
                  </template>
                </template>
              </i18n-t>
            </div>
            <div v-if="doc.applicationTemplates" class="text-sm text-slate-700">
              <i18n-t keypath="partials.ActivityListItem.entityLinks" scope="global">
                <template #entity>{{ t("common.entities.applicationTemplate", doc.applicationTemplates.length) }}</template>
                <template #links>
                  <template v-for="(applicationTemplate, i) in doc.applicationTemplates" :key="applicationTemplate.id">
                    <template v-if="i > 0">, </template>
                    <WithApplicationTemplateDocument :params="{ id: applicationTemplate.id }" name="ApplicationTemplateGet">
                      <template #default="{ doc: appDoc, url: appUrl }">
                        <router-link :to="{ name: 'ApplicationTemplateGet', params: { id: applicationTemplate.id } }" :data-url="appUrl" class="link">
                          {{ appDoc.name }}
                        </router-link>
                      </template>
                      <template #error="{ url: appErrorUrl }">
                        <span :data-url="appErrorUrl" class="text-error-600 italic">{{ t("common.data.loadingDataFailed") }}</span>
                      </template>
                    </WithApplicationTemplateDocument>
                  </template>
                </template>
              </i18n-t>
            </div>
            <div v-if="doc.organizationApplications" class="text-sm text-slate-700">
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
            <div class="text-xs text-neutral-500">
              {{ getFormattedTimestamp(doc.timestamp) }}
            </div>
            <div class="text-xs text-neutral-500">Session: {{ doc.sessionId }}</div>
          </div>
        </div>
      </div>
    </template>
    <template #error="{ url }">
      <div class="flex flex-row gap-4" :data-url="url">
        <div class="flex-grow flex">
          <span class="text-error-600 italic">{{ t("common.data.loadingDataFailed") }}</span>
        </div>
      </div>
    </template>
  </WithActivityDocument>
</template>
