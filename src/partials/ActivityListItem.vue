<script setup lang="ts">
import type { Activity, ActivityRef, Identity, Organization, ApplicationTemplate } from "@/types"
import type { DeepReadonly, FunctionalComponent } from "vue"

import { useI18n } from "vue-i18n"
import { LockClosedIcon, LockOpenIcon, IdentificationIcon, UserGroupIcon, CalculatorIcon } from "@heroicons/vue/24/outline"
import { IdentificationIcon as IdentificationSolidIcon, UserGroupIcon as UserGroupSolidIcon, CalculatorIcon as CalculatorSolidIcon } from "@heroicons/vue/24/solid"
import WithDocument from "@/components/WithDocument.vue"
import { getProviderName } from "@/flow"

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

function getChangeDescription(changeType: string): string {
  switch (changeType) {
    case "publicData":
      return t("partials.ActivityListItem.changes.publicData")
    case "permissionsAdded":
      return t("partials.ActivityListItem.changes.permissionsAdded")
    case "permissionsRemoved":
      return t("partials.ActivityListItem.changes.permissionsRemoved")
    case "permissionsChanged":
      return t("partials.ActivityListItem.changes.permissionsChanged")
    case "membershipAdded":
      return t("partials.ActivityListItem.changes.membershipAdded")
    case "membershipRemoved":
      return t("partials.ActivityListItem.changes.membershipRemoved")
    case "membershipChanged":
      return t("partials.ActivityListItem.changes.membershipChanged")
    case "membershipActivated":
      return t("partials.ActivityListItem.changes.membershipActivated")
    case "membershipDisabled":
      return t("partials.ActivityListItem.changes.membershipDisabled")
    default:
      throw new Error(`unknown change type: ${changeType}`)
  }
}

const WithActivityDocument = WithDocument<Activity>
const WithIdentityDocument = WithDocument<Identity>
const WithOrganizationDocument = WithDocument<Organization>
const WithApplicationTemplateDocument = WithDocument<ApplicationTemplate>
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
              <span v-for="change in doc.changes" :key="change" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm text-sm leading-none">{{ getChangeDescription(change) }}</span>
            </div>
            <div v-if="doc.providers" class="flex flex-row flex-wrap content-start items-start gap-1 text-sm">
              <span v-for="provider in doc.providers" :key="provider" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm text-sm leading-none">{{ getProviderName(t, provider) }}</span>
            </div>
            <div v-if="doc.identity" class="text-sm text-slate-700">
              {{ t("common.entities.identity") }}:
              <WithIdentityDocument :params="{ id: doc.identity.id }" name="IdentityGet">
                <template #default="{ doc: identityDoc, url: identityUrl }">
                  <router-link :to="{ name: 'IdentityGet', params: { id: doc.identity.id } }" :data-url="identityUrl" class="link">
                    {{ getIdentityDisplayName(identityDoc) }}
                  </router-link>
                </template>
                <template #error="{ url: identityErrorUrl }">
                  <span :data-url="identityErrorUrl" class="text-error-600 italic">{{ t("common.data.loadingDataFailed") }}</span>
                </template>
              </WithIdentityDocument>
            </div>
            <div v-if="doc.organization" class="text-sm text-slate-700">
              {{ t("common.entities.organization") }}:
              <WithOrganizationDocument :params="{ id: doc.organization.id }" name="OrganizationGet">
                <template #default="{ doc: orgDoc, url: orgUrl }">
                  <router-link :to="{ name: 'OrganizationGet', params: { id: doc.organization.id } }" :data-url="orgUrl" class="link">
                    {{ orgDoc.name }}
                  </router-link>
                </template>
                <template #error="{ url: orgErrorUrl }">
                  <span :data-url="orgErrorUrl" class="text-error-600 italic">{{ t("common.data.loadingDataFailed") }}</span>
                </template>
              </WithOrganizationDocument>
            </div>
            <div v-if="doc.applicationTemplate" class="text-sm text-slate-700">
              {{ t("common.entities.applicationTemplate") }}:
              <WithApplicationTemplateDocument :params="{ id: doc.applicationTemplate.id }" name="ApplicationTemplateGet">
                <template #default="{ doc: appDoc, url: appUrl }">
                  <router-link :to="{ name: 'ApplicationTemplateGet', params: { id: doc.applicationTemplate.id } }" :data-url="appUrl" class="link">
                    {{ appDoc.name }}
                  </router-link>
                </template>
                <template #error="{ url: appErrorUrl }">
                  <span :data-url="appErrorUrl" class="text-error-600 italic">{{ t("common.data.loadingDataFailed") }}</span>
                </template>
              </WithApplicationTemplateDocument>
            </div>
            <div class="text-xs text-neutral-500">
              {{ getFormattedTimestamp(doc.timestamp) }}
            </div>
            <div v-if="doc.appId" class="text-xs text-neutral-500">App: {{ doc.appId }}</div>
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
