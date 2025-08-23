<script setup lang="ts">
import type { Activity, ActivityRef, Identity, Organization, ApplicationTemplate } from "@/types"
import type { DeepReadonly } from "vue"

import { useI18n } from "vue-i18n"
import WithDocument from "@/components/WithDocument.vue"

const { t } = useI18n({ useScope: "global" })

defineProps<{
  item: ActivityRef
}>()

const WithActivityDocument = WithDocument<Activity>
const WithIdentityDocument = WithDocument<Identity>
const WithOrganizationDocument = WithDocument<Organization>
const WithApplicationTemplateDocument = WithDocument<ApplicationTemplate>

const getActivityIcon = (type: string) => {
  switch (type) {
    case "signIn":
      return "🔓"
    case "signOut":
      return "🔒"
    case "identityCreate":
      return "👤"
    case "identityUpdate":
      return "✏️"
    case "organizationCreate":
      return "🏢"
    case "organizationUpdate":
      return "🏢"
    case "applicationTemplateCreate":
      return "📱"
    case "applicationTemplateUpdate":
      return "📱"
    default:
      return "⚡"
  }
}

const getActivityDescription = (type: string) => {
  switch (type) {
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
      return t("partials.ActivityListItem.unknownActivity")
  }
}

const getFormattedTimestamp = (timestamp: string) => {
  const date = new Date(timestamp)
  return date.toLocaleString()
}

const getIdentityDisplayName = (identity: Identity | DeepReadonly<Identity>) => {
  return identity.username || identity.email || identity.givenName || identity.fullName || identity.id
}

const getChangeDescription = (changeType: string) => {
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
</script>

<template>
  <WithActivityDocument :params="{ id: item.id }" name="ActivityGet">
    <template #default="{ doc, url }">
      <div class="flex items-start gap-3" :data-url="url">
        <div class="flex-shrink-0 w-8 h-8 flex items-center justify-center text-lg">
          {{ getActivityIcon(doc.type) }}
        </div>
        <div class="flex-grow">
          <div class="flex flex-col gap-1">
            <div class="font-medium text-gray-900">
              {{ getActivityDescription(doc.type) }}
            </div>
            <div v-if="doc.identity" class="text-sm text-gray-600">
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
            <div v-if="doc.organization" class="text-sm text-gray-600">
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
            <div v-if="doc.applicationTemplate" class="text-sm text-gray-600">
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
            <div class="text-xs text-gray-500">
              {{ getFormattedTimestamp(doc.timestamp) }}
            </div>
            <div v-if="doc.changes" class="flex flex-wrap gap-1 mt-1">
              <span v-for="change in doc.changes" :key="change" class="inline-block px-2 py-1 text-xs bg-blue-100 text-blue-800 rounded-full">
                {{ getChangeDescription(change) }}
              </span>
            </div>
            <div v-if="doc.appId" class="text-xs text-gray-400">App: {{ doc.appId }}</div>
            <div class="text-xs text-gray-400">Session: {{ doc.sessionId }}</div>
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
