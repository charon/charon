<script setup lang="ts">
import type { Activity, ActivityRef } from "@/types"

import { useI18n } from "vue-i18n"
import WithDocument from "@/components/WithDocument.vue"

const { t } = useI18n({ useScope: "global" })

defineProps<{
  item: ActivityRef
}>()

const WithActivityDocument = WithDocument<Activity>

const getActivityIcon = (type: string) => {
  switch (type) {
    case "signin":
      return "🔓"
    case "signout":
      return "🔒"
    case "identity_create":
      return "👤"
    case "identity_update":
      return "✏️"
    case "organization_create":
      return "🏢"
    case "organization_update":
      return "🏢"
    case "application_template_create":
      return "📱"
    case "application_template_update":
      return "📱"
    default:
      return "⚡"
  }
}

const getActivityDescription = (type: string) => {
  switch (type) {
    case "signin":
      return t("partials.ActivityListItem.signin")
    case "signout":
      return t("partials.ActivityListItem.signout")
    case "identity_create":
      return t("partials.ActivityListItem.identityCreate")
    case "identity_update":
      return t("partials.ActivityListItem.identityUpdate")
    case "organization_create":
      return t("partials.ActivityListItem.organizationCreate")
    case "organization_update":
      return t("partials.ActivityListItem.organizationUpdate")
    case "application_template_create":
      return t("partials.ActivityListItem.applicationTemplateCreate")
    case "application_template_update":
      return t("partials.ActivityListItem.applicationTemplateUpdate")
    default:
      return t("partials.ActivityListItem.unknownActivity")
  }
}

const getFormattedTimestamp = (timestamp: string) => {
  const date = new Date(timestamp)
  return date.toLocaleString()
}

const getDocumentTypeLabel = (documentType: string | undefined) => {
  if (!documentType) return ""

  switch (documentType) {
    case "identity":
      return t("common.entities.identity")
    case "organization":
      return t("common.entities.organization")
    case "application_template":
      return t("common.entities.applicationTemplate")
    default:
      return documentType
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
            <div v-if="doc.document" class="text-sm text-gray-600">{{ getDocumentTypeLabel(doc.document.type) }}: {{ doc.document.id }}</div>
            <div class="text-xs text-gray-500">
              {{ getFormattedTimestamp(doc.timestamp) }}
            </div>
            <div v-if="doc.metadata && Object.keys(doc.metadata).length > 0" class="text-xs text-gray-400">
              <details>
                <summary class="cursor-pointer">{{ t("partials.ActivityListItem.showMetadata") }}</summary>
                <pre class="mt-1 text-xs">{{ JSON.stringify(doc.metadata, null, 2) }}</pre>
              </details>
            </div>
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
