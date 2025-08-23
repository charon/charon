<script setup lang="ts">
import type { Activity } from "@/types"

import { computed } from "vue"
import { useI18n } from "vue-i18n"

interface Props {
  activity: Activity
}

const props = defineProps<Props>()
const { t } = useI18n({ useScope: "global" })

const activityIcon = computed(() => {
  switch (props.activity.type) {
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
})

const activityDescription = computed(() => {
  switch (props.activity.type) {
    case "signin":
      return t("partials.ActivityItem.signin")
    case "signout":
      return t("partials.ActivityItem.signout")
    case "identity_create":
      return t("partials.ActivityItem.identityCreate")
    case "identity_update":
      return t("partials.ActivityItem.identityUpdate")
    case "organization_create":
      return t("partials.ActivityItem.organizationCreate")
    case "organization_update":
      return t("partials.ActivityItem.organizationUpdate")
    case "application_template_create":
      return t("partials.ActivityItem.applicationTemplateCreate")
    case "application_template_update":
      return t("partials.ActivityItem.applicationTemplateUpdate")
    default:
      return t("partials.ActivityItem.unknownActivity")
  }
})

const formattedTimestamp = computed(() => {
  const date = new Date(props.activity.timestamp)
  return date.toLocaleString()
})

const documentTypeLabel = computed(() => {
  if (!props.activity.document) return ""

  switch (props.activity.document.type) {
    case "identity":
      return t("common.entities.identity")
    case "organization":
      return t("common.entities.organization")
    case "application_template":
      return t("common.entities.applicationTemplate")
    default:
      return props.activity.document.type
  }
})
</script>

<template>
  <div class="flex items-start gap-3">
    <div class="flex-shrink-0 w-8 h-8 flex items-center justify-center text-lg">
      {{ activityIcon }}
    </div>
    <div class="flex-grow">
      <div class="flex flex-col gap-1">
        <div class="font-medium text-gray-900">
          {{ activityDescription }}
        </div>
        <div v-if="activity.document" class="text-sm text-gray-600">{{ documentTypeLabel }}: {{ activity.document.id }}</div>
        <div class="text-xs text-gray-500">
          {{ formattedTimestamp }}
        </div>
        <div v-if="activity.metadata && Object.keys(activity.metadata).length > 0" class="text-xs text-gray-400">
          <details>
            <summary class="cursor-pointer">{{ t("partials.ActivityItem.showMetadata") }}</summary>
            <pre class="mt-1 text-xs">{{ JSON.stringify(activity.metadata, null, 2) }}</pre>
          </details>
        </div>
      </div>
    </div>
  </div>
</template>
