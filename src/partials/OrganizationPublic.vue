<script setup lang="ts">
import type { DeepReadonly } from "vue"

import type { OrganizationPublic } from "@/types"

import { useI18n } from "vue-i18n"

withDefaults(
  defineProps<{
    organization: OrganizationPublic | DeepReadonly<OrganizationPublic>
    url?: string
    h3?: boolean
    canUpdate?: boolean
    labels?: string[]
  }>(),
  {
    // Other optional props we set to undefined, which is also default.
    url: undefined,
    labels: undefined,
  },
)

const { t } = useI18n({ useScope: "global" })
</script>

<template>
  <div class="flex flex-row items-center justify-between gap-4" :data-url="url">
    <component :is="h3 ? 'h3' : 'h2'" class="flex flex-row items-center gap-1" :class="h3 ? 'text-lg' : 'text-xl'">
      <router-link :to="{ name: 'OrganizationGet', params: { id: organization.id } }" class="link">{{ organization.name }}</router-link>
      <span v-for="label in labels || []" :key="label" class="rounded-xs bg-slate-100 px-1.5 py-0.5 text-sm leading-none text-gray-600 shadow-xs">{{ label }}</span>
      <span v-if="canUpdate" class="rounded-xs bg-slate-100 px-1.5 py-0.5 text-sm leading-none text-gray-600 shadow-xs">{{ t("common.labels.admin") }}</span>
    </component>
    <slot :organization="organization" :can-update="canUpdate"></slot>
  </div>
  <div v-if="organization.description" class="mt-4 ml-4 whitespace-pre-line">{{ organization.description }}</div>
</template>
