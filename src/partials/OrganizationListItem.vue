<script setup lang="ts">
import type { Organization, OrganizationRef } from "@/types"

import { useI18n } from "vue-i18n"
import WithDocument from "@/components/WithDocument.vue"

const { t } = useI18n({ useScope: 'global' })

defineProps<{
  item: OrganizationRef
  h3?: boolean
  labels?: string[]
}>()

const WithOrganizationDocument = WithDocument<Organization>
</script>

<template>
  <WithOrganizationDocument :params="{ id: item.id }" name="OrganizationGet">
    <template #default="{ doc, metadata, url }">
      <div class="flex flex-row justify-between items-center gap-4" :data-url="url">
        <component :is="h3 ? 'h3' : 'h2'" class="flex flex-row items-center gap-1" :class="h3 ? 'text-lg' : 'text-xl'">
          <router-link :to="{ name: 'OrganizationGet', params: { id: doc.id } }" class="link">{{ doc.name }}</router-link>
          <span v-for="label in labels || []" :key="label" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm text-sm leading-none">{{ label }}</span>
          <span v-if="metadata.can_update" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm text-sm leading-none">{{ t("labels.admin") }}</span>
        </component>
        <slot :doc="doc" :metadata="metadata"></slot>
      </div>
      <div v-if="doc.description" class="mt-4 ml-4 whitespace-pre-line">{{ doc.description }}</div>
    </template>
    <template #error="{ url }">
      <div class="flex flex-row gap-4" :data-url="url">
        <div class="flex-grow flex">
          <span class="text-error-600 italic">{{ t("loading.loadingDataFailed") }}</span>
        </div>
        <slot :doc="undefined" :metadata="undefined"></slot>
      </div>
    </template>
  </WithOrganizationDocument>
</template>
