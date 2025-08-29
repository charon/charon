<script setup lang="ts">
import type { DeepReadonly } from "vue"
import type { ApplicationTemplate, ApplicationTemplatePublic, ApplicationTemplateRef } from "@/types"

import { useI18n } from "vue-i18n"
import WithDocument from "@/components/WithDocument.vue"

defineProps<{
  item: ApplicationTemplateRef
  // This partial supports providing an ApplicationTemplatePublic which is used if provided instead of data
  // fetched for the item ID. This supports using this partial also with organization documents which
  // include a copy of ApplicationTemplatePublic which might have diverged from the ApplicationTemplate
  // document (or it might be that ApplicationTemplate document does not even exist.)
  publicDoc?: ApplicationTemplatePublic | DeepReadonly<ApplicationTemplatePublic>
  h3?: boolean
  labels?: string[]
}>()

const { t } = useI18n({ useScope: "global" })

const WithApplicationTemplateDocument = WithDocument<ApplicationTemplate>
</script>

<template>
  <!--
    TODO: If fetching ApplicationTemplate fails with 404 but publicDoc is provided, we should not error but operate like metadata only does not exist.
          It could be that this partial is used with organization document with a ApplicationTemplatePublic
          which does not have anymore its ApplicationTemplate document (or it might even never had one).
  -->
  <WithApplicationTemplateDocument :params="{ id: item.id }" name="ApplicationTemplateGet">
    <template #default="{ doc, metadata, url }">
      <div class="flex flex-row justify-between items-center gap-4" :data-url="url">
        <component :is="h3 ? 'h3' : 'h2'" class="flex flex-row items-center gap-1" :class="h3 ? 'text-lg' : 'text-xl'">
          <router-link :to="{ name: 'ApplicationTemplateGet', params: { id: item.id } }" class="link">{{ publicDoc ? publicDoc.name : doc.name }}</router-link>
          <span v-for="label in labels || []" :key="label" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm text-sm leading-none">{{ label }}</span>
          <span v-if="metadata.can_update" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm text-sm leading-none">{{
            t("common.labels.admin")
          }}</span>
        </component>
        <slot :doc="doc" :metadata="metadata"></slot>
      </div>
      <div v-if="publicDoc ? publicDoc.description : doc.description" class="mt-4 ml-4 whitespace-pre-line">
        {{ publicDoc ? publicDoc.description : doc.description }}
      </div>
    </template>
    <template #error="{ url }">
      <div class="flex flex-row gap-4" :data-url="url">
        <div class="flex-grow flex">
          <span class="text-error-600 italic">{{ t("common.data.loadingDataFailed") }}</span>
        </div>
        <slot :doc="undefined" :metadata="undefined"></slot>
      </div>
    </template>
  </WithApplicationTemplateDocument>
</template>
