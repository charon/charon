<script setup lang="ts">
import type { ApplicationTemplate, ApplicationTemplateRef } from "@/types"

import WithDocument from "@/components/WithDocument.vue"

defineProps<{
  item: ApplicationTemplateRef
}>()

const WithApplicationTemplateDocument = WithDocument<ApplicationTemplate>
</script>

<template>
  <WithApplicationTemplateDocument :params="{ id: item.id }" name="ApplicationTemplateGet">
    <template #default="{ doc, metadata, url }">
      <h2 class="text-xl flex flex-row items-center gap-1" :data-url="url">
        <router-link :to="{ name: 'ApplicationTemplateGet', params: { id: doc.id } }" class="link">{{ doc.name }}</router-link>
        <span v-if="metadata.can_update" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm text-sm leading-none">admin</span>
      </h2>
    </template>
  </WithApplicationTemplateDocument>
</template>
