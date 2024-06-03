<script setup lang="ts">
import type { Organization, OrganizationRef } from "@/types"

import WithDocument from "@/components/WithDocument.vue"

defineProps<{
  item: OrganizationRef
}>()

const WithOrganizationDocument = WithDocument<Organization>
</script>

<template>
  <WithOrganizationDocument :id="item.id" name="OrganizationGet">
    <template #default="{ doc, metadata, url }">
      <h2 class="text-xl flex flex-row items-center gap-1" :data-url="url">
        <router-link :to="{ name: 'OrganizationGet', params: { id: doc.id } }" class="link">{{ doc.name }}</router-link>
        <span v-if="metadata.can_update" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm text-sm leading-none">admin</span>
      </h2>
    </template>
  </WithOrganizationDocument>
</template>
