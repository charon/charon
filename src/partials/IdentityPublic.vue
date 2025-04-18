<script setup lang="ts">
import type { IdentityPublic, IdentityRef } from "@/types"

import WithDocument from "@/components/WithDocument.vue"

defineProps<{
  item: IdentityRef
  organizationId: string
}>()

const WithIdentityPublicDocument = WithDocument<IdentityPublic>
</script>

<template>
  <WithIdentityPublicDocument :params="{ id: organizationId, identityId: item.id }" name="OrganizationIdentity">
    <template #default="{ doc, metadata, url }">
      <div class="flex flex-row gap-4" :data-url="url">
        <div v-if="doc.pictureUrl" class="flex-none">
          <img :src="doc.pictureUrl" alt="picture" class="h-20 w-20 ring-2 ring-white rounded" />
        </div>
        <div class="flex-grow flex flex-col">
          <h2 v-if="doc.username" class="text-xl">
            <ul v-if="metadata.can_update" class="flex flex-row flex-wrap content-start items-start gap-1 text-sm float-right">
              <li v-if="metadata.can_update" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm leading-none">admin</li>
            </ul>
            {{ doc.username }}
            <span v-if="doc.email"> ({{ doc.email }})</span>
          </h2>
          <h2 v-else-if="doc.email" class="text-xl">
            <ul v-if="metadata.can_update" class="flex flex-row flex-wrap content-start items-start gap-1 text-sm float-right">
              <li v-if="metadata.can_update" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm leading-none">admin</li>
            </ul>
            {{ doc.email }}
          </h2>
          <h2 v-else-if="doc.givenName" class="text-xl">
            <ul v-if="metadata.can_update" class="flex flex-row flex-wrap content-start items-start gap-1 text-sm float-right">
              <li v-if="metadata.can_update" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm leading-none">admin</li>
            </ul>
            {{ doc.givenName }}
            <span v-if="doc.fullName"> ({{ doc.fullName }})</span>
          </h2>
          <h2 v-else-if="doc.fullName" class="text-xl">
            <ul v-if="metadata.can_update" class="flex flex-row flex-wrap content-start items-start gap-1 text-sm float-right">
              <li v-if="metadata.can_update" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm leading-none">admin</li>
            </ul>
            {{ doc.fullName }}
          </h2>
          <div v-else-if="metadata.can_update">
            <ul class="flex flex-row flex-wrap content-start items-start gap-1 text-sm float-right">
              <li v-if="metadata.can_update" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm leading-none">admin</li>
            </ul>
          </div>
          <div v-if="doc.givenName && (doc.username || doc.email)" class="mt-1">
            {{ doc.givenName }}
            <span v-if="doc.fullName"> ({{ doc.fullName }})</span>
          </div>
          <div v-else-if="doc.fullName && (doc.username || doc.email)" class="mt-1">
            {{ doc.fullName }}
          </div>
        </div>
        <slot :doc="doc"></slot>
      </div>
    </template>
  </WithIdentityPublicDocument>
</template>
