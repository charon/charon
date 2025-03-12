<script setup lang="ts">
import type { Identity, IdentityRef } from "@/types"
import type { ComponentExposed } from "vue-component-type-helpers"

import { ref } from "vue"
import WithDocument from "@/components/WithDocument.vue"

const props = defineProps<{
  item: IdentityRef
  organizationId?: string
  flowId?: string
}>()

const WithIdentityDocument = WithDocument<Identity>
const identity = ref<ComponentExposed<typeof WithIdentityDocument> | null>(null)

function isDisabled(): boolean {
  if (!props.organizationId) {
    return false
  }

  for (const idOrg of identity.value!.doc!.organizations) {
    if (idOrg.organization.id === props.organizationId) {
      return !idOrg.active
    }
  }

  return false
}
</script>

<template>
  <WithIdentityDocument ref="identity" :params="{ id: item.id }" :query="flowId ? { flow: flowId } : undefined" name="IdentityGet">
    <template #default="{ doc, metadata, url }">
      <div class="flex flex-row gap-4" :data-url="url">
        <div v-if="doc.pictureUrl" class="flex-none">
          <router-link :to="{ name: 'IdentityGet', params: { id: doc.id } }" class="link">
            <img :src="doc.pictureUrl" alt="picture" class="h-20 w-20 ring-2 ring-white rounded" />
          </router-link>
        </div>
        <div class="flex-grow flex flex-col">
          <h2 v-if="doc.username" class="text-xl">
            <ul v-if="metadata.can_update || isDisabled()" class="flex flex-row flex-wrap content-start items-start gap-1 text-sm float-right">
              <li v-if="metadata.can_update" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm leading-none">admin</li>
              <li v-if="isDisabled()" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm leading-none">disabled</li>
            </ul>
            <router-link :to="{ name: 'IdentityGet', params: { id: doc.id } }" class="link">{{ doc.username }}</router-link>
            <span v-if="doc.email"> ({{ doc.email }})</span>
          </h2>
          <h2 v-else-if="doc.email" class="text-xl">
            <ul v-if="metadata.can_update || isDisabled()" class="flex flex-row flex-wrap content-start items-start gap-1 text-sm float-right">
              <li v-if="metadata.can_update" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm leading-none">admin</li>
              <li v-if="isDisabled()" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm leading-none">disabled</li>
            </ul>
            <router-link :to="{ name: 'IdentityGet', params: { id: doc.id } }" class="link">{{ doc.email }}</router-link>
          </h2>
          <h2 v-else-if="doc.givenName" class="text-xl">
            <ul v-if="metadata.can_update || isDisabled()" class="flex flex-row flex-wrap content-start items-start gap-1 text-sm float-right">
              <li v-if="metadata.can_update" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm leading-none">admin</li>
              <li v-if="isDisabled()" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm leading-none">disabled</li>
            </ul>
            <router-link :to="{ name: 'IdentityGet', params: { id: doc.id } }" class="link">{{ doc.givenName }}</router-link>
            <span v-if="doc.fullName"> ({{ doc.fullName }})</span>
          </h2>
          <h2 v-else-if="doc.fullName" class="text-xl">
            <ul v-if="metadata.can_update || isDisabled()" class="flex flex-row flex-wrap content-start items-start gap-1 text-sm float-right">
              <li v-if="metadata.can_update" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm leading-none">admin</li>
              <li v-if="isDisabled()" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm leading-none">disabled</li>
            </ul>
            <router-link :to="{ name: 'IdentityGet', params: { id: doc.id } }" class="link">{{ doc.fullName }}</router-link>
          </h2>
          <div v-else-if="metadata.can_update || isDisabled()">
            <ul class="flex flex-row flex-wrap content-start items-start gap-1 text-sm float-right">
              <li v-if="metadata.can_update" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm leading-none">admin</li>
              <li v-if="isDisabled()" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm leading-none">disabled</li>
            </ul>
          </div>
          <div v-if="doc.givenName && (doc.username || doc.email)" class="mt-1">
            {{ doc.givenName }}
            <span v-if="doc.fullName"> ({{ doc.fullName }})</span>
          </div>
          <div v-else-if="doc.fullName && (doc.username || doc.email)" class="mt-1">
            {{ doc.fullName }}
          </div>
          <div v-if="doc.description" class="mt-1 whitespace-pre-line">{{ doc.description }}</div>
        </div>
        <slot></slot>
      </div>
    </template>
  </WithIdentityDocument>
</template>
