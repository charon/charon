<script setup lang="ts">
import type { Identity, IdentityRef } from "@/types"
import type { ComponentExposed } from "vue-component-type-helpers"

import { ref } from "vue"
import WithDocument from "@/components/WithDocument.vue"

defineProps<{
  item: IdentityRef
  flowId?: string
  labels?: string[]
}>()

const WithIdentityDocument = WithDocument<Identity>
const identity = ref<ComponentExposed<typeof WithIdentityDocument> | null>(null)
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
            <ul v-if="metadata.can_update || metadata.is_current || labels?.length" class="flex flex-row flex-wrap content-start items-start gap-1 text-sm float-right">
              <li v-for="label in labels || []" :key="label" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm text-sm leading-none">{{ label }}</li>
              <li v-if="metadata.is_current" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm leading-none">current</li>
              <li v-if="metadata.can_update" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm leading-none">admin</li>
            </ul>
            <router-link :to="{ name: 'IdentityGet', params: { id: doc.id } }" class="link">{{ doc.username }}</router-link>
            <span v-if="doc.email"> ({{ doc.email }})</span>
          </h2>
          <h2 v-else-if="doc.email" class="text-xl">
            <ul v-if="metadata.can_update || metadata.is_current || labels?.length" class="flex flex-row flex-wrap content-start items-start gap-1 text-sm float-right">
              <li v-for="label in labels || []" :key="label" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm text-sm leading-none">{{ label }}</li>
              <li v-if="metadata.is_current" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm leading-none">current</li>
              <li v-if="metadata.can_update" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm leading-none">admin</li>
            </ul>
            <router-link :to="{ name: 'IdentityGet', params: { id: doc.id } }" class="link">{{ doc.email }}</router-link>
          </h2>
          <h2 v-else-if="doc.givenName" class="text-xl">
            <ul v-if="metadata.can_update || metadata.is_current || labels?.length" class="flex flex-row flex-wrap content-start items-start gap-1 text-sm float-right">
              <li v-for="label in labels || []" :key="label" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm text-sm leading-none">{{ label }}</li>
              <li v-if="metadata.is_current" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm leading-none">current</li>
              <li v-if="metadata.can_update" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm leading-none">admin</li>
            </ul>
            <router-link :to="{ name: 'IdentityGet', params: { id: doc.id } }" class="link">{{ doc.givenName }}</router-link>
            <span v-if="doc.fullName"> ({{ doc.fullName }})</span>
          </h2>
          <h2 v-else-if="doc.fullName" class="text-xl">
            <ul v-if="metadata.can_update || metadata.is_current || labels?.length" class="flex flex-row flex-wrap content-start items-start gap-1 text-sm float-right">
              <li v-for="label in labels || []" :key="label" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm text-sm leading-none">{{ label }}</li>
              <li v-if="metadata.is_current" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm leading-none">current</li>
              <li v-if="metadata.can_update" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm leading-none">admin</li>
            </ul>
            <router-link :to="{ name: 'IdentityGet', params: { id: doc.id } }" class="link">{{ doc.fullName }}</router-link>
          </h2>
          <div v-else-if="metadata.can_update || metadata.is_current || labels?.length">
            <ul class="flex flex-row flex-wrap content-start items-start gap-1 text-sm float-right">
              <li v-for="label in labels || []" :key="label" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm text-sm leading-none">{{ label }}</li>
              <li v-if="metadata.is_current" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm leading-none">current</li>
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
          <div v-if="doc.description" class="mt-1 whitespace-pre-line">{{ doc.description }}</div>
        </div>
        <slot :doc="doc" :metadata="metadata"></slot>
      </div>
    </template>
    <template #error="{ url }">
      <div class="flex flex-row gap-4" :data-url="url">
        <div class="flex-grow flex">
          <span class="text-error-600 italic">loading data failed</span>
        </div>
        <slot :doc="undefined" :metadata="undefined"></slot>
      </div>
    </template>
  </WithIdentityDocument>
</template>
