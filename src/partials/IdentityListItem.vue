<script setup lang="ts">
import type { Identity, IdentityRef } from "@/types"

import WithDocument from "@/components/WithDocument.vue"

defineProps<{
  item: IdentityRef
}>()

const WithIdentityDocument = WithDocument<Identity>
</script>

<template>
  <WithIdentityDocument :id="item.id" name="IdentityGet">
    <template #default="{ doc, metadata, url }">
      <div class="flex flex-row gap-4" :data-url="url">
        <div v-if="doc.pictureUrl" class="flex-none">
          <router-link :to="{ name: 'IdentityGet', params: { id: doc.id } }" class="link">
            <img :src="doc.pictureUrl" alt="picture" class="h-20 w-20 ring-2 ring-white rounded" />
          </router-link>
        </div>
        <div class="flex-grow flex flex-col">
          <h2 v-if="doc.username" class="text-xl">
            <span v-if="metadata.can_update" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm text-sm leading-none float-right">admin</span>
            <router-link :to="{ name: 'IdentityGet', params: { id: doc.id } }" class="link">{{ doc.username }}</router-link>
            <span v-if="doc.email"> ({{ doc.email }})</span>
          </h2>
          <h2 v-else-if="doc.email" class="text-xl">
            <span v-if="metadata.can_update" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm text-sm leading-none float-right">admin</span>
            <router-link :to="{ name: 'IdentityGet', params: { id: doc.id } }" class="link">{{ doc.email }}</router-link>
          </h2>
          <h2 v-else-if="doc.givenName" class="text-xl">
            <span v-if="metadata.can_update" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm text-sm leading-none float-right">admin</span>
            <router-link :to="{ name: 'IdentityGet', params: { id: doc.id } }" class="link">{{ doc.givenName }}</router-link>
            <span v-if="doc.fullName"> ({{ doc.fullName }})</span>
          </h2>
          <h2 v-else-if="doc.fullName" class="text-xl">
            <span v-if="metadata.can_update" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm text-sm leading-none float-right">admin</span>
            <router-link :to="{ name: 'IdentityGet', params: { id: doc.id } }" class="link">{{ doc.fullName }}</router-link>
          </h2>
          <div v-else-if="metadata.can_update">
            <span class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm text-sm leading-none float-right">admin</span>
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
      </div>
    </template>
  </WithIdentityDocument>
</template>
