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
    <template #default="{ doc, url }">
      <div class="flex flex-row gap-4" :data-url="url">
        <div v-if="doc.pictureUrl" class="flex-none">
          <router-link :to="{ name: 'IdentityGet', params: { id: doc.id } }" class="link">
            <img :src="doc.pictureUrl" alt="picture" class="h-20 w-20 ring-2 ring-white rounded" />
          </router-link>
        </div>
        <div class="flex-grow flex flex-col">
          <h2 v-if="doc.username" class="text-xl">
            <router-link :to="{ name: 'IdentityGet', params: { id: doc.id } }" class="link">{{ doc.username }}</router-link>
            <span v-if="doc.email"> ({{ doc.email }})</span>
          </h2>
          <h2 v-else-if="doc.email" class="text-xl">
            <router-link :to="{ name: 'IdentityGet', params: { id: doc.id } }" class="link">{{ doc.email }}</router-link>
          </h2>
          <h2 v-else-if="doc.givenName" class="text-xl">
            <router-link :to="{ name: 'IdentityGet', params: { id: doc.id } }" class="link">{{ doc.givenName }}</router-link>
            <span v-if="doc.fullName"> ({{ doc.fullName }})</span>
          </h2>
          <h2 v-else-if="doc.fullName" class="text-xl">
            <router-link :to="{ name: 'IdentityGet', params: { id: doc.id } }" class="link">{{ doc.fullName }}</router-link>
          </h2>
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
