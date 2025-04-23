<script setup lang="ts">
import type { IdentityPublic as IdentityPublicType, IdentityRef } from "@/types"

import WithDocument from "@/components/WithDocument.vue"
import IdentityPublic from "@/partials/IdentityPublic.vue"

defineProps<{
  item: IdentityRef
  organizationId: string
  labels?: string[]
}>()

const WithIdentityPublicDocument = WithDocument<IdentityPublicType>
</script>

<template>
  <WithIdentityPublicDocument :params="{ id: organizationId, identityId: item.id }" name="OrganizationIdentity">
    <template #default="{ doc, metadata, url }">
      <IdentityPublic :identity="doc" :url="url" :is-current="metadata.is_current" :can-update="metadata.can_update" :labels="labels" />
    </template>
    <template #error="{ url }">
      <div class="flex flex-row gap-4" :data-url="url">
        <div class="flex-grow flex">
          <span class="text-error-600 italic">loading data failed</span>
        </div>
        <slot :identity="undefined" :is-current="undefined" :can-update="undefined"></slot>
      </div>
    </template>
  </WithIdentityPublicDocument>
</template>
