<script setup lang="ts">
import type { Organization, OrganizationRef } from "@/types"

import { useI18n } from "vue-i18n"

import WithDocument from "@/components/WithDocument.vue"
import OrganizationPublic from "@/partials/OrganizationPublic.vue"

defineProps<{
  item: OrganizationRef
  h3?: boolean
  labels?: string[]
}>()

const { t } = useI18n({ useScope: "global" })

const WithOrganizationDocument = WithDocument<Organization>
</script>

<template>
  <WithOrganizationDocument :params="{ id: item.id }" name="OrganizationGet">
    <template #default="{ doc, metadata, url }">
      <OrganizationPublic :organization="doc" :url="url" :can-update="metadata.can_update" :h3="h3" :labels="labels">
        <slot :organization="doc" :can-update="metadata.can_update"></slot>
      </OrganizationPublic>
    </template>
    <template #error="{ url }">
      <div class="flex flex-row gap-4" :data-url="url">
        <div class="flex grow">
          <span class="text-error-600 italic">{{ t("common.data.loadingDataFailed") }}</span>
        </div>
        <slot :organization="undefined" :can-update="undefined"></slot>
      </div>
    </template>
  </WithOrganizationDocument>
</template>
