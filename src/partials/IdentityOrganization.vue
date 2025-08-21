<script setup lang="ts">
import type { IdentityOrganization, OrganizationApplicationPublic } from "@/types"
import type { DeepReadonly } from "vue"

import { useI18n } from "vue-i18n"
import WithDocument from "@/components/WithDocument.vue"
import { getHomepage } from "@/utils"

const { t } = useI18n()

defineProps<{
  identityOrganization: IdentityOrganization | DeepReadonly<IdentityOrganization>
}>()

const WithOrganizationApplicationDocument = WithDocument<OrganizationApplicationPublic>
</script>

<template>
  <div class="ml-4 mt-4 flex flew-row gap-4 justify-between items-start">
    <div class="grid auto-rows-auto grid-cols-[max-content,auto] gap-x-1">
      <div>{{ t("labels.id") }}</div>
      <div v-if="identityOrganization.id">
        <code>{{ identityOrganization.id }}</code>
      </div>
      <div v-else>
        <span class="italic">{{ t("labels.confirmUpdateToAllocate") }}</span>
      </div>
      <div>{{ t("labels.status") }}</div>
      <div>
        <strong>{{ identityOrganization.active ? t("labels.active") : t("labels.disabled") }}</strong>
      </div>
      <div>{{ t("labels.apps") }}</div>
      <ol v-if="identityOrganization.applications.length">
        <li v-for="application in identityOrganization.applications" :key="application.id">
          <WithOrganizationApplicationDocument :params="{ id: identityOrganization.organization.id, appId: application.id }" name="OrganizationApp">
            <template #default="{ doc }">
              <a :href="getHomepage(doc)" class="link">{{ doc.applicationTemplate.name }}</a>
            </template>
          </WithOrganizationApplicationDocument>
        </li>
      </ol>
      <div v-else class="italic">{{ t("labels.none") }}</div>
    </div>
    <slot />
  </div>
</template>
