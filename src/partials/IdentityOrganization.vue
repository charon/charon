<script setup lang="ts">
import type { IdentityOrganization, OrganizationApplicationPublic, OrganizationBlockedStatus } from "@/types"
import type { ComponentExposed } from "vue-component-type-helpers"
import type { DeepReadonly } from "vue"

import { ref } from "vue"
import { useI18n } from "vue-i18n"
import WithDocument from "@/components/WithDocument.vue"
import { getHomepage } from "@/utils"

defineProps<{
  identityOrganization: IdentityOrganization | DeepReadonly<IdentityOrganization>
}>()

const { t } = useI18n({ useScope: "global" })

const WithOrganizationApplicationDocument = WithDocument<OrganizationApplicationPublic>
const withOrganizationApplicationDocument = ref<ComponentExposed<typeof WithOrganizationApplicationDocument> | null>(null)
const WithOrganizationBlockedStatusDocument = WithDocument<OrganizationBlockedStatus>
const withOrganizationBlockedStatusDocument = ref<ComponentExposed<typeof WithOrganizationBlockedStatusDocument> | null>(null)
</script>

<template>
  <div class="ml-4 mt-4 flex flew-row gap-4 justify-between items-start">
    <div class="grid auto-rows-auto grid-cols-[max-content,auto] gap-x-1">
      <div>{{ t("partials.IdentityOrganization.id") }}</div>
      <div v-if="identityOrganization.id">
        <code>{{ identityOrganization.id }}</code>
      </div>
      <div v-else>
        <span class="italic">{{ t("common.data.confirmUpdateToAllocate") }}</span>
      </div>
      <div>{{ t("partials.IdentityOrganization.status") }}</div>
      <div>
        <WithOrganizationBlockedStatusDocument
          v-if="identityOrganization.id"
          ref="withOrganizationBlockedStatusDocument"
          :params="{ id: identityOrganization.organization.id, identityId: identityOrganization.id }"
          name="OrganizationBlockedStatus"
        >
          <template #default="{ doc, url }">
            <strong v-if="doc.blocked !== 'notBlocked'" :data-url="url">{{
              t("partials.IdentityOrganization.statusAndBlocked", {
                status: identityOrganization.active ? t("common.labels.active") : t("common.labels.disabled"),
                blocked: t("common.labels.blocked"),
              })
            }}</strong>
            <strong v-else>{{ identityOrganization.active ? t("common.labels.active") : t("common.labels.disabled") }}</strong>
          </template>
        </WithOrganizationBlockedStatusDocument>
        <strong v-else>{{ identityOrganization.active ? t("common.labels.active") : t("common.labels.disabled") }}</strong>
      </div>
      <div>{{ t("partials.IdentityOrganization.apps") }}</div>
      <ol v-if="identityOrganization.applications.length">
        <li v-for="application in identityOrganization.applications" :key="application.id">
          <WithOrganizationApplicationDocument
            ref="withOrganizationApplicationDocument"
            :params="{ id: identityOrganization.organization.id, appId: application.id }"
            name="OrganizationApp"
          >
            <template #default="{ doc, url }">
              <a :href="getHomepage(doc)" :data-url="url" class="link">{{ doc.applicationTemplate.name }}</a>
            </template>
          </WithOrganizationApplicationDocument>
        </li>
      </ol>
      <div v-else class="italic">{{ t("partials.IdentityOrganization.noApps") }}</div>
    </div>
    <slot :organization-application="withOrganizationApplicationDocument?.doc" :organization-blocked-status="withOrganizationBlockedStatusDocument?.doc" />
  </div>
</template>
