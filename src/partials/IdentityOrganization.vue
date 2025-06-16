<script setup lang="ts">
import type { IdentityOrganization, OrganizationApplicationPublic } from "@/types"
import type { DeepReadonly } from "vue"

import WithDocument from "@/components/WithDocument.vue"
import { getHomepage } from "@/utils"

defineProps<{
  identityOrganization: IdentityOrganization | DeepReadonly<IdentityOrganization>
}>()

const WithOrganizationApplicationDocument = WithDocument<OrganizationApplicationPublic>
</script>

<template>
  <div class="ml-4 mt-4 flex flew-row gap-4 justify-between items-start">
    <div class="grid auto-rows-auto grid-cols-[max-content,auto] gap-x-1">
      <div>ID:</div>
      <div v-if="identityOrganization.id">
        <code>{{ identityOrganization.id }}</code>
      </div>
      <div v-else><span class="italic">confirm update to allocate</span></div>
      <div>Status:</div>
      <div>
        <strong>{{ identityOrganization.active ? "active" : "disabled" }}</strong>
      </div>
      <div>Apps:</div>
      <ol v-if="identityOrganization.applications.length">
        <li v-for="application in identityOrganization.applications" :key="application.id">
          <WithOrganizationApplicationDocument :params="{ id: identityOrganization.organization.id, appId: application.id }" name="OrganizationApp">
            <template #default="{ doc }">
              <a :href="getHomepage(doc)" class="link">{{ doc.applicationTemplate.name }}</a>
            </template>
          </WithOrganizationApplicationDocument>
        </li>
      </ol>
      <div v-else class="italic">none</div>
    </div>
    <slot />
  </div>
</template>
