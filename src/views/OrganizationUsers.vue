<script setup lang="ts">
import type { IdentityForAdmin, Identities } from "@/types"

import { onBeforeMount, onBeforeUnmount, ref } from "vue"
import { useI18n } from "vue-i18n"
import { useRouter } from "vue-router"
import WithDocument from "@/components/WithDocument.vue"
import OrganizationListItem from "@/partials/OrganizationListItem.vue"
import IdentityPublic from "@/partials/IdentityPublic.vue"
import NavBar from "@/partials/NavBar.vue"
import Footer from "@/partials/Footer.vue"
import IdentityOrganization from "@/partials/IdentityOrganization.vue"
import Button from "@/components/Button.vue"
import { getURL } from "@/api"
import { injectProgress } from "@/progress"

const props = defineProps<{
  id: string
}>()

const { t } = useI18n({ useScope: "global" })
const router = useRouter()
const progress = injectProgress()

const abortController = new AbortController()
const dataLoading = ref(true)
const dataLoadingError = ref("")
const users = ref<Identities>([])

onBeforeUnmount(() => {
  abortController.abort()
})

// TODO: If user is not signed-in, this will show "unexpected error".

onBeforeMount(async () => {
  progress.value += 1
  try {
    const url = router.apiResolve({
      name: "OrganizationUsers",
      params: {
        id: props.id,
      },
    }).href

    const response = await getURL<Identities>(url, null, abortController.signal, progress)
    if (abortController.signal.aborted) {
      return
    }

    users.value = response.doc
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("OrganizationUsers.onBeforeMount", error)
    dataLoadingError.value = `${error}`
  } finally {
    dataLoading.value = false
    progress.value -= 1
  }
})

function onBlock(identityId: string) {
  if (abortController.signal.aborted) {
    return
  }

  router.push({ name: "OrganizationBlockUser", params: { id: props.id, identityId: identityId } })
}

const WithIdentityForAdminDocument = WithDocument<IdentityForAdmin>
</script>

<template>
  <Teleport to="header">
    <NavBar></NavBar>
  </Teleport>
  <div class="w-full flex flex-col items-center mt-12 sm:mt-[4.5rem] border-t border-transparent">
    <div class="grid auto-rows-auto grid-cols-[minmax(0,_65ch)] m-1 sm:m-4 gap-1 sm:gap-4">
      <div class="w-full rounded border bg-white p-4 shadow flex flex-col gap-4">
        <div class="flex flex-col gap-4">
          <h1 class="text-2xl font-bold">{{ t("views.OrganizationUsers.usersForOrganization") }}</h1>
          <div>
            <OrganizationListItem :item="{ id }" />
          </div>
        </div>
      </div>
      <div v-if="dataLoading" class="w-full rounded border bg-white p-4 shadow">{{ t("common.data.dataLoading") }}</div>
      <div v-else-if="dataLoadingError" class="w-full rounded border bg-white p-4 shadow text-error-600">{{ t("common.errors.unexpected") }}</div>
      <template v-else>
        <div v-if="!users.length" class="w-full rounded border bg-white p-4 shadow italic">{{ t("views.OrganizationUsers.noUsers") }}</div>
        <div v-for="user in users" :key="user.id" class="w-full rounded border bg-white p-4 shadow">
          <WithIdentityForAdminDocument :params="{ id, identityId: user.id }" name="OrganizationIdentity">
            <template #default="{ doc, metadata, url }">
              <IdentityPublic :identity="doc" :url="url" :is-current="metadata.is_current" :can-update="metadata.can_update" />
              <IdentityOrganization :identity-organization="doc.organizations[0]">
                <template #default="{ organizationBlockedStatus }">
                  <div v-if="metadata.can_update && (!organizationBlockedStatus || organizationBlockedStatus.blocked === 'onlyIdentity' || organizationBlockedStatus.blocked === 'notBlocked')" class="flex flex-col items-start">
                    <Button type="button" :progress="progress" @click.prevent="onBlock(user.id)">
                      {{ !organizationBlockedStatus || organizationBlockedStatus.blocked === "notBlocked" ? t("common.buttons.block") : t("common.buttons.unblock") }}
                    </Button>
                  </div>
                </template>
              </IdentityOrganization>
            </template>
          </WithIdentityForAdminDocument>
        </div>
      </template>
    </div>
  </div>
  <Teleport to="footer">
    <Footer />
  </Teleport>
</template>
