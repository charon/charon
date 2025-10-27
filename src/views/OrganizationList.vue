<script setup lang="ts">
import type { Organizations } from "@/types"

import { onBeforeMount, onBeforeUnmount, ref } from "vue"
import { useI18n } from "vue-i18n"
import { useRouter } from "vue-router"

import { getURL } from "@/api"
import { isSignedIn } from "@/auth"
import ButtonLink from "@/components/ButtonLink.vue"
import Footer from "@/partials/Footer.vue"
import NavBar from "@/partials/NavBar.vue"
import OrganizationListItem from "@/partials/OrganizationListItem.vue"
import { injectProgress } from "@/progress"

const { t } = useI18n({ useScope: "global" })
const router = useRouter()
const progress = injectProgress()

const abortController = new AbortController()
const dataLoading = ref(true)
const dataLoadingError = ref("")
const organizations = ref<Organizations>([])

onBeforeUnmount(() => {
  abortController.abort()
})

onBeforeMount(async () => {
  progress.value += 1
  try {
    const url = router.apiResolve({
      name: "OrganizationList",
    }).href

    const response = await getURL<Organizations>(url, null, abortController.signal, progress)
    if (abortController.signal.aborted) {
      return
    }

    organizations.value = response.doc
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("OrganizationList.onBeforeMount", error)
    dataLoadingError.value = `${error}`
  } finally {
    dataLoading.value = false
    progress.value -= 1
  }
})
</script>

<template>
  <Teleport to="header">
    <NavBar></NavBar>
  </Teleport>
  <div class="w-full flex flex-col items-center mt-12 sm:mt-[4.5rem] border-t border-transparent">
    <div class="grid auto-rows-auto grid-cols-[minmax(0,_65ch)] m-1 sm:m-4 gap-1 sm:gap-4">
      <div class="w-full rounded-xs border bg-white p-4 shadow-sm flex flex-col gap-4">
        <div class="flex flex-row justify-between items-center gap-4">
          <h1 class="text-2xl font-bold">{{ t("common.entities.organizations") }}</h1>
          <ButtonLink v-if="isSignedIn()" :to="{ name: 'OrganizationCreate' }" :progress="progress" primary>{{ t("common.buttons.create") }}</ButtonLink>
        </div>
      </div>
      <div v-if="dataLoading" class="w-full rounded-xs border bg-white p-4 shadow-sm">{{ t("common.data.dataLoading") }}</div>
      <div v-else-if="dataLoadingError" class="w-full rounded-xs border bg-white p-4 shadow-sm text-error-600">{{ t("common.errors.unexpected") }}</div>
      <template v-else>
        <div v-if="!organizations.length" class="w-full rounded-xs border bg-white p-4 shadow-sm italic">
          {{ isSignedIn() ? t("views.OrganizationList.noOrganizationsCreate") : t("views.OrganizationList.noOrganizationsSignIn") }}
        </div>
        <div v-for="organization in organizations" :key="organization.id" class="w-full rounded-xs border bg-white p-4 shadow-sm">
          <OrganizationListItem :item="organization" />
        </div>
      </template>
    </div>
  </div>
  <Teleport to="footer">
    <Footer />
  </Teleport>
</template>
