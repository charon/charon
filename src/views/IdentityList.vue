<script setup lang="ts">
import type { Identities, Identity } from "@/types"

import { onBeforeMount, onBeforeUnmount, ref } from "vue"
import { useI18n } from "vue-i18n"
import { useRouter } from "vue-router"

import { getURL } from "@/api"
import { isSignedIn } from "@/auth"
import ButtonLink from "@/components/ButtonLink.vue"
import WithDocument from "@/components/WithDocument.vue"
import Footer from "@/partials/Footer.vue"
import IdentityFull from "@/partials/IdentityFull.vue"
import NavBar from "@/partials/NavBar.vue"
import { injectProgress } from "@/progress"

const { t } = useI18n({ useScope: "global" })
const router = useRouter()
const progress = injectProgress()

const abortController = new AbortController()
const dataLoading = ref(true)
const dataLoadingError = ref("")
const identities = ref<Identities>([])

onBeforeUnmount(() => {
  abortController.abort()
})

// TODO: If user is not signed-in, this will show "unexpected error".

onBeforeMount(async () => {
  progress.value += 1
  try {
    const url = router.apiResolve({
      name: "IdentityList",
    }).href

    const response = await getURL<Identities>(url, null, abortController.signal, progress)
    if (abortController.signal.aborted) {
      return
    }

    identities.value = response.doc
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("IdentityList.onBeforeMount", error)
    dataLoadingError.value = `${error}`
  } finally {
    dataLoading.value = false
    progress.value -= 1
  }
})

const WithIdentityDocument = WithDocument<Identity>
</script>

<template>
  <Teleport to="header">
    <NavBar></NavBar>
  </Teleport>
  <div class="mt-12 flex w-full flex-col items-center border-t border-transparent sm:mt-[4.5rem]">
    <div class="m-1 grid auto-rows-auto grid-cols-[minmax(0,_65ch)] gap-1 sm:m-4 sm:gap-4">
      <div class="flex w-full flex-col gap-4 rounded-xs border border-gray-200 bg-white p-4 shadow-sm">
        <div class="flex flex-row items-center justify-between gap-4">
          <h1 class="text-2xl font-bold">{{ t("common.entities.identities") }}</h1>
          <ButtonLink v-if="isSignedIn()" :to="{ name: 'IdentityCreate' }" :progress="progress" primary>{{ t("common.buttons.create") }}</ButtonLink>
        </div>
      </div>
      <div v-if="dataLoading" class="w-full rounded-xs border border-gray-200 bg-white p-4 shadow-sm">{{ t("common.data.dataLoading") }}</div>
      <div v-else-if="dataLoadingError" class="w-full rounded-xs border border-gray-200 bg-white p-4 text-error-600 shadow-sm">{{ t("common.errors.unexpected") }}</div>
      <template v-else>
        <div v-if="!identities.length" class="w-full rounded-xs border border-gray-200 bg-white p-4 italic shadow-sm">
          {{ isSignedIn() ? t("views.IdentityList.noIdentitiesCreate") : t("views.IdentityList.noIdentitiesSignIn") }}
        </div>
        <div v-for="identity in identities" :key="identity.id" class="w-full rounded-xs border border-gray-200 bg-white p-4 shadow-sm">
          <WithIdentityDocument :params="{ id: identity.id }" name="IdentityGet">
            <template #default="{ doc, metadata, url }">
              <IdentityFull :identity="doc" :url="url" :is-current="metadata.is_current" :can-update="metadata.can_update" />
            </template>
          </WithIdentityDocument>
        </div>
      </template>
    </div>
  </div>
  <Teleport to="footer">
    <Footer />
  </Teleport>
</template>
