<script setup lang="ts">
import type { Identity, Identities } from "@/types"

import { onBeforeMount, onBeforeUnmount, ref } from "vue"
import { useI18n } from "vue-i18n"
import { useRouter } from "vue-router"
import WithDocument from "@/components/WithDocument.vue"
import ButtonLink from "@/components/ButtonLink.vue"
import IdentityFull from "@/partials/IdentityFull.vue"
import NavBar from "@/partials/NavBar.vue"
import Footer from "@/partials/Footer.vue"
import { getURL } from "@/api"
import { injectProgress } from "@/progress"
import { isSignedIn } from "@/auth"

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
  <div class="w-full flex flex-col items-center mt-12 sm:mt-[4.5rem] border-t border-transparent">
    <div class="grid auto-rows-auto grid-cols-[minmax(0,_65ch)] m-1 sm:m-4 gap-1 sm:gap-4">
      <div class="w-full rounded border bg-white p-4 shadow flex flex-col gap-4">
        <div class="flex flex-row justify-between items-center gap-4">
          <h1 class="text-2xl font-bold">{{ t("common.entities.identities") }}</h1>
          <ButtonLink v-if="isSignedIn()" :to="{ name: 'IdentityCreate' }" :progress="progress" primary>{{ t("common.buttons.create") }}</ButtonLink>
        </div>
      </div>
      <div v-if="dataLoading" class="w-full rounded border bg-white p-4 shadow">{{ t("common.data.dataLoading") }}</div>
      <div v-else-if="dataLoadingError" class="w-full rounded border bg-white p-4 shadow text-error-600">{{ t("common.errors.unexpected") }}</div>
      <template v-else>
        <div v-if="!identities.length" class="w-full rounded border bg-white p-4 shadow italic">
          {{ isSignedIn() ? t("views.IdentityList.noIdentitiesCreate") : t("views.IdentityList.noIdentitiesSignIn") }}
        </div>
        <div v-for="identity in identities" :key="identity.id" class="w-full rounded border bg-white p-4 shadow">
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
