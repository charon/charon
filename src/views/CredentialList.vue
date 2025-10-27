<script setup lang="ts">
import type { Credentials } from "@/types"

import { getCredentials, removeCredential } from "@/api"
import { isSignedIn } from "@/auth"
import ButtonLink from "@/components/ButtonLink.vue"
import CredentialListItem from "@/partials/CredentialListItem.vue"
import Footer from "@/partials/Footer.vue"
import NavBar from "@/partials/NavBar.vue"
import { injectProgress } from "@/progress"
import { onBeforeMount, onBeforeUnmount, ref } from "vue"
import { useI18n } from "vue-i18n"
import { useRoute, useRouter } from "vue-router"

const { t } = useI18n({ useScope: "global" })
const route = useRoute()
const router = useRouter()
const progress = injectProgress()

const abortController = new AbortController()
const dataLoading = ref(true)
const dataLoadingError = ref("")
const credentials = ref<Credentials>([])
const removingCredentialId = ref<string | null>(null)

onBeforeUnmount(() => {
  abortController.abort()
})

onBeforeMount(async () => {
  progress.value += 1
  try {
    const flowId = route.query.flow as string | undefined
    const result = await getCredentials(router, abortController, progress, flowId)
    if (abortController.signal.aborted) {
      return
    }

    if (result === null) {
      dataLoadingError.value = t("common.errors.unexpected")
      return
    }

    credentials.value = result
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("CredentialList.onBeforeMount", error)
    dataLoadingError.value = `${error}`
  } finally {
    dataLoading.value = false
    progress.value -= 1
  }
})

async function handleRemove(credentialId: string) {
  if (abortController.signal.aborted || removingCredentialId.value) {
    return
  }

  removingCredentialId.value = credentialId

  try {
    const success = await removeCredential(router, credentialId, abortController, progress)
    if (abortController.signal.aborted) {
      return
    }

    if (success) {
      credentials.value = credentials.value.filter((c) => c.id !== credentialId)
    } else {
      console.error("Failed to remove credential")
    }
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("CredentialList.handleRemove", error)
  } finally {
    removingCredentialId.value = null
  }
}
</script>

<template>
  <Teleport to="header">
    <NavBar></NavBar>
  </Teleport>
  <div class="w-full flex flex-col items-center mt-12 sm:mt-[4.5rem] border-t border-transparent">
    <div class="grid auto-rows-auto grid-cols-[minmax(0,_65ch)] m-1 sm:m-4 gap-1 sm:gap-4">
      <div class="w-full rounded border bg-white p-4 shadow flex flex-col gap-4">
        <div class="flex flex-row justify-between items-center gap-4">
          <h1 class="text-2xl font-bold">{{ t("common.entities.credentials") }}</h1>
          <ButtonLink v-if="isSignedIn()" :to="{ name: 'CredentialAdd' }" :progress="progress" primary>
            {{ t("common.buttons.add") }}
          </ButtonLink>
        </div>
      </div>
      <div v-if="dataLoading" class="w-full rounded border bg-white p-4 shadow">{{ t("common.data.dataLoading") }}</div>
      <div v-else-if="dataLoadingError" class="w-full rounded border bg-white p-4 shadow text-error-600">{{ t("common.errors.unexpected") }}</div>
      <template v-else>
        <div v-if="!credentials.length" class="w-full rounded border bg-white p-4 shadow italic">
          {{ isSignedIn() ? t("views.CredentialList.noCredentialsCreate") : t("views.CredentialList.noCredentialsSignIn") }}
        </div>
        <CredentialListItem
          v-for="credential in credentials"
          :key="credential.id"
          :credential="credential"
          :removing="removingCredentialId === credential.id"
          :progress="progress"
          @remove="handleRemove"
        />
      </template>
    </div>
  </div>
  <Teleport to="footer">
    <Footer />
  </Teleport>
</template>
