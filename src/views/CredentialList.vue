<script setup lang="ts">
import type { CredentialInfo, Credentials } from "@/types"

import { onBeforeMount, onBeforeUnmount, Ref, ref } from "vue"
import { useI18n } from "vue-i18n"
import { Router, useRouter } from "vue-router"

import {FetchError, getCredentials, postJSON} from "@/api"
import { isSignedIn } from "@/auth"
import Button from "@/components/Button.vue"
import ButtonLink from "@/components/ButtonLink.vue"
import WithDocument from "@/components/WithDocument.vue"
import CredentialFull from "@/partials/credentials/CredentialFull.vue"
import Footer from "@/partials/Footer.vue"
import NavBar from "@/partials/NavBar.vue"
import { injectProgress } from "@/progress"

const { t } = useI18n({ useScope: "global" })
const router = useRouter()

const progress = injectProgress()

const abortController = new AbortController()
const unexpectedError = ref("")
const dataLoading = ref(true)
const dataLoadingError = ref("")
const credentials = ref<Credentials>([])

onBeforeUnmount(() => {
  abortController.abort()
})

onBeforeMount(async () => {
  progress.value += 1
  try {
    const result = await getCredentials(router, abortController, progress)
    if (abortController.signal.aborted || !result) {
      return
    }

    credentials.value = result
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }

    if (error instanceof  FetchError && error.status === 401){
      credentials.value = []
    } else {
      console.error("CredentialList.onBeforeMount", error)
      dataLoadingError.value = `${error}`
    }
  } finally {
    dataLoading.value = false
    progress.value -= 1
  }
})

function resetOnInteraction() {
  // We reset the error on interaction.
  unexpectedError.value = ""
}

async function removeCredential(router: Router, id: string, abortController: AbortController, progress: Ref<number>): Promise<boolean> {
  progress.value += 1
  try {
    const url = router.apiResolve({
      name: "CredentialRemove",
      params: { id },
    }).href

    await postJSON(url, {}, abortController.signal, progress)
    return !abortController.signal.aborted
  } finally {
    progress.value -= 1
  }
}

async function onRemove(credentialId: string) {
  if (abortController.signal.aborted) {
    return
  }
  resetOnInteraction()
  progress.value += 1

  try {
    const success = await removeCredential(router, credentialId, abortController, progress)
    if (abortController.signal.aborted) {
      return
    }
    if (!success) {
      throw new Error("failed to remove credential")
    }
    credentials.value = credentials.value.filter((c) => c.id !== credentialId)
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    unexpectedError.value = `${error}`
    console.error("CredentialList.onRemove", error)
  } finally {
    progress.value -= 1
  }
}

const WithCredentialDocument = WithDocument<CredentialInfo>
</script>

<template>
  <Teleport to="header">
    <NavBar></NavBar>
  </Teleport>
  <div class="mt-12 flex w-full flex-col items-center border-t border-transparent sm:mt-[4.5rem]">
    <div class="m-1 grid auto-rows-auto grid-cols-[minmax(0,65ch)] gap-1 sm:m-4 sm:gap-4">
      <div class="flex w-full flex-col gap-4 rounded-sm border border-gray-200 bg-white p-4 shadow-sm">
        <div class="flex flex-row items-center justify-between gap-4">
          <h1 class="text-2xl font-bold">{{ t("common.entities.credentials") }}</h1>
          <ButtonLink v-if="isSignedIn()" :to="{ name: 'CredentialAdd' }" :progress="progress" primary>
            {{ t("common.buttons.add") }}
          </ButtonLink>
        </div>
      </div>
      <div v-if="dataLoading" class="w-full rounded-sm border border-gray-200 bg-white p-4 shadow-sm">{{ t("common.data.dataLoading") }}</div>
      <div v-else-if="dataLoadingError" class="w-full rounded-sm border border-gray-200 bg-white p-4 text-error-600 shadow-sm">{{ t("common.errors.unexpected") }}</div>
      <template v-else>
        <div v-if="!credentials.length" class="w-full rounded-sm border border-gray-200 bg-white p-4 italic shadow-sm">
          {{ isSignedIn() ? t("views.CredentialList.noCredentialsCreate") : t("views.CredentialList.noCredentialsSignIn") }}
        </div>
        <div v-for="credential in credentials" :key="credential.id" class="w-full rounded-sm border border-gray-200 bg-white p-4 shadow-sm">
          <WithCredentialDocument :params="{ id: credential.id }" name="CredentialGet">
            <template #default="{ doc, url }">
              <CredentialFull :credential="doc" :url="url">
                <Button v-if="doc.provider === 'email'" :id="`credentiallist-button-verify-${doc.id}`" type="button" secondary disabled>
                  {{ t("views.CredentialList.verify") }}
                </Button>
                <Button :id="`credentiallist-button-remove-${doc.id}`" type="button" :progress="progress" @click="onRemove(doc.id)">
                  {{ t("common.buttons.remove") }}
                </Button>
              </CredentialFull>
            </template>
          </WithCredentialDocument>
        </div>
      </template>
    </div>
  </div>
  <Teleport to="footer">
    <Footer />
  </Teleport>
</template>
