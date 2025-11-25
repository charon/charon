<script setup lang="ts">
import type { Ref } from "vue"

import type { CredentialInfo } from "@/types"

import { onBeforeMount, onBeforeUnmount, ref, watch } from "vue"
import { useI18n } from "vue-i18n"
import {type Router, useRouter} from "vue-router"

import { getURL, postJSON } from "@/api"
import Button from "@/components/Button.vue"
import InputText from "@/components/InputText.vue"
import Footer from "@/partials/Footer.vue"
import NavBar from "@/partials/NavBar.vue"
import { injectProgress } from "@/progress"

const { t } = useI18n({ useScope: "global" })
const progress = injectProgress()
const router = useRouter()

const abortController = new AbortController()
const unexpectedError = ref("")
const dataLoading = ref(true)
const dataLoadingError = ref("")
const updateError = ref("")

const credential = ref<CredentialInfo | null>(null)
const displayName = ref("")

function getErrorMessage(errorCode: string) {
  switch (errorCode) {
    case "todo":
      return "error"
    default:
      throw new Error(`unexpected error code: ${errorCode}`)
  }
}

const props = defineProps<{
  id: string
}>()

async function getCredential(router: Router, abortController: AbortController, progress: Ref<number>): Promise<CredentialInfo | null> {
  progress.value += 1
  try {
    const url = router.apiResolve({
      name: "CredentialGet",
      params: { id: props.id },
    }).href

    const response = await getURL<CredentialInfo>(url, null, abortController.signal, progress)
    if (abortController.signal.aborted) {
      return null
    }

    return response.doc
  } finally {
    progress.value -= 1
  }
}

onBeforeMount(async () => {
  progress.value += 1
  try {
    const result = await getCredential(router, abortController, progress)
    if (abortController.signal.aborted || !result) {
      return
    }

    credential.value = result
    displayName.value = result.displayName
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("CredentialUpdateDisplayName.onBeforeMount", error)
    // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
    dataLoadingError.value = `${error}`
  } finally {
    dataLoading.value = false
    progress.value -= 1
  }
})

onBeforeUnmount(() => {
  abortController.abort()
})

// Watch displayName for changes to reset errors.
watch(displayName, () => {
  resetOnInteraction()
})

async function onSubmit() {
  if (abortController.signal.aborted) {
    return
  }

  resetOnInteraction()

  progress.value += 1
  try {
    const url = router.apiResolve({
      name: "CredentialUpdateDisplayName",
      params: { id: props.id },
    }).href

    await postJSON(url, { displayName: displayName.value.trim() }, abortController.signal, progress)
    if (abortController.signal.aborted) {
      return
    }

    // Redirect back to credential list on success.
    await router.push({ name: "CredentialList" })
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("CredentialUpdateDisplayName.onSubmit", error)
    // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
    unexpectedError.value = `${error}`
  } finally {
    progress.value -= 1
  }
}

function resetOnInteraction() {
  // We reset the error on interaction.
  updateError.value = ""
  unexpectedError.value = ""
}

function canSubmit(): boolean {
  if (!credential.value) {
    return false
  }
  return !!displayName.value.trim() && displayName.value.trim() !== credential.value.displayName
}
</script>

<template>
  <Teleport to="header">
    <NavBar></NavBar>
  </Teleport>
  <div class="mt-12 flex w-full flex-col items-center border-t border-transparent sm:mt-[4.5rem]">
    <div class="m-1 grid auto-rows-auto grid-cols-[minmax(0,65ch)] gap-1 sm:m-4 sm:gap-4">
      <div class="flex w-full flex-col gap-4 rounded-sm border border-gray-200 bg-white p-4 shadow-sm">
        <div class="flex flex-row items-center justify-between gap-4">
          <h1 class="text-2xl font-bold">{{ t("views.CredentialUpdateDisplayName.updateDisplayName") }}</h1>
        </div>
      </div>
      <div v-if="dataLoading" class="w-full rounded-sm border border-gray-200 bg-white p-4 shadow-sm">{{ t("common.data.dataLoading") }}</div>
      <div v-else-if="dataLoadingError" class="w-full rounded-sm border border-gray-200 bg-white p-4 text-error-600 shadow-sm">
        {{ t("common.errors.unexpected") }}
      </div>
      <div v-else-if="credential" class="w-full rounded-sm border border-gray-200 bg-white p-4 shadow-sm">
        <form class="flex flex-col" novalidate @submit.prevent="onSubmit">
          <label for="credentialupdatedisplayname-input" class="mb-1">{{ t("views.CredentialUpdateDisplayName.displayNameLabel") }}</label>
          <InputText
              id="credentialupdatedisplayname-input"
              v-model="displayName"
              class="min-w-0 flex-auto grow"
              :progress="progress"
              autocomplete="off"
              autocorrect="off"
              autocapitalize="none"
              spellcheck="false"
              required
          />
          <div v-if="updateError" class="mt-4 text-error-600">{{ getErrorMessage(updateError) }}</div>
          <div v-else-if="unexpectedError" class="mt-4 text-error-600">{{ unexpectedError }}</div>
          <div class="mt-4 flex flex-row justify-end">
            <Button type="submit" primary :disabled="!canSubmit()" :progress="progress">{{ t("common.buttons.update") }}</Button>
          </div>
        </form>
      </div>
    </div>
  </div>
  <Teleport to="footer">
    <Footer />
  </Teleport>
</template>