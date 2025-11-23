<script setup lang="ts">
import type { CredentialAddResponse, CredentialAddUsernameRequest } from "@/types"

import { onBeforeUnmount, onMounted, ref, watch } from "vue"
import { useI18n } from "vue-i18n"
import { useRouter } from "vue-router"

import { postJSON } from "@/api.ts"
import Button from "@/components/Button.vue"
import InputText from "@/components/InputText.vue"
import { injectProgress } from "@/progress.ts"

const { t } = useI18n({ useScope: "global" })
const router = useRouter()
const progress = injectProgress()

const abortController = new AbortController()
const username = ref("")
const usernameError = ref("")
const unexpectedError = ref("")

function getErrorMessage(errorCode: string) {
  switch (errorCode) {
    case "invalidEmailOrUsername":
      return t("common.errors.invalidEmailOrUsername.username")
    case "shortEmailOrUsername":
      return t("common.errors.shortEmailOrUsername.username")
    case "credentialInUse":
      return t("common.errors.credentialInUse.username")
    case "alreadyPresent":
      return t("common.errors.alreadyPresent.username")
    default:
      throw new Error(`unexpected error code: ${errorCode}`)
  }
}

function resetOnInteraction() {
  // We reset the error on interaction.
  usernameError.value = ""
  unexpectedError.value = ""
}

watch([username], resetOnInteraction)

onBeforeUnmount(() => {
  abortController.abort()
})

onMounted(() => {
  document.getElementById("credentialaddusername-input-username")?.focus()
})

function canSubmit(): boolean {
  // Required fields.
  return !!username.value
}

async function onSubmit() {
  if (abortController.signal.aborted) {
    return
  }

  resetOnInteraction()

  progress.value += 1
  try {
    const url = router.apiResolve({
      name: "CredentialAddUsername",
    }).href

    const response = await postJSON<CredentialAddResponse>(
      url,
      {
        username: username.value,
      } as CredentialAddUsernameRequest,
      abortController.signal,
      progress,
    )
    if (abortController.signal.aborted) {
      return
    }
    if (response.error) {
      // We check if it is an expected error code by trying to get the error message.
      getErrorMessage(response.error)
      usernameError.value = response.error
      return
    }

    await router.push({ name: "CredentialList" })
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("CredentialAddUsername.onSubmit", error)
    // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
    unexpectedError.value = `${error}`
  } finally {
    progress.value -= 1
  }
}
</script>

<template>
  <!--
    We set novalidate because we do not UA to show hints.
    We show them ourselves when we want them.
  -->
  <form class="flex flex-col" novalidate @submit.prevent="onSubmit">
    <label for="credentialaddusername-input-username" class="mb-1">{{ t("common.fields.username") }}</label>
    <InputText
      id="credentialaddusername-input-username"
      v-model="username"
      class="min-w-0 flex-auto grow"
      :progress="progress"
      autocomplete="off"
      autocorrect="off"
      autocapitalize="none"
      spellcheck="false"
      minlength="3"
      required
    />
    <div v-if="usernameError" class="mt-4 text-error-600">{{ getErrorMessage(usernameError) }}</div>
    <div v-else-if="unexpectedError" class="mt-4 text-error-600">{{ t("common.errors.unexpected") }}</div>
    <div class="mt-4 flex flex-row justify-end">
      <Button type="submit" primary :disabled="!canSubmit()" :progress="progress">{{ t("common.buttons.add") }}</Button>
    </div>
  </form>
</template>
