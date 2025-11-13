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
    default:
      return t("common.errors.unexpected")
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
  return username.value.trim().length > 0
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
      usernameError.value = response.error
      return
    }

    router.push({ name: "CredentialList" })
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("CredentialAddUsername.onSubmit", error)
    unexpectedError.value = t("common.errors.unexpected")
  } finally {
    progress.value -= 1
  }
}
</script>

<template>
  <form class="flex flex-col" novalidate @submit.prevent="onSubmit">
    <label for="username" class="mb-1">{{ t("common.fields.username") }}</label>
    <InputText
      id="credentialaddusername-input-username"
      v-model="username"
      name="username"
      tabindex="0"
      class="min-w-0 flex-auto grow"
      :progress="progress"
      autocorrect="off"
      autocapitalize="none"
      spellcheck="false"
      required
    />
    <div v-if="unexpectedError" class="mt-4 text-error-600">{{ t("common.errors.unexpected") }}</div>
    <div v-else-if="usernameError" class="mt-4 text-error-600">{{ getErrorMessage(usernameError) }}</div>
    <div class="mt-4 flex flex-row justify-end gap-4">
      <Button type="submit" primary :disabled="!canSubmit()" :progress="progress">{{ t("common.buttons.add") }}</Button>
    </div>
  </form>
</template>
