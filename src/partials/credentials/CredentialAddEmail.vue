<script setup lang="ts">
import type { CredentialAddEmailRequest, CredentialAddResponse } from "@/types"

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
const email = ref("")
const emailError = ref("")
const unexpectedError = ref("")

function getErrorMessage(errorCode: string) {
  switch (errorCode) {
    case "invalidEmailOrUsername":
      return t("common.errors.invalidEmailOrUsername.email")
    case "shortEmailOrUsername":
      return t("common.errors.shortEmailOrUsername.email")
    case "alreadyPresent":
      return t("common.errors.alreadyPresent.email")
    default:
      return t("common.errors.unexpected")
  }
}

function resetOnInteraction() {
  // We reset the error on interaction.
  emailError.value = ""
  unexpectedError.value = ""
}

watch([email], resetOnInteraction)

onBeforeUnmount(() => {
  abortController.abort()
})

onMounted(() => {
  document.getElementById("credentialaddemail-input-email")?.focus()
})

function canSubmit(): boolean {
  return email.value.trim().length > 0
}

async function onSubmit() {
  if (abortController.signal.aborted) {
    return
  }

  resetOnInteraction()

  progress.value += 1
  try {
    const url = router.apiResolve({
      name: "CredentialAddEmail",
    }).href

    const response = await postJSON<CredentialAddResponse>(
      url,
      {
        email: email.value,
      } as CredentialAddEmailRequest,
      abortController.signal,
      progress,
    )
    if (abortController.signal.aborted) {
      return
    }

    if (response.error) {
      emailError.value = response.error
      return
    }

    router.push({ name: "CredentialList" })
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("CredentialAddEmail.onSubmit", error)
    unexpectedError.value = t("common.errors.unexpected")
  } finally {
    progress.value -= 1
  }
}
</script>

<template>
  <form class="flex flex-col" novalidate @submit.prevent="onSubmit">
    <label for="email" class="mb-1"> {{ t("common.fields.email") }} </label>
    <InputText
      id="credentialaddemail-input-email"
      v-model="email"
      name="email"
      tabindex="0"
      class="min-w-0 flex-auto grow"
      :progress="progress"
      autocomplete="email"
      autocorrect="off"
      autocapitalize="none"
      spellcheck="false"
      type="email"
      minlength="3"
      required
    />
    <div v-if="unexpectedError" class="mt-4 text-error-600">{{ t("common.errors.unexpected") }}</div>
    <div v-else-if="emailError" class="mt-4 text-error-600">{{ getErrorMessage(emailError) }}</div>
    <div class="mt-4 flex flex-row justify-end gap-4">
      <Button type="submit" primary :disabled="!canSubmit()" :progress="progress">{{ t("common.buttons.add") }}</Button>
    </div>
  </form>
</template>
