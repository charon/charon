<script setup lang="ts">
import {
  CredentialAddPasswordCompleteRequest, CredentialAddResponse, DeriveOptions,
  EncryptedPasswordData, EncryptOptions
} from "@/types"

import { onBeforeUnmount, onMounted, ref, watch } from "vue"
import { useI18n } from "vue-i18n"
import { Router, useRouter } from "vue-router"

import { postJSON } from "@/api.ts"
import Button from "@/components/Button.vue"
import InputText from "@/components/InputText.vue"
import { injectProgress } from "@/progress.ts"
import {encryptPasswordECDHAESGCM} from "@/utils.ts";

const { t } = useI18n({ useScope: "global" })
const router = useRouter()
const progress = injectProgress()

const abortController = new AbortController()
const password = ref("")
const passwordLabel = ref("")
const passwordError = ref("")
const unexpectedError = ref("")

async function startAddPasswordCredential(router: Router, abortController: AbortController): Promise<CredentialAddResponse> {
  const url = router.apiResolve({ name: "CredentialAddPasswordStart" }).href
  return await postJSON<CredentialAddResponse>(url, {}, abortController.signal, progress)
}

async function completeAddPasswordCredential(
  router: Router,
  request: CredentialAddPasswordCompleteRequest,
  abortController: AbortController,
): Promise<CredentialAddResponse> {
  const url = router.apiResolve({ name: "CredentialAddPasswordComplete" }).href
  return await postJSON<CredentialAddResponse>(url, request as CredentialAddPasswordCompleteRequest, abortController.signal, progress)
}

function getErrorMessage(errorCode: string) {
  switch (errorCode) {
    case "shortPassword":
      return t("common.errors.shortPassword")
    default:
      return t("common.errors.unexpected")
  }
}

function resetOnInteraction() {
  // We reset the error on interaction.
  passwordError.value = ""
  unexpectedError.value = ""
}

watch([password, passwordLabel], resetOnInteraction)

onBeforeUnmount(() => {
  abortController.abort()
})

onMounted(() => {
  document.getElementById("credentialaddpassword-input-password")?.focus()
})

function canSubmit(): boolean {
  return password.value.trim().length > 0 && passwordLabel.value.trim().length > 0
}

async function onSubmit() {
  if (abortController.signal.aborted) {
    return
  }

  resetOnInteraction()

  progress.value += 1
  try {
    const startResponse = await startAddPasswordCredential(router, abortController)
    if (abortController.signal.aborted || !startResponse) {
      return
    }
    if (!startResponse.password) {
      throw new Error("missing password parameters")
    }

    const publicKey = Uint8Array.from(atob(startResponse.password?.publicKey), (c) => c.charCodeAt(0))
    const deriveOptions = startResponse.password?.deriveOptions
    const encryptOptions: EncryptOptions = {
      name: startResponse.password.encryptOptions.name,
      iv: Uint8Array.from(atob(startResponse.password.encryptOptions.iv), (c) => c.charCodeAt(0)),
      tagLength: startResponse.password.encryptOptions.tagLength,
      length: startResponse.password.encryptOptions.length,
    }

    if (!publicKey || !deriveOptions || !encryptOptions) {
      // This should not happen.
      throw new Error("missing public key or options")
    }

    const encrypted = await encryptPasswordECDHAESGCM(password.value, publicKey, deriveOptions, encryptOptions, abortController)

    const result = await completeAddPasswordCredential(
      router,
      {
        sessionId: startResponse.sessionId,
        publicKey: Array.from(new Uint8Array(encrypted.publicKeyBytes)),
        password: Array.from(new Uint8Array(encrypted.ciphertext)),
        label: passwordLabel.value,
      } as CredentialAddPasswordCompleteRequest,
      abortController,
    )

    if (abortController.signal.aborted) {
      return
    }

    if (result.error) {
      passwordError.value = result.error
      return
    }

    router.push({ name: "CredentialList" })
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("CredentialAddPassword.onSubmit", error)
    unexpectedError.value = t("common.errors.unexpected")
  } finally {
    progress.value -= 1
  }
}
</script>

<template>
  <form class="flex flex-col" novalidate @submit.prevent="onSubmit">
    <label for="password" class="mb-1">{{ t("common.providers.passwordTitle") }}</label>
    <InputText
      id="credentialaddpassword-input-password"
      v-model="password"
      name="password"
      type="password"
      minlength="8"
      tabindex="0"
      :invalid="!!unexpectedError"
      class="min-w-0 flex-auto grow"
      :progress="progress"
      autocomplete="password"
      autocorrect="off"
      autocapitalize="none"
      spellcheck="false"
      required
    />
    <label for="password-label" class="mt-4 mb-1"> {{ t("partials.CredentialAddPassword.label") }}</label>
    <InputText
      id="credentialaddpassword-input-passwordlabel"
      v-model="passwordLabel"
      name="password-label"
      tabindex="0"
      class="mt-2 flex flex-row gap-4"
      :progress="progress"
      autocomplete="label"
      required
    />
    <div v-if="unexpectedError" class="mt-4 text-error-600">{{ unexpectedError }}</div>
    <div v-else-if="passwordError" class="mt-4 text-error-600">{{ getErrorMessage(passwordError) }}</div>
    <div class="mt-4 flex flex-row justify-end gap-4">
      <Button type="submit" primary :disabled="!canSubmit()" :progress="progress">{{ t("common.buttons.add") }}</Button>
    </div>
  </form>
</template>
