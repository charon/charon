<script setup lang="ts">
import { CredentialAddCredentialWithLabelStartRequest, CredentialAddPasswordCompleteRequest, CredentialAddResponse, EncryptOptions } from "@/types"

import { onBeforeUnmount, onMounted, ref, watch } from "vue"
import { useI18n } from "vue-i18n"
import { useRouter } from "vue-router"

import { postJSON } from "@/api.ts"
import Button from "@/components/Button.vue"
import InputText from "@/components/InputText.vue"
import { injectProgress } from "@/progress.ts"
import { encryptPasswordECDHAESGCM } from "@/utils.ts"

const { t } = useI18n({ useScope: "global" })
const router = useRouter()
const progress = injectProgress()

const abortController = new AbortController()
const password = ref("")
const passwordLabel = ref("")
const passwordError = ref("")
const unexpectedError = ref("")

function getErrorMessage(errorCode: string) {
  switch (errorCode) {
    case "shortPassword":
      return t("common.errors.shortPassword")
    case "invalidPassword":
      return t("common.errors.invalidPassword")
    case "alreadyPresent":
      return t("common.errors.alreadyPresent.password")
    case "credentialLabelInUse":
      return t("common.errors.credentialLabelInUse.password")
    case "credentialLabelMissing":
      return t("common.errors.credentialLabelMissing.password")
    default:
      throw new Error(`unexpected error code: ${errorCode}`)
  }
}

async function startAddPasswordCredential(request: CredentialAddCredentialWithLabelStartRequest): Promise<CredentialAddResponse> {
  const url = router.apiResolve({ name: "CredentialAddPasswordStart" }).href
  return await postJSON<CredentialAddResponse>(url, request, abortController.signal, progress)
}

async function completeAddPasswordCredential(request: CredentialAddPasswordCompleteRequest): Promise<CredentialAddResponse> {
  const url = router.apiResolve({ name: "CredentialAddPasswordComplete" }).href
  return await postJSON<CredentialAddResponse>(url, request, abortController.signal, progress)
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
  // Required fields.
  return !!password.value && !!passwordLabel.value
}

async function onSubmit() {
  if (abortController.signal.aborted) {
    return
  }

  resetOnInteraction()

  progress.value += 1
  try {
    const startResponse = await startAddPasswordCredential({
      label: passwordLabel.value,
    })
    if (abortController.signal.aborted) {
      return
    }
    if (startResponse.error) {
      // We check if it is an expected error code by trying to get the error message.
      getErrorMessage(startResponse.error)
      passwordError.value = startResponse.error
      return
    }
    if (!startResponse.password) {
      throw new Error("unexpected response")
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

    const completeResponse = await completeAddPasswordCredential({
      sessionId: startResponse.sessionId,
      publicKey: Array.from(new Uint8Array(encrypted.publicKeyBytes)),
      password: Array.from(new Uint8Array(encrypted.ciphertext)),
    })
    if (abortController.signal.aborted) {
      return
    }
    if (completeResponse.error) {
      // We check if it is an expected error code by trying to get the error message.
      getErrorMessage(completeResponse.error)
      passwordError.value = completeResponse.error
      return
    }

    await router.push({ name: "CredentialList" })
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("CredentialAddPassword.onSubmit", error)
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
    <label for="credentialaddpassword-input-password" class="mb-1">{{ t("partials.CredentialAddPassword.passwordLabel") }}</label>
    <InputText
      id="credentialaddpassword-input-password"
      v-model="password"
      type="password"
      minlength="8"
      :invalid="!!passwordError"
      class="min-w-0 flex-auto grow"
      :progress="progress"
      autocomplete="off"
      autocorrect="off"
      autocapitalize="none"
      spellcheck="false"
      required
    />
    <label for="credentialaddpassword-input-label" class="mt-4 mb-1"> {{ t("partials.CredentialAddPassword.label") }}</label>
    <InputText id="credentialaddpassword-input-label" v-model="passwordLabel" class="min-w-0 flex-auto grow" :progress="progress" required />
    <div v-if="passwordError" class="mt-4 text-error-600">{{ getErrorMessage(passwordError) }}</div>
    <div v-else-if="unexpectedError" class="mt-4 text-error-600">{{ t("common.errors.unexpected") }}</div>
    <div class="mt-4 flex flex-row justify-end">
      <Button type="submit" primary :disabled="!canSubmit()" :progress="progress">{{ t("common.buttons.add") }}</Button>
    </div>
  </form>
</template>
