<script setup lang="ts">
import { CredentialAddCredentialStartRequest, CredentialAddPasskeyCompleteRequest, CredentialAddResponse } from "@/types"

import { onBeforeUnmount, onMounted, ref, watch } from "vue"
import { useI18n } from "vue-i18n"
import { useRouter } from "vue-router"

import { postJSON } from "@/api.ts"
import Button from "@/components/Button.vue"
import InputText from "@/components/InputText.vue"
import { useProgress } from "@/progress.ts"
import { browserSupportsWebAuthn, startRegistration } from "@simplewebauthn/browser"

const { t } = useI18n({ useScope: "global" })
const router = useRouter()
const progress = useProgress()

const abortController = new AbortController()
const passkeyDisplayName = ref("")
const passkeyError = ref("")
const unexpectedError = ref("")

if (!browserSupportsWebAuthn()) {
  throw new Error("webauthn is required for this partial")
}

function getErrorMessage(errorCode: string) {
  switch (errorCode) {
    case "credentialDisplayNameInUse":
      return t("common.errors.credentialDisplayNameInUse")
    default:
      throw new Error(`unexpected error code: ${errorCode}`)
  }
}

async function startAddPasskeyCredential(request: CredentialAddCredentialStartRequest): Promise<CredentialAddResponse> {
  const url = router.apiResolve({ name: "CredentialAddPasskeyStart" }).href
  return await postJSON<CredentialAddResponse>(url, request, abortController.signal, progress)
}

async function completeAddPasskeyCredential(request: CredentialAddPasskeyCompleteRequest): Promise<CredentialAddResponse> {
  const url = router.apiResolve({ name: "CredentialAddPasskeyComplete" }).href
  return await postJSON<CredentialAddResponse>(url, request, abortController.signal, progress)
}

function resetOnInteraction() {
  // We reset the error on interaction.
  passkeyError.value = ""
  unexpectedError.value = ""
}

watch([passkeyDisplayName], resetOnInteraction)

onBeforeUnmount(() => {
  abortController.abort()
})

onMounted(() => {
  document.getElementById("credentialaddpasskey-input-label")?.focus()
})

function canSubmit(): boolean {
  // Required fields.
  return !!passkeyDisplayName.value
}

async function onSubmit() {
  if (abortController.signal.aborted) {
    return
  }

  resetOnInteraction()

  progress.value += 1
  try {
    const startResponse = await startAddPasskeyCredential({
      displayName: passkeyDisplayName.value,
    })
    if (abortController.signal.aborted) {
      return
    }
    if ("error" in startResponse) {
      // We check if it is an expected error code by trying to get the error message.
      getErrorMessage(startResponse.error)
      passkeyError.value = startResponse.error
      return
    }
    if (!("passkey" in startResponse && "createOptions" in startResponse.passkey)) {
      throw new Error("unexpected response")
    }

    const regResponse = await startRegistration({ optionsJSON: startResponse.passkey.createOptions.publicKey })
    if (abortController.signal.aborted) {
      return
    }

    const completeResponse = await completeAddPasskeyCredential({
      sessionId: startResponse.sessionId,
      createResponse: regResponse,
    })
    if (abortController.signal.aborted) {
      return
    }
    if ("error" in completeResponse) {
      // We check if it is an expected error code by trying to get the error message.
      getErrorMessage(completeResponse.error)
      passkeyError.value = completeResponse.error
      return
    }

    await router.push({ name: "CredentialList" })
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("CredentialAddPasskey.onSubmit", error)
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
    <label for="credentialaddpasskey-input-label" class="mb-1"> {{ t("partials.CredentialAddPasskey.displayName") }}</label>
    <InputText id="credentialaddpasskey-input-label" v-model="passkeyDisplayName" class="min-w-0 flex-auto grow" :progress="progress" required />
    <div class="mt-4">{{ t("partials.CredentialAddPasskey.passkeyInstructions") }}</div>
    <div v-if="passkeyError" class="mt-4 text-error-600">{{ getErrorMessage(passkeyError) }}</div>
    <div v-else-if="unexpectedError" class="mt-4 text-error-600">{{ t("common.errors.unexpected") }}</div>
    <div class="mt-4 flex flex-row justify-end">
      <Button type="submit" primary :disabled="!canSubmit()" :progress="progress">{{ t("common.buttons.add") }}</Button>
    </div>
  </form>
</template>
