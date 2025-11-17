<script setup lang="ts">
import { CredentialAddCredentialWithLabelStartRequest, CredentialAddPasskeyCompleteRequest, CredentialAddResponse } from "@/types"

import { onBeforeUnmount, onMounted, ref, watch } from "vue"
import { useI18n } from "vue-i18n"
import { Router, useRouter } from "vue-router"

import { postJSON } from "@/api.ts"
import Button from "@/components/Button.vue"
import InputText from "@/components/InputText.vue"
import { injectProgress } from "@/progress.ts"
import { browserSupportsWebAuthn, startRegistration } from "@simplewebauthn/browser"

const { t } = useI18n({ useScope: "global" })
const router = useRouter()
const progress = injectProgress()

const abortController = new AbortController()
const passkeyLabel = ref("")
const passkeyError = ref("")
const unexpectedError = ref("")

if (!browserSupportsWebAuthn()) {
  throw new Error("webauthn is required for this partial")
}

function getErrorMessage(errorCode: string | undefined) {
  switch (errorCode) {
    case "credentialLabelInUse":
      return t("common.errors.credentialLabelInUse")
    case "credentialLabelMissing":
      return t("common.errors.credentialLabelMissing")
    default:
      return t("common.errors.unexpected")
  }
}

async function startAddPasskeyCredential(router: Router, label: string, abortController: AbortController): Promise<CredentialAddResponse> {
  const url = router.apiResolve({ name: "CredentialAddPasskeyStart" }).href
  return await postJSON<CredentialAddResponse>(url, { label: label } as CredentialAddCredentialWithLabelStartRequest, abortController.signal, progress)
}

async function completeAddPasskeyCredential(
  router: Router,
  request: CredentialAddPasskeyCompleteRequest,
  abortController: AbortController,
): Promise<CredentialAddResponse> {
  const url = router.apiResolve({ name: "CredentialAddPasskeyComplete" }).href
  return await postJSON<CredentialAddResponse>(url, request as CredentialAddPasskeyCompleteRequest, abortController.signal, progress)
}

function resetOnInteraction() {
  // We reset the error on interaction.
  passkeyError.value = ""
  unexpectedError.value = ""
}

watch([passkeyLabel], resetOnInteraction)

onBeforeUnmount(() => {
  abortController.abort()
})

onMounted(() => {
  document.getElementById("credentialaddpasskey-input-label")?.focus()
})

function canSubmit(): boolean {
  return passkeyLabel.value.trim().length > 0
}

async function onSubmit() {
  if (abortController.signal.aborted) {
    return
  }

  resetOnInteraction()

  progress.value += 1
  try {
    const startResponse = await startAddPasskeyCredential(router, passkeyLabel.value.trim(), abortController)
    if (abortController.signal.aborted || !startResponse) {
      return
    }

    if (startResponse.error) {
      passkeyError.value = startResponse.error
      return
    }

    if (!startResponse.passkey) {
      throw new Error("missing passkey parameters")
    }

    const regResponse = await startRegistration({ optionsJSON: startResponse.passkey.createOptions.publicKey })
    if (abortController.signal.aborted) {
      return
    }

    const result = await completeAddPasskeyCredential(
      router,
      {
        sessionId: startResponse.sessionId,
        createResponse: regResponse,
      } as CredentialAddPasskeyCompleteRequest,
      abortController,
    )

    if (abortController.signal.aborted) {
      return
    }

    if (result.error) {
      passkeyError.value = result.error
      return
    }

    router.push({ name: "CredentialList" })
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("CredentialAddPasskey.onSubmit", error)
    unexpectedError.value = t("common.errors.unexpected")
  } finally {
    progress.value -= 1
  }
}
</script>

<template>
  <form class="flex flex-col" novalidate @submit.prevent="onSubmit">
    <label for="credentialaddpasskey-input-label" class="mb-1"> {{ t("partials.CredentialAddPasskey.label") }}</label>
    <InputText
      id="credentialaddpasskey-input-label"
      v-model="passkeyLabel"
      name="passkey-label"
      class="min-w-0 flex-auto grow"
      :progress="progress"
      autocomplete="off"
      required
    />
    <p class="mt-2 text-sm text-slate-600">{{ t("partials.CredentialAddPasskey.passkeyInstructions") }}</p>
    <div v-if="unexpectedError" class="mt-4 text-error-600">{{ unexpectedError }}</div>
    <div v-else-if="passkeyError" class="mt-4 text-error-600">{{ getErrorMessage(passkeyError) }}</div>
    <div class="mt-4 flex flex-row justify-end gap-4">
      <Button type="submit" primary :disabled="!canSubmit()" :progress="progress">{{ t("common.buttons.add") }}</Button>
    </div>
  </form>
</template>
