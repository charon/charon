<script setup lang="ts">
import type { AuthFlowResponse } from "@/types"
import { ref } from "vue"
import { useRouter } from "vue-router"
import { startRegistration, WebAuthnAbortService } from "@simplewebauthn/browser"
import Button from "@/components/Button.vue"
import { postURL } from "@/api"
import { locationRedirect } from "@/utils"

const props = defineProps<{
  modelValue: string
  id: string
}>()

const emit = defineEmits<{
  "update:modelValue": [value: string]
}>()

const router = useRouter()

const progress = ref(0)
const signupProgress = ref(0)
const signupAttempted = ref(false)
const signupFailed = ref(false)
const signupFailedAtLeastOnce = ref(false)

let aborted = false

async function onBack() {
  aborted = true
  WebAuthnAbortService.cancelCeremony()
  emit("update:modelValue", "start")
}

async function onRetry() {
  aborted = true
  WebAuthnAbortService.cancelCeremony()
  emit("update:modelValue", "passkeySignin")
}

// TODO: Better handle unexpected errors. (E.g., createComplete failing.)
async function onPasskeySignup() {
  signupProgress.value += 1
  try {
    signupAttempted.value = true
    signupFailed.value = false
    aborted = false
    const url = router.apiResolve({
      name: "AuthFlow",
      params: {
        id: props.id,
      },
    }).href

    const start: AuthFlowResponse = await postURL(
      url,
      {
        step: "createStart",
        provider: "passkey",
      },
      signupProgress,
    )
    if (aborted) {
      return
    }
    if (locationRedirect(start)) {
      // We increase the progress and never decrease it to wait for browser to do the redirect.
      progress.value += 1
      return
    }
    if (!start.passkey?.createOptions) {
      throw new Error("Webauthn options missing in response.")
    }

    let attestation
    try {
      attestation = await startRegistration(start.passkey.createOptions.publicKey)
    } catch (error) {
      if (aborted) {
        return
      }
      aborted = true
      signupFailed.value = true
      signupFailedAtLeastOnce.value = true
      return
    }

    // We do not allow back or cancel after this point.
    progress.value += 1
    try {
      const complete: AuthFlowResponse = await postURL(
        url,
        {
          step: "createComplete",
          provider: "passkey",
          passkey: {
            createResponse: attestation,
          },
        },
        progress,
      )
      if (locationRedirect(complete)) {
        // We increase the progress and never decrease it to wait for browser to do the redirect.
        progress.value += 1
      } else {
        throw new Error("unexpected response")
      }
    } finally {
      progress.value -= 1
    }
  } finally {
    signupProgress.value -= 1
  }
}
</script>

<template>
  <div v-if="signupAttempted && signupFailed">Signing up using <strong>passkey</strong> failed.</div>
  <div v-else-if="signupAttempted">Signing you up using <strong>passkey</strong>. Please follow instructions by your browser and/or device.</div>
  <div v-else>Signing in using <strong>passkey</strong> failed. Do you want to sign up instead?</div>
  <div class="mt-4 flex flex-row justify-between gap-4">
    <div class="flex flex-row gap-4">
      <Button type="button" :disabled="progress > 0" @click.prevent="onBack">Back</Button>
      <Button type="button" :disabled="progress > 0" @click.prevent="onRetry">Retry sign-in</Button>
    </div>
    <Button type="button" :disabled="progress + signupProgress > 0" @click.prevent="onPasskeySignup">{{
      signupFailedAtLeastOnce ? "Retry sign-up" : "Passkey sign-up"
    }}</Button>
  </div>
</template>
