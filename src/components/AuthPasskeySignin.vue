<script setup lang="ts">
import type { AuthFlowRequest, AuthFlowResponse } from "@/types"
import { onMounted, ref } from "vue"
import { useRouter } from "vue-router"
import { startAuthentication, WebAuthnAbortService } from "@simplewebauthn/browser"
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

let aborted = false

async function onBack() {
  aborted = true
  WebAuthnAbortService.cancelCeremony()
  emit("update:modelValue", "start")
}

async function onCancel() {
  aborted = true
  WebAuthnAbortService.cancelCeremony()
  emit("update:modelValue", "passkeySignup")
}

// TODO: Better handle unexpected errors. (E.g., getComplete failing.)
onMounted(async () => {
  aborted = false
  const url = router.apiResolve({
    name: "AuthFlow",
    params: {
      id: props.id,
    },
  }).href

  const start = (await postURL(
    url,
    {
      provider: "passkey",
      step: "getStart",
    } as AuthFlowRequest,
    // We do not pass here progress on purpose.
    null,
  )) as AuthFlowResponse
  if (aborted) {
    return
  }
  if (locationRedirect(start)) {
    // We increase the progress and never decrease it to wait for browser to do the redirect.
    progress.value += 1
    return
  }
  if (!("passkey" in start && "getOptions" in start.passkey)) {
    throw new Error("unexpected response")
  }

  let assertion
  try {
    assertion = await startAuthentication(start.passkey.getOptions.publicKey)
  } catch (error) {
    if (aborted) {
      return
    }
    aborted = true
    emit("update:modelValue", "passkeySignup")
    return
  }

  // We do not allow back or cancel after this point.
  progress.value += 1
  try {
    const complete = (await postURL(
      url,
      {
        provider: "passkey",
        step: "getComplete",
        passkey: {
          getResponse: assertion,
        },
      } as AuthFlowRequest,
      progress,
    )) as AuthFlowResponse
    if (locationRedirect(complete)) {
      // We increase the progress and never decrease it to wait for browser to do the redirect.
      progress.value += 1
      return
    }
    throw new Error("unexpected response")
  } finally {
    progress.value -= 1
  }
})
</script>

<template>
  <div>Signing you in using <strong>passkey</strong>. Please follow instructions by your browser and/or device.</div>
  <div class="mt-4">If you have not yet signed up with passkey, this will fail. In that case Charon will offer you to sign up instead.</div>
  <div class="mt-4 flex flex-row justify-between gap-4">
    <Button type="button" :disabled="progress > 0" @click.prevent="onBack">Back</Button>
    <Button type="button" :disabled="progress > 0" @click.prevent="onCancel">Cancel</Button>
  </div>
</template>
