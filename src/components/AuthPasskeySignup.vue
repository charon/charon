<script setup lang="ts">
import type { AuthFlowResponse } from "@/types"
import { ref } from "vue"
import { useRouter } from "vue-router"
import { startRegistration } from "@simplewebauthn/browser"
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

async function onBack() {
  emit("update:modelValue", "start")
}

async function onRetry() {
  emit("update:modelValue", "passkeySignin")
}

async function onPasskeySignup() {
  const progress = ref(0)
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
    progress,
  )
  if (locationRedirect(router, start)) {
    return
  }
  if (!start.passkey?.createOptions) {
    // TODO: Handle better?
    return
  }

  // TODO: Handle error?
  const attestation = await startRegistration(start.passkey.createOptions.publicKey)

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
  locationRedirect(router, complete)
}
</script>

<template>
  <div>Signing in using <strong>passkey</strong> failed. Do you want to sign up instead?</div>
  <div class="mt-4 flex flex-row justify-between gap-4">
    <div class="flex flex-row gap-4">
      <Button type="button" @click.prevent="onBack">Back</Button>
      <Button type="button" @click.prevent="onRetry">Retry sign-in</Button>
    </div>
    <Button type="button" @click.prevent="onPasskeySignup">Passkey sign-up</Button>
  </div>
</template>
