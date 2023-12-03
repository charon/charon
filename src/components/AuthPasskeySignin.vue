<script setup lang="ts">
import type { AuthFlowResponse } from "@/types"
import { onMounted, ref } from "vue"
import { useRouter } from "vue-router"
import { startAuthentication } from "@simplewebauthn/browser"
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

async function onCancel() {
  emit("update:modelValue", "passkeySignup")
}

onMounted(async () => {
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
      step: "getStart",
      provider: "passkey",
    },
    progress,
  )
  if (locationRedirect(start)) {
    return
  }
  if (!start.passkey?.getOptions) {
    // TODO: Handle better?
    return
  }

  // TODO: Handle error?
  const assertion = await startAuthentication(start.passkey.getOptions.publicKey)

  const complete: AuthFlowResponse = await postURL(
    url,
    {
      step: "getComplete",
      provider: "passkey",
      passkey: {
        getResponse: assertion,
      },
    },
    progress,
  )
  locationRedirect(complete)
})
</script>

<template>
  <div>Signing you in using <strong>passkey</strong>. Please follow instructions by your browser and/or device.</div>
  <div class="mt-4">If you have not yet signed up with passkey, this will fail. In that case Charon will offer you to sign up instead.</div>
  <div class="mt-4 flex flex-row justify-between gap-4">
    <Button type="button" @click.prevent="onBack">Back</Button>
    <Button type="button" @click.prevent="onCancel">Cancel</Button>
  </div>
</template>
