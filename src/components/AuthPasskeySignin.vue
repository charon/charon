<script setup lang="ts">
import type { AuthFlowRequest, AuthFlowResponse } from "@/types"
import { getCurrentInstance, onMounted, onUnmounted, ref } from "vue"
import { useRouter } from "vue-router"
import { startAuthentication, WebAuthnAbortService } from "@simplewebauthn/browser"
import Button from "@/components/Button.vue"
import { postURL } from "@/api"
import { locationRedirect } from "@/utils"

const props = defineProps<{
  state: string
  direction: "forward" | "backward"
  id: string
}>()

const emit = defineEmits<{
  "update:state": [value: string]
  "update:direction": [value: "forward" | "backward"]
}>()

const router = useRouter()

const mainProgress = ref(0)
const abortController = new AbortController()

// Define transition hooks to be called by the parent component.
// See: https://github.com/vuejs/rfcs/discussions/613
onMounted(() => {
  const vm = getCurrentInstance()!
  vm.vnode.el!.__vue_exposed = vm.exposeProxy
})

defineExpose({
  onAfterEnter,
  onBeforeLeave,
})

onUnmounted(onBeforeLeave)

function onBeforeLeave() {
  abortController.abort()
  WebAuthnAbortService.cancelCeremony()
}

// TODO: Better handle unexpected errors. (E.g., getComplete failing.)
async function onAfterEnter() {
  const url = router.apiResolve({
    name: "AuthFlow",
    params: {
      id: props.id,
    },
  }).href

  let start
  try {
    start = (await postURL(
      url,
      {
        provider: "passkey",
        step: "getStart",
      } as AuthFlowRequest,
      abortController.signal,
      // We do not pass here progress on purpose.
      null,
    )) as AuthFlowResponse
    if (abortController.signal.aborted) {
      return
    }
    if (locationRedirect(start)) {
      // We increase the progress and never decrease it to wait for browser to do the redirect.
      mainProgress.value += 1
      return
    }
    if (!("passkey" in start && "getOptions" in start.passkey)) {
      throw new Error("unexpected response")
    }
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    throw error
  }

  let assertion
  try {
    assertion = await startAuthentication(start.passkey.getOptions.publicKey)
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    abortController.abort()
    emit("update:direction", "forward")
    emit("update:state", "passkeySignup")
    return
  }

  if (abortController.signal.aborted) {
    return
  }

  // We do not allow back or cancel after this point.
  mainProgress.value += 1
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
      abortController.signal,
      mainProgress,
    )) as AuthFlowResponse
    if (abortController.signal.aborted) {
      return
    }
    if (locationRedirect(complete)) {
      // We increase the progress and never decrease it to wait for browser to do the redirect.
      mainProgress.value += 1
      return
    }
    throw new Error("unexpected response")
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    throw error
  } finally {
    mainProgress.value -= 1
  }
}

async function onBack() {
  if (abortController.signal.aborted) {
    return
  }

  abortController.abort()
  WebAuthnAbortService.cancelCeremony()
  emit("update:direction", "backward")
  emit("update:state", "start")
}

async function onCancel() {
  if (abortController.signal.aborted) {
    return
  }

  abortController.abort()
  WebAuthnAbortService.cancelCeremony()
  emit("update:direction", "forward")
  emit("update:state", "passkeySignup")
}
</script>

<template>
  <div class="flex flex-col rounded border bg-white p-4 shadow w-full float-left first:ml-0 ml-[-100%]">
    <h2 class="text-center mx-4 mb-4 text-xl font-bold uppercase">Sign-in or sign-up</h2>
    <div>Signing you in using <strong>passkey</strong>. Please follow instructions by your browser and/or device.</div>
    <div class="mt-4">If you have not yet signed up with passkey, this will fail. In that case Charon will offer you to sign up instead.</div>
    <div class="mt-4 flex flex-row justify-between gap-4">
      <Button type="button" :disabled="mainProgress > 0" @click.prevent="onBack">Back</Button>
      <Button type="button" :disabled="mainProgress > 0" @click.prevent="onCancel">Cancel</Button>
    </div>
  </div>
</template>
