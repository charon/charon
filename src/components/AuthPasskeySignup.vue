<script setup lang="ts">
import type { AuthFlowRequest, AuthFlowResponse } from "@/types"
import { getCurrentInstance, inject, onMounted, onUnmounted, ref } from "vue"
import { useRouter } from "vue-router"
import { startRegistration, WebAuthnAbortService } from "@simplewebauthn/browser"
import Button from "@/components/Button.vue"
import { postURL } from "@/api"
import { flowKey, locationRedirect } from "@/utils"

const props = defineProps<{
  id: string
}>()

const router = useRouter()

const flow = inject(flowKey)

const mainProgress = ref(0)
let abortController = new AbortController()
const signupProgress = ref(0)
const signupAttempted = ref(false)
const signupFailed = ref(false)
const signupFailedAtLeastOnce = ref(false)

// Define transition hooks to be called by the parent component.
// See: https://github.com/vuejs/rfcs/discussions/613
onMounted(() => {
  const vm = getCurrentInstance()!
  vm.vnode.el!.__vue_exposed = vm.exposeProxy
})

defineExpose({
  onBeforeLeave,
})

onUnmounted(onBeforeLeave)

function onBeforeLeave() {
  abortController.abort()
}

async function onBack() {
  if (abortController.signal.aborted) {
    return
  }

  abortController.abort()
  WebAuthnAbortService.cancelCeremony()
  flow!.backward("start")
}

async function onRetry() {
  if (abortController.signal.aborted) {
    return
  }

  abortController.abort()
  WebAuthnAbortService.cancelCeremony()
  flow!.backward("passkeySignin")
}

// TODO: Better handle unexpected errors. (E.g., createComplete failing.)
async function onPasskeySignup() {
  if (abortController.signal.aborted) {
    return
  }

  signupProgress.value += 1
  try {
    signupAttempted.value = true
    signupFailed.value = false
    abortController = new AbortController()
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
        step: "createStart",
      } as AuthFlowRequest,
      abortController.signal,
      signupProgress,
    )) as AuthFlowResponse
    if (abortController.signal.aborted) {
      return
    }
    if (locationRedirect(start, flow)) {
      // We increase the progress and never decrease it to wait for browser to do the redirect.
      mainProgress.value += 1
      return
    }
    if (!("passkey" in start && "createOptions" in start.passkey)) {
      throw new Error("unexpected response")
    }

    let attestation
    try {
      attestation = await startRegistration(start.passkey.createOptions.publicKey)
    } catch (error) {
      if (abortController.signal.aborted) {
        return
      }
      abortController.abort()
      signupFailed.value = true
      signupFailedAtLeastOnce.value = true
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
          step: "createComplete",
          passkey: {
            createResponse: attestation,
          },
        } as AuthFlowRequest,
        abortController.signal,
        mainProgress,
      )) as AuthFlowResponse
      if (abortController.signal.aborted) {
        return
      }
      if (locationRedirect(complete, flow)) {
        // We increase the progress and never decrease it to wait for browser to do the redirect.
        mainProgress.value += 1
        return
      }
      throw new Error("unexpected response")
    } finally {
      mainProgress.value -= 1
    }
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    throw error
  } finally {
    signupProgress.value -= 1
  }
}
</script>

<template>
  <div class="flex flex-col rounded border bg-white p-4 shadow w-full float-left first:ml-0 ml-[-100%]">
    <h2 class="text-center mx-4 mb-4 text-xl font-bold uppercase">Sign-in or sign-up</h2>
    <div v-if="signupAttempted && signupFailed">Signing up using <strong>passkey</strong> failed.</div>
    <div v-else-if="signupAttempted">Signing you up using <strong>passkey</strong>. Please follow instructions by your browser and/or device.</div>
    <div v-else>Signing in using <strong>passkey</strong> failed. Do you want to sign up instead?</div>
    <div class="mt-4 flex flex-row justify-between gap-4">
      <div class="flex flex-row gap-4">
        <Button type="button" :disabled="mainProgress > 0" @click.prevent="onBack">Back</Button>
        <Button primary type="button" :disabled="mainProgress > 0" @click.prevent="onRetry">Retry sign-in</Button>
      </div>
      <Button primary type="button" :disabled="mainProgress + signupProgress > 0" @click.prevent="onPasskeySignup">{{
        signupFailedAtLeastOnce ? "Retry sign-up" : "Passkey sign-up"
      }}</Button>
    </div>
  </div>
</template>
