<script setup lang="ts">
import type { AuthFlowPasskeyCreateCompleteRequest, AuthFlowResponse } from "@/types"

import { getCurrentInstance, inject, nextTick, onMounted, onBeforeUnmount, ref } from "vue"
import { useRouter } from "vue-router"
import { startRegistration, WebAuthnAbortService } from "@simplewebauthn/browser"
import Button from "@/components/Button.vue"
import { postURL } from "@/api"
import { processCompletedAndLocationRedirect } from "@/utils"
import { flowKey } from "@/flow"
import { injectProgress } from "@/progress"

const props = defineProps<{
  id: string
}>()

const router = useRouter()

const flow = inject(flowKey)
const progress = injectProgress()

const abortController = new AbortController()

const signupAttempted = ref(false)
const signupFailed = ref(false)
const signupFailedAtLeastOnce = ref(false)
const unexpectedError = ref("")

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

onBeforeUnmount(onBeforeLeave)

function onAfterEnter() {
  document.getElementById("passkey-signup")?.focus()
}

function onBeforeLeave() {
  abortController.abort()
}

async function onBack() {
  if (abortController.signal.aborted) {
    return
  }

  abortController.abort()
  WebAuthnAbortService.cancelCeremony()
  flow!.backward("passkeySignin")
}

async function onPasskeySignup() {
  if (abortController.signal.aborted) {
    return
  }

  progress.value += 1
  try {
    signupAttempted.value = true
    signupFailed.value = false
    unexpectedError.value = ""
    const startUrl = router.apiResolve({
      name: "AuthFlowPasskeyCreateStart",
      params: {
        id: props.id,
      },
    }).href
    const completeUrl = router.apiResolve({
      name: "AuthFlowPasskeyCreateComplete",
      params: {
        id: props.id,
      },
    }).href

    const start = await postURL<AuthFlowResponse>(startUrl, {}, abortController.signal, progress)
    if (abortController.signal.aborted) {
      return
    }
    if (processCompletedAndLocationRedirect(start, flow, progress, abortController)) {
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
      signupFailed.value = true
      signupFailedAtLeastOnce.value = true
      nextTick(() => {
        // We refocus button to retry.
        document.getElementById("passkey-signup")?.focus()
      })
      return
    }

    if (abortController.signal.aborted) {
      return
    }

    const complete = await postURL<AuthFlowResponse>(
      completeUrl,
      {
        createResponse: attestation,
      } as AuthFlowPasskeyCreateCompleteRequest,
      abortController.signal,
      progress,
    )
    if (abortController.signal.aborted) {
      return
    }
    if (processCompletedAndLocationRedirect(complete, flow, progress, abortController)) {
      return
    }
    throw new Error("unexpected response")
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("AuthPasskeySignup.onPasskeySignup", error)
    unexpectedError.value = `${error}`
    signupFailedAtLeastOnce.value = true
  } finally {
    progress.value -= 1
  }
}
</script>

<template>
  <div class="flex flex-col rounded border bg-white p-4 shadow w-full">
    <div v-if="signupAttempted && signupFailed">Signing up using <strong>passkey</strong> failed.</div>
    <div v-else-if="signupAttempted">Signing you up using <strong>passkey</strong>. Please follow instructions by your browser and/or device.</div>
    <div v-else>Signing in using <strong>passkey</strong> failed. Do you want to sign up instead?</div>
    <div v-if="unexpectedError" class="mt-4 text-error-600">Unexpected error. Please try again.</div>
    <div class="mt-4 flex flex-row justify-between gap-4">
      <Button type="button" tabindex="2" @click.prevent="onBack">Retry sign-in</Button>
      <Button id="passkey-signup" primary type="button" tabindex="1" :progress="progress" @click.prevent="onPasskeySignup">{{
        signupFailedAtLeastOnce ? "Retry sign-up" : "Passkey sign-up"
      }}</Button>
    </div>
  </div>
</template>
