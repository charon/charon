<script setup lang="ts">
import type { AuthFlowPasskeyGetCompleteRequest, AuthFlowResponse } from "@/types"

import { getCurrentInstance, inject, onMounted, onBeforeUnmount, ref } from "vue"
import { useRouter } from "vue-router"
import { startAuthentication, WebAuthnAbortService } from "@simplewebauthn/browser"
import Button from "@/components/Button.vue"
import { postJSON } from "@/api"
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

function onBeforeLeave() {
  abortController.abort()
  WebAuthnAbortService.cancelCeremony()
}

async function onAfterEnter() {
  try {
    const startUrl = router.apiResolve({
      name: "AuthFlowPasskeyGetStart",
      params: {
        id: props.id,
      },
    }).href
    const completeUrl = router.apiResolve({
      name: "AuthFlowPasskeyGetComplete",
      params: {
        id: props.id,
      },
    }).href

    const start = await postJSON<AuthFlowResponse>(
      startUrl,
      {},
      abortController.signal,
      // We do not pass here progress on purpose because we start this automatically
      // and we user to be able to interact with buttons (e.g., cancel).
      null,
    )
    if (abortController.signal.aborted) {
      return
    }
    if (processCompletedAndLocationRedirect(start, flow, progress, abortController)) {
      return
    }
    if (!("passkey" in start && "getOptions" in start.passkey)) {
      throw new Error("unexpected response")
    }

    let assertion
    try {
      assertion = await startAuthentication(start.passkey.getOptions.publicKey)
    } catch (error) {
      if (abortController.signal.aborted) {
        return
      }
      flow!.forward("passkeySignup")
      return
    }

    if (abortController.signal.aborted) {
      return
    }

    // We do not allow cancel after this point.
    progress.value += 1
    try {
      const complete = await postJSON<AuthFlowResponse>(
        completeUrl,
        {
          getResponse: assertion,
        } as AuthFlowPasskeyGetCompleteRequest,
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
    } finally {
      progress.value -= 1
    }
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("AuthPasskeySignin.onAfterEnter", error)
    unexpectedError.value = `${error}`
  }
}

async function onRetry() {
  if (abortController.signal.aborted) {
    return
  }

  unexpectedError.value = ""
  await onAfterEnter()
}

async function onBack() {
  if (abortController.signal.aborted) {
    return
  }

  abortController.abort()
  WebAuthnAbortService.cancelCeremony()
  flow!.backward("start")
}

async function onCancel() {
  if (abortController.signal.aborted) {
    return
  }

  abortController.abort()
  WebAuthnAbortService.cancelCeremony()
  flow!.forward("passkeySignup")
}
</script>

<template>
  <div class="flex flex-col rounded border bg-white p-4 shadow w-full">
    <div>Signing you in using <strong>passkey</strong>. Please follow instructions by your browser and/or device.</div>
    <div class="mt-4">If you have not yet signed up with passkey, this will fail. In that case Charon will offer you to sign up instead.</div>
    <div v-if="unexpectedError" class="mt-4 text-error-600">Unexpected error. Please try again.</div>
    <div class="mt-4 flex flex-row justify-between gap-4">
      <Button type="button" tabindex="2" @click.prevent="onBack">Back</Button>
      <Button v-if="unexpectedError" primary type="button" tabindex="1" @click.prevent="onRetry">Retry</Button>
      <Button v-else type="button" tabindex="1" :progress="progress" @click.prevent="onCancel">Cancel</Button>
    </div>
  </div>
</template>
