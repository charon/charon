<script setup lang="ts">
import type { AuthFlowRequest, AuthFlowResponse } from "@/types"

import { getCurrentInstance, inject, onMounted, onUnmounted, ref } from "vue"
import { useRouter } from "vue-router"
import { startAuthentication, WebAuthnAbortService } from "@simplewebauthn/browser"
import Button from "@/components/Button.vue"
import { postURL } from "@/api"
import { processCompletedAndLocationRedirect } from "@/utils"
import { flowKey } from "@/flow"
import { progressKey } from "@/progress"

const props = defineProps<{
  id: string
}>()

const router = useRouter()

const flow = inject(flowKey)
const mainProgress = inject(progressKey, ref(0))

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

onUnmounted(onBeforeLeave)

function onBeforeLeave() {
  abortController.abort()
  WebAuthnAbortService.cancelCeremony()
}

async function onAfterEnter() {
  try {
    const url = router.apiResolve({
      name: "AuthFlow",
      params: {
        id: props.id,
      },
    }).href

    const start = await postURL<AuthFlowResponse>(
      url,
      {
        provider: "passkey",
        step: "getStart",
      } as AuthFlowRequest,
      abortController.signal,
      // We do not pass here progress on purpose.
      null,
    )
    if (abortController.signal.aborted) {
      return
    }
    if (processCompletedAndLocationRedirect(start, flow, mainProgress, abortController)) {
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
    mainProgress.value += 1
    try {
      const complete = await postURL<AuthFlowResponse>(
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
      )
      if (abortController.signal.aborted) {
        return
      }
      if (processCompletedAndLocationRedirect(complete, flow, mainProgress, abortController)) {
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
    console.error(error)
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
      <Button v-else type="button" tabindex="1" :disabled="mainProgress > 0" @click.prevent="onCancel">Cancel</Button>
    </div>
  </div>
</template>
