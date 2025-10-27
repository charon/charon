<script setup lang="ts">
import type { AuthFlowPasskeyGetCompleteRequest, AuthFlowResponse, Flow } from "@/types"

import { startAuthentication, WebAuthnAbortService } from "@simplewebauthn/browser"
import { getCurrentInstance, onBeforeUnmount, onMounted, ref } from "vue"
import { useI18n } from "vue-i18n"
import { useRouter } from "vue-router"

import { postJSON } from "@/api"
import Button from "@/components/Button.vue"
import { processResponse } from "@/flow"
import { injectProgress } from "@/progress"

const props = defineProps<{
  flow: Flow
}>()

const { t } = useI18n({ useScope: "global" })
const router = useRouter()
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
        id: props.flow.getId(),
      },
    }).href
    const completeUrl = router.apiResolve({
      name: "AuthFlowPasskeyGetComplete",
      params: {
        id: props.flow.getId(),
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
    // processResponse should not really do anything here.
    if (processResponse(router, start, props.flow, progress, abortController)) {
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
      props.flow.forward("passkeySignup")
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
      // processResponse should move the flow to the next step.
      if (processResponse(router, complete, props.flow, progress, abortController)) {
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
  props.flow.backward("start")
}

async function onCancel() {
  if (abortController.signal.aborted) {
    return
  }

  abortController.abort()
  WebAuthnAbortService.cancelCeremony()
  props.flow.forward("passkeySignup")
}
</script>

<template>
  <div class="flex flex-col rounded-sm border bg-white p-4 shadow-sm w-full">
    <div>
      <i18n-t keypath="partials.AuthPasskeySignin.signingIn" scope="global">
        <template #strongPasskey
          ><strong>{{ t("partials.AuthPasskeySignin.passkey") }}</strong></template
        >
      </i18n-t>
    </div>
    <div class="mt-4">{{ t("partials.AuthPasskeySignin.signupInfo") }}</div>
    <div v-if="unexpectedError" class="mt-4 text-error-600">{{ t("common.errors.unexpected") }}</div>
    <div class="mt-4 flex flex-row justify-between gap-4">
      <Button type="button" tabindex="2" @click.prevent="onBack">{{ t("common.buttons.back") }}</Button>
      <Button v-if="unexpectedError" primary type="button" tabindex="1" @click.prevent="onRetry">{{ t("common.buttons.retry") }}</Button>
      <Button v-else type="button" tabindex="1" :progress="progress" @click.prevent="onCancel">{{ t("common.buttons.cancel") }}</Button>
    </div>
  </div>
</template>
