<script setup lang="ts">
import type { AuthFlowPasskeyCreateCompleteRequest, AuthFlowResponse, Flow } from "@/types"

import { startRegistration, WebAuthnAbortService } from "@simplewebauthn/browser"
import { getCurrentInstance, nextTick, onBeforeUnmount, onMounted, ref } from "vue"
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

function onBack() {
  if (abortController.signal.aborted) {
    return
  }

  abortController.abort()
  WebAuthnAbortService.cancelCeremony()
  props.flow.backward("passkeySignin")
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
        id: props.flow.getId(),
      },
    }).href
    const completeUrl = router.apiResolve({
      name: "AuthFlowPasskeyCreateComplete",
      params: {
        id: props.flow.getId(),
      },
    }).href

    const start = await postJSON<AuthFlowResponse>(startUrl, {}, abortController.signal, progress)
    if (abortController.signal.aborted) {
      return
    }
    // processResponse should not really do anything here.
    if (processResponse(router, start, props.flow, progress, abortController)) {
      return
    }
    if (!("passkey" in start && "createOptions" in start.passkey)) {
      throw new Error("unexpected response")
    }

    let attestation
    try {
      attestation = await startRegistration({ optionsJSON: start.passkey.createOptions.publicKey })
    } catch (error) {
      if (abortController.signal.aborted) {
        return
      }
      signupFailed.value = true
      signupFailedAtLeastOnce.value = true
      await nextTick(() => {
        // We refocus button to retry.
        document.getElementById("passkey-signup")?.focus()
      })
      return
    }

    if (abortController.signal.aborted) {
      return
    }

    const complete = await postJSON<AuthFlowResponse>(
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
    // processResponse should move the flow to the next step.
    if (processResponse(router, complete, props.flow, progress, abortController)) {
      return
    }
    throw new Error("unexpected response")
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("AuthPasskeySignup.onPasskeySignup", error)
    // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
    unexpectedError.value = `${error}`
    signupFailedAtLeastOnce.value = true
  } finally {
    progress.value -= 1
  }
}
</script>

<template>
  <div class="flex w-full flex-col rounded-sm border border-gray-200 bg-white p-4 shadow-sm">
    <div v-if="signupAttempted && signupFailed">
      <i18n-t keypath="partials.AuthPasskeySignup.failed" scope="global">
        <template #strongPasskey
          ><strong>{{ t("partials.AuthPasskeySignup.passkey") }}</strong></template
        >
      </i18n-t>
    </div>
    <div v-else-if="signupAttempted">
      <i18n-t keypath="partials.AuthPasskeySignup.signingUp" scope="global">
        <template #strongPasskey
          ><strong>{{ t("partials.AuthPasskeySignup.passkey") }}</strong></template
        >
      </i18n-t>
    </div>
    <div v-else>
      <i18n-t keypath="partials.AuthPasskeySignup.instructions" scope="global">
        <template #strongPasskey
          ><strong>{{ t("partials.AuthPasskeySignup.passkey") }}</strong></template
        >
      </i18n-t>
    </div>
    <div class="mt-4">{{ t("partials.AuthPasskeySignup.signupInfo") }}</div>
    <div v-if="unexpectedError" class="mt-4 text-error-600">{{ t("common.errors.unexpected") }}</div>
    <div class="mt-4 flex flex-row justify-between gap-4">
      <Button type="button" tabindex="2" @click.prevent="onBack">{{ t("partials.AuthPasskeySignup.retrySigninButton") }}</Button>
      <Button id="passkey-signup" primary type="button" tabindex="1" :progress="progress" @click.prevent="onPasskeySignup">{{
        signupFailedAtLeastOnce ? t("partials.AuthPasskeySignup.retrySignupButton") : t("partials.AuthPasskeySignup.passkeySignupButton")
      }}</Button>
    </div>
  </div>
</template>
