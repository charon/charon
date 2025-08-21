<script setup lang="ts">
import type { AuthFlowPasskeyCreateCompleteRequest, AuthFlowResponse, Flow } from "@/types"

import { getCurrentInstance, nextTick, onMounted, onBeforeUnmount, ref } from "vue"
import { useRouter } from "vue-router"
import { useI18n } from "vue-i18n"
import { startRegistration, WebAuthnAbortService } from "@simplewebauthn/browser"
import Button from "@/components/Button.vue"
import { postJSON } from "@/api"
import { processResponse } from "@/flow"
import { injectProgress } from "@/progress"

const { t } = useI18n()

const props = defineProps<{
  flow: Flow
}>()

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

async function onBack() {
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
    unexpectedError.value = `${error}`
    signupFailedAtLeastOnce.value = true
  } finally {
    progress.value -= 1
  }
}
</script>

<template>
  <div class="flex flex-col rounded border bg-white p-4 shadow w-full">
    <div v-if="signupAttempted && signupFailed">
      <i18n-t keypath="auth.passkey.signup.failed">
        <template #strong><strong>{{ t('auth.passkey.signin.strongPasskey') }}</strong></template>
      </i18n-t>
    </div>
    <div v-else-if="signupAttempted">
      <i18n-t keypath="auth.passkey.signup.signingUp">
        <template #strong><strong>{{ t('auth.passkey.signin.strongPasskey') }}</strong></template>
      </i18n-t>
    </div>
    <div v-else>
      <i18n-t keypath="auth.passkey.signup.instructions">
        <template #strong><strong>{{ t('auth.passkey.signin.strongPasskey') }}</strong></template>
      </i18n-t>
    </div>
    <div v-if="unexpectedError" class="mt-4 text-error-600">{{ t('auth.passkey.errors.unexpected') }}</div>
    <div class="mt-4 flex flex-row justify-between gap-4">
      <Button type="button" tabindex="2" @click.prevent="onBack">{{ t('auth.passkey.signup.retrySigninButton') }}</Button>
      <Button id="passkey-signup" primary type="button" tabindex="1" :progress="progress" @click.prevent="onPasskeySignup">{{ signupFailedAtLeastOnce ? t('auth.passkey.signup.retrySignupButton') : t('auth.passkey.signup.passkeySignupButton') }}</Button>
    </div>
  </div>
</template>
