<script setup lang="ts">
import type { AuthFlowCodeStartRequest, AuthFlowPasswordCompleteRequest, AuthFlowResponse, Flow } from "@/types"

import { ref, watch, onBeforeUnmount, onMounted, getCurrentInstance } from "vue"
import { useRouter } from "vue-router"
import Button from "@/components/Button.vue"
import InputText from "@/components/InputText.vue"
import InputTextButton from "@/components/InputTextButton.vue"
import { postJSON, startPassword } from "@/api"
import { toBase64, isEmail } from "@/utils"
import { removeSteps, processResponse } from "@/flow"
import { injectProgress } from "@/progress"

const props = defineProps<{
  flow: Flow
}>()

const router = useRouter()

const progress = injectProgress()

const abortController = new AbortController()

const password = ref("")
const keyProgress = ref(0)
const passwordError = ref("")
const codeError = ref("")
const codeErrorOnce = ref(false)
const unexpectedPasswordError = ref("")
const unexpectedCodeError = ref("")

function resetOnInteraction() {
  // We reset flags and errors on interaction.
  passwordError.value = ""
  // codeError is not reset on purpose, once it is set it stays set.
  codeErrorOnce.value = false
  unexpectedPasswordError.value = ""
  unexpectedCodeError.value = ""
}

watch([password], resetOnInteraction)

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
  document.getElementById("current-password")?.focus()

  // If public key or options are not available, we fetch them early so that user
  // does not have to wait later on for us to fetch them.
  if (!props.flow.getPublicKey() || !props.flow.getDeriveOptions() || !props.flow.getEncryptOptions()) {
    // We do not use await here because it is OK if everything else continues to run
    // while we are fetching the public key and options. (Also onAfterEnter is not async.)
    getKey()
  }
}

function onBeforeLeave() {
  abortController.abort()
}

async function getKey(): Promise<boolean> {
  if (abortController.signal.aborted) {
    return false
  }

  // TODO: If getKey is already running at this point, we should just wait for the other one to finish.
  //       And then return here with the same return value as the other one.

  keyProgress.value += 1
  try {
    const response = await startPassword(router, props.flow, abortController, keyProgress, progress)
    if (abortController.signal.aborted) {
      return false
    }
    if (response === null) {
      return false
    }
    if ("error" in response) {
      // This call has already succeeded with same arguments so it should not error.
      throw new Error("unexpected response")
    }

    props.flow.setPublicKey(response.publicKey)
    props.flow.setDeriveOptions(response.deriveOptions)
    props.flow.setEncryptOptions(response.encryptOptions)
    return true
  } catch (error) {
    if (abortController.signal.aborted) {
      return false
    }
    // We just rethrow the error here. If this is called from onNext it will be handled
    // there. Otherwise it will be logged as we call getKey without awaiting on it.
    // If the error is persistent, then it will be eventually handled by the onNext
    // because the public key or options will not be set.
    // TODO: Can we do something better?
    throw error
  } finally {
    keyProgress.value -= 1
  }
}

async function onBack() {
  if (abortController.signal.aborted) {
    return
  }

  abortController.abort()
  props.flow.backward("start")
}

async function onRedo() {
  if (abortController.signal.aborted) {
    return
  }
  // We disable this event handler because this event handler is called from a link.
  if (progress.value > 0) {
    return
  }

  abortController.abort()
  props.flow.backward("start")
}

async function onNext() {
  if (abortController.signal.aborted) {
    return
  }

  resetOnInteraction()

  progress.value += 1
  try {
    const url = router.apiResolve({
      name: "AuthFlowPasswordComplete",
      params: {
        id: props.flow.getId(),
      },
    }).href

    if (!props.flow.getPublicKey() || !props.flow.getDeriveOptions() || !props.flow.getEncryptOptions()) {
      if (!(await getKey())) {
        // Or signal was aborted or it was an redirect response.
        return
      }
    }

    const publicKey = props.flow.getPublicKey()
    const deriveOptions = props.flow.getDeriveOptions()
    const encryptOptions = props.flow.getEncryptOptions()

    if (!publicKey || !deriveOptions || !encryptOptions) {
      // This should not happen.
      throw new Error("missing public key or options")
    }

    // We invalidate public key and options to never reuse them.
    props.flow.setPublicKey()
    props.flow.setDeriveOptions()
    props.flow.setEncryptOptions()

    const encoder = new TextEncoder()
    const keyPair = await crypto.subtle.generateKey(deriveOptions, false, ["deriveKey"])
    if (abortController.signal.aborted) {
      return
    }
    const remotePublicKey = await crypto.subtle.importKey("raw", publicKey, deriveOptions, false, [])
    if (abortController.signal.aborted) {
      return
    }
    const secret = await crypto.subtle.deriveKey(
      {
        ...deriveOptions,
        public: remotePublicKey,
      },
      keyPair.privateKey,
      encryptOptions,
      false,
      ["encrypt"],
    )
    if (abortController.signal.aborted) {
      return
    }
    const ciphertext = await crypto.subtle.encrypt(encryptOptions, secret, encoder.encode(password.value))
    if (abortController.signal.aborted) {
      return
    }
    const publicKeyBytes = await crypto.subtle.exportKey("raw", keyPair.publicKey)
    if (abortController.signal.aborted) {
      return
    }
    const response = await postJSON<AuthFlowResponse>(
      url,
      {
        publicKey: toBase64(new Uint8Array(publicKeyBytes)),
        password: toBase64(new Uint8Array(ciphertext)),
      } as AuthFlowPasswordCompleteRequest,
      abortController.signal,
      progress,
    )
    if (abortController.signal.aborted) {
      return
    }
    // processResponse might move the flow to the next step if sign-in or sign-up happened.
    if (processResponse(router, response, props.flow, progress, abortController)) {
      // Sign-in or sign-up happened, code step is not necessary anymore.
      removeSteps(props.flow, ["code"])
      return
    }
    if ("error" in response && ["wrongPassword", "invalidPassword", "shortPassword"].includes(response.error)) {
      passwordError.value = response.error
      if (response.error === "wrongPassword" && !codeError.value) {
        // If password error was returned and account recovery was not automatically
        // attempted it means that the account exist but without e-mail addresses.
        codeError.value = "noEmails"
        codeErrorOnce.value = true
        // Code step is not possible.
        removeSteps(props.flow, ["code"])
      }
      // We do not await getKey so that user can fix the password in meantime.
      getKey()
      return
    }
    if (response.providers && response.providers.length > 0 && response.providers[response.providers.length-1] === "code") {
      props.flow.forward("code")
      return
    }
    throw new Error("unexpected response")
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("AuthPassword.onNext", error)
    unexpectedPasswordError.value = `${error}`
  } finally {
    progress.value -= 1
  }
}

async function onCode() {
  if (abortController.signal.aborted) {
    return
  }

  resetOnInteraction()

  progress.value += 1
  try {
    const url = router.apiResolve({
      name: "AuthFlowCodeStart",
      params: {
        id: props.flow.getId(),
      },
    }).href

    // We invalidate public key and options because starting the code
    // provider invalidates them on the server side.
    props.flow.setPublicKey()
    props.flow.setDeriveOptions()
    props.flow.setEncryptOptions()

    const response = await postJSON<AuthFlowResponse>(
      url,
      {
        emailOrUsername: props.flow.getEmailOrUsername(),
      } as AuthFlowCodeStartRequest,
      abortController.signal,
      progress,
    )
    if (abortController.signal.aborted) {
      return
    }
    // processResponse should move the flow to the next step.
    if (processResponse(router, response, props.flow, progress, abortController)) {
      return
    }
    if ("error" in response && ["noAccount", "noEmails"].includes(response.error)) {
      codeError.value = response.error
      codeErrorOnce.value = true
      // Code step is not possible.
      removeSteps(props.flow, ["code"])
      return
    }
    if (response.providers && response.providers.length > 0 && response.providers[response.providers.length-1] === "code") {
      props.flow.forward("code")
      return
    }
    throw new Error("unexpected response")
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("AuthPassword.onCode", error)
    unexpectedCodeError.value = `${error}`
  } finally {
    progress.value -= 1
  }
}
</script>

<template>
  <div class="flex flex-col rounded border bg-white p-4 shadow w-full">
    <div class="flex flex-col">
      <label for="email-or-username" class="mb-1">{{ isEmail(flow.getEmailOrUsername()) ? "Your e-mail address" : "Charon username" }}</label>
      <InputTextButton id="email-or-username" class="flex-grow" tabindex="5" @click.prevent="onBack">
        {{ flow.getEmailOrUsername() }}
      </InputTextButton>
    </div>
    <div class="flex flex-col mt-4">
      <label for="current-password" class="mb-1">Password or passphrase</label>
      <!--
        We set novalidate because we do not UA to show hints.
        We show them ourselves when we want them.
      -->
      <form class="flex flex-row gap-4" novalidate @submit.prevent="onNext">
        <!--
          Help Chrome remember the username/e-mail address using hidden input field.
          See: https://www.chromium.org/developers/design-documents/form-styles-that-chromium-understands/
        -->
        <input
          id="email"
          name="email"
          autocomplete="username"
          autocorrect="off"
          autocapitalize="none"
          spellcheck="false"
          type="email"
          :value="flow.getEmailOrUsername()"
          class="hidden"
        />
        <InputText
          id="current-password"
          v-model="password"
          name="current-password"
          type="password"
          minlength="8"
          tabindex="1"
          :invalid="!!passwordError"
          class="flex-grow flex-auto min-w-0"
          :progress="progress"
          autocomplete="current-password"
          autocorrect="off"
          autocapitalize="none"
          spellcheck="false"
          required
        />
        <!--
          Here we enable button when password is not empty because we do not tell users
          what is expected upfront. If they try a too short password we will tell them.
          We prefer this so that they do not wonder why the button is not enabled.
          We also prefer this because we do not want to do full password normalization on the
          client side so we might be counting characters differently here, leading to confusion.
          Button is on purpose not disabled on unexpectedPasswordError so that user can retry.
        -->
        <Button primary type="submit" tabindex="2" :disabled="!password || keyProgress > 0 || !!passwordError" :progress="progress">Next</Button>
      </form>
    </div>
    <template v-if="passwordError">
      <div v-if="passwordError === 'wrongPassword'" class="mt-4 text-error-600">Wrong password or passphrase for the account with the provided username.</div>
      <div v-else-if="passwordError === 'invalidPassword'" class="mt-4 text-error-600">Invalid password or passphrase.</div>
      <div v-else-if="passwordError === 'shortPassword'" class="mt-4 text-error-600">Password or passphrase should be at least 8 characters.</div>
      <div v-if="passwordError === 'wrongPassword'" class="mt-4">
        If you have trouble remembering your password or passphrase, try a
        <a href="" class="link" @click.prevent="onRedo">different sign-in method</a>.
      </div>
    </template>
    <div v-else-if="unexpectedPasswordError" class="mt-4 text-error-600">Unexpected error. Please try again.</div>
    <div v-else-if="isEmail(flow.getEmailOrUsername())" class="mt-4">
      If you do not yet have an account, it will be created for you. If you enter wrong password or passphrase, recovery will be done automatically for you by sending you
      a code to your e-mail address.
    </div>
    <div v-else class="mt-4">
      If you do not yet have an account, it will be created for you. Username will not be visible to others, but it is possible to determine if an account with a username
      exists or not. If you enter wrong password or passphrase, recovery will be done automatically for you by sending you a code to e-mail address(es) associated with
      the username, if any.
    </div>
    <div v-if="codeError === 'noAccount'" class="mt-4" :class="codeErrorOnce ? 'text-error-600' : ''">
      You cannot receive the code because there is no account with the provided username.
    </div>
    <div v-else-if="codeError === 'noEmails'" class="mt-4" :class="codeErrorOnce ? 'text-error-600' : ''">
      You cannot receive the code because there is no e-mail address associated with the provided username.
    </div>
    <div v-else-if="unexpectedCodeError" class="mt-4 text-error-600">Unexpected error. Please try again.</div>
    <div v-else class="mt-4">You can also skip entering password or passphrase and directly request the code.</div>
    <div class="mt-4 flex flex-row justify-between gap-4">
      <Button type="button" tabindex="4" @click.prevent="onBack">Back</Button>
      <!--
        Button is on purpose not disabled on unexpectedCodeError so that user can retry.
      -->
      <Button type="button" primary tabindex="3" :disabled="!!codeError" :progress="progress" @click.prevent="onCode">Send code</Button>
    </div>
  </div>
</template>
