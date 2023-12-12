<script setup lang="ts">
import type { AuthFlowRequest, AuthFlowResponse, DeriveOptions, EncryptOptions } from "@/types"
import { ref, computed, watch, onUnmounted, onMounted, getCurrentInstance } from "vue"
import { useRouter } from "vue-router"
import Button from "@/components/Button.vue"
import InputText from "@/components/InputText.vue"
import { postURL, startPassword } from "@/api"
import { locationRedirect, toBase64 } from "@/utils"

const props = defineProps<{
  state: string
  direction: "forward" | "backward"
  id: string
  emailOrUsername: string
  publicKey: Uint8Array
  deriveOptions: DeriveOptions
  encryptOptions: EncryptOptions
}>()

const emit = defineEmits<{
  "update:state": [value: string]
  "update:direction": [value: "forward" | "backward"]
}>()

const router = useRouter()

const password = ref("")
const mainProgress = ref(0)
const abortController = new AbortController()
const keyProgress = ref(0)
const passwordError = ref("")
const codeError = ref("")
const codeErrorOnce = ref(false)

const isEmail = computed(() => {
  return props.emailOrUsername.indexOf("@") >= 0
})

let remotePublicKeyBytes = props.publicKey
let effectiveDeriveOptions = props.deriveOptions
let effectiveEncryptOptions = props.encryptOptions

watch(password, () => {
  // We reset the error when input box value changes.
  passwordError.value = ""
  codeErrorOnce.value = false
})

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

function onAfterEnter() {
  document.getElementById("current-password")?.focus()
}

function onBeforeLeave() {
  abortController.abort()
}

async function getKey() {
  try {
    const response = await startPassword(router, props.id, props.emailOrUsername, abortController.signal, keyProgress, mainProgress)
    if (abortController.signal.aborted) {
      return
    }
    if (response === null) {
      return
    }
    if ("error" in response) {
      // This call has already succeeded with same arguments so it should not error.
      throw new Error("unexpected response")
    }

    // We ignore response.emailOrUsername.
    remotePublicKeyBytes = response.publicKey
    effectiveDeriveOptions = response.deriveOptions
    effectiveEncryptOptions = response.encryptOptions
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    throw error
  }
}

async function onBack() {
  if (abortController.signal.aborted) {
    return
  }

  if (mainProgress.value > 0) {
    // Clicking on disabled links.
    return
  }

  abortController.abort()
  emit("update:direction", "backward")
  emit("update:state", "start")
}

async function onNext() {
  if (abortController.signal.aborted) {
    return
  }

  mainProgress.value += 1
  try {
    codeErrorOnce.value = false
    const url = router.apiResolve({
      name: "AuthFlow",
      params: {
        id: props.id,
      },
    }).href

    const encoder = new TextEncoder()
    const keyPair = await crypto.subtle.generateKey(effectiveDeriveOptions, false, ["deriveKey"])
    if (abortController.signal.aborted) {
      return
    }
    const remotePublicKey = await crypto.subtle.importKey("raw", remotePublicKeyBytes, effectiveDeriveOptions, false, [])
    if (abortController.signal.aborted) {
      return
    }
    const secret = await crypto.subtle.deriveKey(
      {
        ...effectiveDeriveOptions,
        public: remotePublicKey,
      },
      keyPair.privateKey,
      effectiveEncryptOptions,
      false,
      ["encrypt"],
    )
    if (abortController.signal.aborted) {
      return
    }
    const ciphertext = await crypto.subtle.encrypt(effectiveEncryptOptions, secret, encoder.encode(password.value))
    if (abortController.signal.aborted) {
      return
    }
    const publicKeyBytes = await crypto.subtle.exportKey("raw", keyPair.publicKey)
    if (abortController.signal.aborted) {
      return
    }
    const response = (await postURL(
      url,
      {
        provider: "password",
        step: "complete",
        password: {
          complete: {
            publicKey: toBase64(new Uint8Array(publicKeyBytes)),
            password: toBase64(new Uint8Array(ciphertext)),
          },
        },
      } as AuthFlowRequest,
      abortController.signal,
      mainProgress,
    )) as AuthFlowResponse
    if (abortController.signal.aborted) {
      return
    }
    if (locationRedirect(response)) {
      // We increase the progress and never decrease it to wait for browser to do the redirect.
      mainProgress.value += 1
      return
    }
    // We do not list "shortPassword" here because UI does not allow too short password.
    if ("error" in response && ["wrongPassword", "invalidPassword"].includes(response.error)) {
      passwordError.value = response.error
      if (response.error === "wrongPassword" && codeError.value === "") {
        // If password error was returned and account recovery was not automatically
        // attempted it means that the account exist but without e-mail addresses.
        codeError.value = "noEmails"
        codeErrorOnce.value = true
      }
      // We do not await getKey so that user can fix the password in meantime.
      getKey()
      return
    }
    if ("code" in response) {
      // We ignore response.code.emailOrUsername.
      emit("update:direction", "forward")
      emit("update:state", "code")
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

async function onCode() {
  if (abortController.signal.aborted) {
    return
  }

  mainProgress.value += 1
  try {
    const url = router.apiResolve({
      name: "AuthFlow",
      params: {
        id: props.id,
      },
    }).href

    const response = (await postURL(
      url,
      {
        provider: "code",
        step: "start",
        code: {
          start: {
            emailOrUsername: props.emailOrUsername,
          },
        },
      } as AuthFlowRequest,
      abortController.signal,
      mainProgress,
    )) as AuthFlowResponse
    if (abortController.signal.aborted) {
      return
    }
    if (locationRedirect(response)) {
      // We increase the progress and never decrease it to wait for browser to do the redirect.
      mainProgress.value += 1
      return
    }
    if ("error" in response && ["noAccount", "noEmails"].includes(response.error)) {
      codeError.value = response.error
      codeErrorOnce.value = true
      return
    }
    if ("code" in response) {
      // We ignore response.code.emailOrUsername.
      emit("update:direction", "forward")
      emit("update:state", "code")
      return
    }
    throw new Error("unexpected response")
  } finally {
    mainProgress.value -= 1
  }
}
</script>

<template>
  <div class="flex flex-col rounded border bg-white p-4 shadow w-full float-left first:ml-0 ml-[-100%]">
    <h2 class="text-center mx-4 mb-4 text-xl font-bold uppercase">Sign-in or sign-up</h2>
    <div class="flex flex-col">
      <label for="email-or-username" class="mb-1">{{ isEmail ? "Your e-mail address" : "Charon username" }}</label>
      <button
        id="email-or-username"
        tabindex="5"
        :disabled="mainProgress > 0"
        type="button"
        class="flex-grow appearance-none rounded border-0 border-gray-500 bg-white px-3 py-2 text-left text-base shadow outline-none ring-2 ring-neutral-300 hover:ring-neutral-400 focus:border-blue-600 focus:ring-2 focus:ring-primary-500"
        @click.prevent="onBack"
      >
        {{ emailOrUsername }}
      </button>
    </div>
    <div class="flex flex-col mt-4">
      <label for="current-password" class="mb-1">Password or passphrase</label>
      <form class="flex flex-row" novalidate @submit.prevent="onNext">
        <InputText
          id="current-password"
          v-model="password"
          type="password"
          minlength="8"
          tabindex="1"
          :invalid="!!passwordError"
          class="flex-grow flex-auto min-w-0"
          :readonly="mainProgress > 0"
          autocomplete="current-password"
          spellcheck="false"
          required
        />
        <Button primary type="submit" class="ml-4" tabindex="2" :disabled="password.length < 8 || mainProgress + keyProgress > 0 || !!passwordError">Next</Button>
      </form>
    </div>
    <template v-if="passwordError">
      <div v-if="passwordError === 'wrongPassword'" class="mt-4 text-error-600">Wrong password or passphrase for the account with the provided username.</div>
      <div v-else-if="passwordError === 'invalidPassword'" class="mt-4 text-error-600">Invalid password or passphrase.</div>
      <div v-if="passwordError === 'wrongPassword'" class="mt-4">
        If you have trouble remembering your password or passphrase, try a
        <a :href="mainProgress > 0 ? undefined : ''" class="link" :class="mainProgress > 0 ? 'disabled' : ''" @click.prevent="onBack">different sign-in method</a>.
      </div>
    </template>
    <div v-else-if="isEmail" class="mt-4">
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
    <div v-else class="mt-4">You can also skip entering password or passphrase and directly request the code.</div>
    <div class="mt-4 flex flex-row justify-between gap-4">
      <Button type="button" tabindex="4" :disabled="mainProgress > 0" @click.prevent="onBack">Back</Button>
      <Button type="button" primary tabindex="3" :disabled="!!codeError || mainProgress > 0" @click.prevent="onCode">Send code</Button>
    </div>
  </div>
</template>
