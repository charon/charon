<script setup lang="ts">
import type { AuthFlowResponse } from "@/types"
import { ref, onMounted, nextTick, computed } from "vue"
import { useRouter } from "vue-router"
import Button from "@/components/Button.vue"
import InputText from "@/components/InputText.vue"
import { postURL } from "@/api"
import { locationRedirect, fromBase64, toBase64 } from "@/utils"

const props = defineProps<{
  modelValue: string
  id: string
  emailOrUsername: string
}>()

const emit = defineEmits<{
  "update:modelValue": [value: string]
}>()

const router = useRouter()

const password = ref("")
const progress = ref(0)
const keyProgress = ref(0)

const isEmail = computed(() => {
  return props.emailOrUsername.indexOf("@") >= 0
})

let remotePublicKeyBytes: Uint8Array
let deriveOptions: object
let encryptOptions: object & { nonceSize: number }

onMounted(async () => {
  await nextTick()
  document.getElementById("password")?.focus()
})

onMounted(async () => {
  keyProgress.value += 1
  try {
    const url = router.apiResolve({
      name: "AuthFlow",
      params: {
        id: props.id,
      },
    }).href

    const response: AuthFlowResponse = await postURL(
      url,
      {
        step: "start",
        provider: "password",
      },
      keyProgress,
    )
    if (locationRedirect(response)) {
      // We increase the progress and never decrease it to wait for browser to do the redirect.
      progress.value += 1
      return
    }
    if (!response.password?.publicKey) {
      throw new Error("password public key missing in response.")
    }
    if (!response.password?.deriveOptions) {
      throw new Error("password derive options missing in response.")
    }
    if (!response.password?.encryptOptions) {
      throw new Error("password encrypt options missing in response.")
    }

    remotePublicKeyBytes = fromBase64(response.password.publicKey)
    deriveOptions = response.password.deriveOptions
    encryptOptions = response.password.encryptOptions
  } finally {
    keyProgress.value -= 1
  }
})

async function onBack() {
  emit("update:modelValue", "start")
  await nextTick()
  document.getElementById("email-or-username")?.focus()
}

async function onNext() {
  progress.value += 1
  try {
    const url = router.apiResolve({
      name: "AuthFlow",
      params: {
        id: props.id,
      },
    }).href

    const encoder = new TextEncoder()
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const keyPair = await crypto.subtle.generateKey(deriveOptions as any, false, ["deriveKey"])
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const remotePublicKey = await crypto.subtle.importKey("raw", remotePublicKeyBytes, deriveOptions as any, false, [])
    const secret = await crypto.subtle.deriveKey(
      {
        ...deriveOptions,
        public: remotePublicKey,
      } as any, // eslint-disable-line @typescript-eslint/no-explicit-any
      keyPair.privateKey,
      encryptOptions as any, // eslint-disable-line @typescript-eslint/no-explicit-any
      false,
      ["encrypt"],
    )
    const nonce = crypto.getRandomValues(new Uint8Array(encryptOptions.nonceSize))
    const ciphertext = await crypto.subtle.encrypt(
      {
        ...encryptOptions,
        iv: nonce,
      } as any, // eslint-disable-line @typescript-eslint/no-explicit-any
      secret,
      encoder.encode(password.value),
    )
    const publicKeyBytes = await crypto.subtle.exportKey("raw", keyPair.publicKey)
    const response: AuthFlowResponse = await postURL(
      url,
      {
        step: "complete",
        provider: "password",
        password: {
          publicKey: toBase64(new Uint8Array(publicKeyBytes)),
          nonce: toBase64(nonce),
          emailOrUsername: props.emailOrUsername,
          password: toBase64(new Uint8Array(ciphertext)),
        },
      },
      progress,
    )
    console.log(response)
    if (locationRedirect(response)) {
      // We increase the progress and never decrease it to wait for browser to do the redirect.
      progress.value += 1
    }
  } finally {
    progress.value -= 1
  }
}
</script>

<template>
  <div class="flex flex-col mt-4">
    <label for="email-or-username" class="mb-1">{{ isEmail ? "Your e-mail address" : "Charon username" }}</label>
    <button
      id="email-or-username"
      type="button"
      class="flex-grow appearance-none rounded border-0 border-gray-500 bg-white px-3 py-2 text-left text-base shadow outline-none ring-2 ring-neutral-300 hover:ring-neutral-400 focus:border-blue-600 focus:ring-2 focus:ring-primary-500"
      @click.prevent="onBack"
    >
      {{ emailOrUsername }}
    </button>
  </div>
  <div class="flex flex-col mt-4">
    <label for="password" class="mb-1">Password or passphrase</label>
    <form class="flex flex-row" @submit.prevent="onNext">
      <InputText id="password" v-model="password" type="password" tabindex="1" class="flex-grow flex-auto min-w-0" :readonly="progress > 0" />
      <Button type="submit" class="ml-4" tabindex="2" :disabled="password.trim().length == 0 || progress + keyProgress > 0">Next</Button>
    </form>
  </div>
  <div v-if="isEmail" class="mt-4">
    If you do not yet have an account, it will be created for you. If you enter invalid password or passphrase, recovery will be done automatically for you by sending you
    a code to your e-mail address.
  </div>
  <div v-else class="mt-4">
    If you do not yet have an account, it will be created for you. Username will not be visible to others, but it is possible to determine if an account with a username
    exists or not. If you enter invalid password or passphrase, recovery will be done automatically for you by sending you a code to e-mail address(es) associated with
    the username, if any.
  </div>
  <div class="mt-4">You can also skip entering password or passphrase and directly request the code.</div>
  <div class="mt-4 flex flex-row justify-between gap-4">
    <Button type="button" tabindex="4" :disabled="progress > 0" @click.prevent="onBack">Back</Button>
    <Button type="button" tabindex="3" :disabled="progress > 0">Send code</Button>
  </div>
</template>
