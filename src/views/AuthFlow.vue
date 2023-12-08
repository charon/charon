<script setup lang="ts">
import type { Ref } from "vue"
import type { AuthFlowRequest, AuthFlowResponse } from "@/types"
import { ref, computed, onMounted, nextTick, watch } from "vue"
import { useRouter } from "vue-router"
import { browserSupportsWebAuthn } from "@simplewebauthn/browser"
import Button from "@/components/Button.vue"
import InputText from "@/components/InputText.vue"
import AuthPassword from "@/components/AuthPassword.vue"
import AuthPasskeySignin from "@/components/AuthPasskeySignin.vue"
import AuthPasskeySignup from "@/components/AuthPasskeySignup.vue"
import AuthCode from "@/components/AuthCode.vue"
import { postURL, startPassword } from "@/api"
import { locationRedirect } from "@/utils"
import siteContext from "@/context"

const props = defineProps<{
  id: string
}>()

const router = useRouter()

const state = ref("start")
const emailOrUsername = ref("")
const passwordProgress = ref(0)
const passwordError = ref("")
const passwordPublicKey = ref(new Uint8Array())
const passwordDeriveOptions = ref({ name: "", namedCurve: "" })
const passwordEncryptOptions = ref({ name: "", iv: new Uint8Array(), tagLength: 9, length: 0 })

const isEmail = computed(() => {
  return emailOrUsername.value.indexOf("@") >= 0
})

const providerProgress = new Map<string, Ref<number>>()
for (const provider of siteContext.providers.values()) {
  providerProgress.set(provider.key, ref(0))
}

const progress = computed(() => {
  let c = passwordProgress.value
  for (const provider of siteContext.providers.values()) {
    c += providerProgress.get(provider.key)!.value
  }
  return c
})

watch(emailOrUsername, () => {
  // We reset the error when input box value changes.
  passwordError.value = ""
})

onMounted(async () => {
  await nextTick()
  document.getElementById("email-or-username")?.focus()
})

async function onNext() {
  const response = await startPassword(router, props.id, emailOrUsername.value, passwordProgress, passwordProgress)
  if (response === null) {
    return
  }
  if ("error" in response) {
    passwordError.value = response.error
    return
  }

  emailOrUsername.value = response.emailOrUsername
  passwordPublicKey.value = response.publicKey
  passwordDeriveOptions.value = response.deriveOptions
  passwordEncryptOptions.value = response.encryptOptions
  state.value = "password"
}

async function onOIDCProvider(provider: string) {
  const progress = providerProgress.get(provider)!
  progress.value += 1
  try {
    const response = (await postURL(
      router.apiResolve({
        name: "AuthFlow",
        params: {
          id: props.id,
        },
      }).href,
      {
        provider: provider,
        step: "start",
      } as AuthFlowRequest,
      progress,
    )) as AuthFlowResponse
    if (locationRedirect(response)) {
      // We increase the progress and never decrease it to wait for browser to do the redirect.
      progress.value += 1
    } else {
      throw new Error("unexpected response")
    }
  } finally {
    progress.value -= 1
  }
}
</script>

<template>
  <div class="flex flex-col self-center rounded border bg-white p-4 shadow my-1 mx-4">
    <h2 class="text-center mx-4 mb-4 text-xl font-bold uppercase">Sign-in or sign-up</h2>
    <template v-if="state === 'start'">
      <div class="flex flex-col">
        <label for="email-or-username" class="mb-1">Enter Charon username or your e-mail address</label>
        <form class="flex flex-row" novalidate @submit.prevent="onNext">
          <InputText
            id="email-or-username"
            v-model="emailOrUsername"
            class="flex-grow flex-auto min-w-0"
            :readonly="progress > 0"
            :invalid="!!passwordError"
            autocomplete="username"
            spellcheck="false"
            type="email"
            minlength="3"
            required
          />
          <Button type="submit" class="ml-4" :disabled="emailOrUsername.trim().length < 3 || progress > 0 || !!passwordError">Next</Button>
        </form>
        <div v-if="passwordError === 'invalidEmailOrUsername' && isEmail" class="mt-4 text-error-600">Invalid e-mail address.</div>
        <div v-else-if="passwordError === 'invalidEmailOrUsername' && !isEmail" class="mt-4 text-error-600">Invalid username.</div>
      </div>
      <h2 class="text-center m-4 text-xl font-bold uppercase">Or use</h2>
      <Button type="button" :disabled="!browserSupportsWebAuthn() || progress > 0" @click.prevent="state = 'passkeySignin'">Passkey</Button>
      <Button
        v-for="provider of siteContext.providers"
        :key="provider.key"
        type="button"
        class="mt-4"
        :disabled="progress > 0"
        :progress="providerProgress.get(provider.key)!.value"
        @click.prevent="onOIDCProvider(provider.key)"
        >{{ provider.name }}</Button
      >
    </template>
    <AuthPasskeySignin v-else-if="state === 'passkeySignin'" :id="id" v-model="state" />
    <AuthPasskeySignup v-else-if="state === 'passkeySignup'" :id="id" v-model="state" />
    <AuthPassword
      v-else-if="state === 'password'"
      :id="id"
      v-model="state"
      :email-or-username="emailOrUsername"
      :public-key="passwordPublicKey"
      :derive-options="passwordDeriveOptions"
      :encrypt-options="passwordEncryptOptions"
    />
    <AuthCode v-else-if="state === 'code'" :id="id" v-model="state" :email-or-username="emailOrUsername" />
  </div>
</template>
