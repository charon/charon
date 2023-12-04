<script setup lang="ts">
import type { Ref } from "vue"
import type { AuthFlowResponse } from "@/types"
import { ref, computed, onMounted, nextTick } from "vue"
import { useRouter } from "vue-router"
import { browserSupportsWebAuthn } from "@simplewebauthn/browser"
import Button from "@/components/Button.vue"
import InputText from "@/components/InputText.vue"
import AuthPassword from "@/components/AuthPassword.vue"
import AuthPasskeySignin from "@/components/AuthPasskeySignin.vue"
import AuthPasskeySignup from "@/components/AuthPasskeySignup.vue"
import { postURL } from "@/api"
import { locationRedirect } from "@/utils"
import siteContext from "@/context"

const props = defineProps<{
  id: string
}>()

const router = useRouter()

const state = ref("start")
const emailOrUsername = ref("")

const providerProgress = new Map<string, Ref<number>>()
for (const provider of siteContext.providers.values()) {
  providerProgress.set(provider.key, ref(0))
}

const progress = computed(() => {
  let c = 0
  for (const provider of siteContext.providers.values()) {
    c += providerProgress.get(provider.key)!.value
  }
  return c
})

onMounted(async () => {
  await nextTick()
  document.getElementById("email-or-username")?.focus()
})

async function onNext() {
  state.value = "password"
}

async function onOIDCProvider(provider: string) {
  const progress = providerProgress.get(provider)!
  progress.value += 1
  try {
    const response: AuthFlowResponse = await postURL(
      router.apiResolve({
        name: "AuthFlow",
        params: {
          id: props.id,
        },
      }).href,
      {
        step: "start",
        provider: provider,
      },
      progress,
    )
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
  <div class="flex flex-col self-center rounded border bg-white p-4 shadow my-1 mx-4">
    <h2 class="text-center mx-4 mb-4 text-xl font-bold uppercase">Sign-in or sign-up</h2>
    <template v-if="state === 'start'">
      <div class="flex flex-col">
        <label for="email-or-username" class="mb-1">Enter Charon username or your e-mail address</label>
        <form class="flex flex-row" @submit.prevent="onNext">
          <InputText id="email-or-username" v-model="emailOrUsername" class="flex-grow flex-auto min-w-0" :readonly="progress > 0" />
          <Button type="submit" class="ml-4" :disabled="emailOrUsername.trim().length == 0 || progress > 0">Next</Button>
        </form>
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
    <AuthPassword v-else-if="state === 'password'" :id="id" v-model="state" :email-or-username="emailOrUsername" />
  </div>
</template>
