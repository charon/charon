<script setup lang="ts">
import type { Ref } from "vue"
import type { AuthFlowResponse } from "@/types"
import { ref, computed } from "vue"
import { useRouter } from "vue-router"
import { browserSupportsWebAuthn } from "@simplewebauthn/browser"
import Button from "@/components/Button.vue"
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
      <AuthPassword :id="id" v-model="state" :disabled="progress > 0" />
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
  </div>
</template>
