<script setup lang="ts">
import type { AuthFlowResponse } from "@/types"
import { ref } from "vue"
import { useRouter } from "vue-router"
import { browserSupportsWebAuthn } from "@simplewebauthn/browser"
import Button from "@/components/Button.vue"
import AuthPassword from "@/components/AuthPassword.vue"
import AuthPasskeySignin from "@/components/AuthPasskeySignin.vue"
import AuthPasskeySignup from "@/components/AuthPasskeySignup.vue"
import { postURL } from "@/api"
import { locationRedirect } from "@/utils"

const props = defineProps<{
  id: string
}>()

const router = useRouter()

const state = ref("start")

async function onOIDCProvider(provider: string) {
  const progress = ref(0)
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
  locationRedirect(response)
}
</script>

<template>
  <div class="flex flex-col self-center rounded border bg-white p-4 shadow my-1 mx-4">
    <h2 class="text-center mx-4 mb-4 text-xl font-bold uppercase">Sign-in or sign-up</h2>
    <template v-if="state === 'start'">
      <AuthPassword :id="id" v-model="state" />
      <h2 class="text-center m-4 text-xl font-bold uppercase">Or use</h2>
      <Button type="button" :disabled="!browserSupportsWebAuthn()" @click.prevent="state = 'passkeySignin'">Passkey</Button>
      <Button type="submit" class="mt-4" @click.prevent="onOIDCProvider('google')">Google</Button>
      <Button type="submit" class="mt-4" @click.prevent="onOIDCProvider('facebook')">Facebook</Button>
    </template>
    <AuthPasskeySignin v-else-if="state === 'passkeySignin'" :id="id" v-model="state" />
    <AuthPasskeySignup v-else-if="state === 'passkeySignup'" :id="id" v-model="state" />
  </div>
</template>
