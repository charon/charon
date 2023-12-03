<script setup lang="ts">
import type { AuthResponse, AuthPasskeySigninResponse } from "@/types"
import { onMounted, ref } from "vue"
import { useRouter, useRoute } from "vue-router"
import { browserSupportsWebAuthn, startAuthentication } from "@simplewebauthn/browser"
import Button from "@/components/Button.vue"
import { postURL } from "@/api"

const router = useRouter()
const route = useRoute()

async function onBack() {
  // TODO: Use router.go(-1) when previous location is the same as what we would push.
  router.push({ name: "Auth", query: { flow: route.query.flow } })
}

async function onCancel() {
  router.push({ name: "AuthPasskeySignup", query: { flow: route.query.flow } })
}

onMounted(async () => {
  const progress = ref(0)
  const options = await postURL(router.apiResolve({ name: "AuthPasskeySignin", query: { flow: route.query.flow } }).href, null, progress)
  const assertion = await startAuthentication((options as AuthPasskeySigninResponse).options.publicKey)
  const result = await postURL(router.apiResolve({ name: "AuthPasskeySigninComplete", query: { flow: route.query.flow } }).href, assertion, progress)
  router.push((result as AuthResponse).location)
})
</script>

<template>
  <div class="flex flex-col self-center rounded border bg-white p-4 shadow my-1 mx-4">
    <h2 class="text-center mx-4 mb-4 text-xl font-bold uppercase">Sign-in or sign-up</h2>
    <template v-if="!browserSupportsWebAuthn()">
      <div>Your browser does not support <strong>passkey</strong> authentication.</div>
      <Button type="button" class="mt-4" @click.prevent="onBack">Back</Button>
    </template>
    <template v-else>
      <div>Signing you in using <strong>passkey</strong>. Please follow instructions by your browser and/or device.</div>
      <div class="mt-4">If you have not yet signed up with passkey, this will fail. In that case Charon will offer you to sign up instead.</div>
      <div class="mt-4 flex flex-row justify-between gap-4">
        <Button type="button" @click.prevent="onBack">Back</Button>
        <Button type="button" @click.prevent="onCancel">Cancel</Button>
      </div>
    </template>
  </div>
</template>
