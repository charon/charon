<script setup lang="ts">
import type { AuthResponse, AuthPasskeySignupResponse } from "@/types"
import { ref } from "vue"
import { useRouter, useRoute } from "vue-router"
import { browserSupportsWebAuthn, startRegistration } from "@simplewebauthn/browser"
import Button from "@/components/Button.vue"
import { postURL } from "@/api"

const router = useRouter()
const route = useRoute()

async function onBack() {
  // TODO: Use router.go(-2) when previous location is the same as what we would push.
  router.push({ name: "Auth", query: { flow: route.query.flow } })
}

async function onRetry() {
  // TODO: Use router.go(-1) when previous location is the same as what we would push.
  router.push({ name: "AuthPasskeySignin", query: { flow: route.query.flow } })
}

async function onPasskeySignup() {
  const progress = ref(0)
  const options = await postURL(router.apiResolve({ name: "AuthPasskeySignup", query: { flow: route.query.flow } }).href, null, progress)
  const attestation = await startRegistration((options as AuthPasskeySignupResponse).options.publicKey)
  const result = await postURL(router.apiResolve({ name: "AuthPasskeySignupComplete", query: { flow: route.query.flow } }).href, attestation, progress)
  router.push((result as AuthResponse).location)
}
</script>

<template>
  <div class="flex flex-col self-center rounded border bg-white p-4 shadow my-1 mx-4">
    <h2 class="text-center mx-4 mb-4 text-xl font-bold uppercase">Sign-in or sign-up</h2>
    <template v-if="!browserSupportsWebAuthn()">
      <div>Your browser does not support <strong>passkey</strong> authentication.</div>
      <Button type="button" class="mt-4" @click.prevent="onBack">Back</Button>
    </template>
    <template v-else>
      <div>Signing in using <strong>passkey</strong> failed. Do you want to sign up instead?</div>
      <div class="mt-4 flex flex-row justify-between gap-4">
        <div class="flex flex-row gap-4">
          <Button type="button" @click.prevent="onBack">Back</Button>
          <Button type="button" @click.prevent="onRetry">Retry sign-in</Button>
        </div>
        <Button type="button" @click.prevent="onPasskeySignup">Passkey sign-up</Button>
      </div>
    </template>
  </div>
</template>
