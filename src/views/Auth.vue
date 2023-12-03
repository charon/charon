<script setup lang="ts">
import { ref } from "vue"
import { useRouter, useRoute } from "vue-router"
import { browserSupportsWebAuthn } from "@simplewebauthn/browser"
import InputText from "@/components/InputText.vue"
import Button from "@/components/Button.vue"

const router = useRouter()
const route = useRoute()

const emailOrUsername = ref("")

async function onStartNext() {}
</script>

<template>
  <div class="flex flex-col self-center rounded border bg-white p-4 shadow my-1 mx-4">
    <h2 class="text-center mx-4 mb-4 text-xl font-bold uppercase">Sign-in or sign-up</h2>
    <div class="flex flex-col">
      <label for="email-address" class="mb-1">Enter your Charon username or your e-mail address</label>
      <form class="flex flex-row" @submit.prevent="onStartNext">
        <InputText id="email-address" v-model="emailOrUsername" class="flex-grow flex-auto min-w-0" />
        <Button type="submit" class="ml-4" :disabled="emailOrUsername.length == 0">Next</Button>
      </form>
    </div>
    <h2 class="text-center m-4 text-xl font-bold uppercase">Or use</h2>
    <form :action="router.apiResolve({ name: 'AuthProvider', query: { flow: route.query.flow } }).href" method="post" class="flex flex-col">
      <router-link v-slot="{ navigate }" custom :to="{ name: 'AuthPasskeySignin', query: { flow: route.query.flow } }">
        <Button type="button" :disabled="!browserSupportsWebAuthn()" @click="navigate">Passkey</Button>
      </router-link>
      <Button type="submit" class="mt-4" name="provider" value="google">Google</Button>
      <Button type="submit" class="mt-4" name="provider" value="facebook">Facebook</Button>
    </form>
  </div>
</template>
