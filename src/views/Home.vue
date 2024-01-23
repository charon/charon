<script setup lang="ts">
import type { AuthFlowResponse } from "@/types"
import { onUnmounted, ref } from "vue"
import { browserSupportsWebAuthn } from "@simplewebauthn/browser"
import Button from "@/components/Button.vue"
import ButtonLink from "@/components/ButtonLink.vue"
import Footer from "@/components/Footer.vue"
import { useRouter } from "vue-router"
import { deleteURL } from "@/api"
import { locationRedirect } from "@/utils"

const router = useRouter()

const mainProgress = ref(0)
const abortController = new AbortController()

onUnmounted(() => {
  abortController.abort()
})

async function onSignOut() {
  mainProgress.value += 1
  try {
    const response = (await deleteURL(router.apiResolve({ name: "Auth" }).href, abortController.signal, mainProgress)) as AuthFlowResponse
    if (abortController.signal.aborted) {
      return
    }
    if (locationRedirect(response)) {
      if (browserSupportsWebAuthn()) {
        navigator.credentials.preventSilentAccess()
      }
      // We increase the progress and never decrease it to wait for browser to do the redirect.
      mainProgress.value += 1
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
</script>

<template>
  <div class="w-full flex flex-col items-center">
    <div class="grid auto-rows-auto grid-cols-[minmax(0,_65ch)] m-1 sm:m-4 gap-1 sm:gap-4">
      <div>Welcome.</div>
      <Button primary type="button" :disabled="mainProgress > 0" @click.prevent="onSignOut">Sign-out</Button>
      <ButtonLink :to="{ name: 'Applications' }" :disabled="mainProgress > 0" primary>Applications</ButtonLink>
      <ButtonLink :to="{ name: 'Organizations' }" :disabled="mainProgress > 0" primary>Organizations</ButtonLink>
    </div>
  </div>
  <Teleport to="footer">
    <Footer />
  </Teleport>
</template>
