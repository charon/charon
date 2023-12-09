<script setup lang="ts">
import type { AuthFlowResponse } from "@/types"
import { ref } from "vue"
import Button from "@/components/Button.vue"
import { useRouter } from "vue-router"
import { deleteURL } from "@/api"
import { locationRedirect } from "@/utils"

const router = useRouter()

const progress = ref(0)

async function onSignOut() {
  progress.value += 1
  try {
    const response: AuthFlowResponse = await deleteURL(router.apiResolve({ name: "Auth" }).href, progress)
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
  <div>Hello world.</div>
  <div><Button primary type="button" :progress="progress" @click.prevent="onSignOut">Sign-out</Button></div>
</template>
