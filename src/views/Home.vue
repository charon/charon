<script setup lang="ts">
import type { AuthFlowResponse } from "@/types"
import { ref } from "vue"
import Button from "@/components/Button.vue"
import { useRouter } from "vue-router"
import { deleteURL } from "@/api"
import { locationRedirect } from "@/utils"

const router = useRouter()

async function onSignOut() {
  const progress = ref(0)
  const response: AuthFlowResponse = await deleteURL(router.apiResolve({ name: "Auth" }).href, progress)
  locationRedirect(router, response)
}
</script>

<template>
  <div>Hello world.</div>
  <div><Button type="submit" @click.prevent="onSignOut">Sign-out</Button></div>
</template>
