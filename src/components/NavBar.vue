<script setup lang="ts">
import type { AuthSignoutResponse } from "@/types"

import { onUnmounted, ref, inject } from "vue"
import { useRouter } from "vue-router"
import { browserSupportsWebAuthn } from "@simplewebauthn/browser"
import { GlobeAltIcon } from "@heroicons/vue/24/outline"
import Button from "@/components/Button.vue"
import { useNavbar } from "@/navbar"
import { deleteURL } from "@/api"
import { progressKey } from "@/progress"

const { ref: navbar, attrs: navbarAttrs } = useNavbar()

const router = useRouter()

const mainProgress = inject(progressKey, ref(0))

const abortController = new AbortController()

onUnmounted(() => {
  abortController.abort()
})

async function onSignOut() {
  mainProgress.value += 1
  try {
    const response = await deleteURL<AuthSignoutResponse>(router.apiResolve({ name: "Auth" }).href, abortController.signal, mainProgress)
    if (abortController.signal.aborted) {
      return
    }

    // We increase the progress and never decrease it to wait for browser to do the redirect.
    mainProgress.value += 1

    // We do not use Vue Router to force a server-side request which might return updated cookies
    // or redirect on its own somewhere because of new (or lack thereof) cookies.
    if (response.replace) {
      window.location.replace(response.url)
    } else {
      window.location.assign(response.url)
    }

    if (browserSupportsWebAuthn()) {
      navigator.credentials.preventSilentAccess()
    }

    return
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
  <div
    ref="navbar"
    class="z-30 flex w-full min-h-12 flex-grow gap-x-1 border-b border-slate-400 bg-slate-300 p-1 shadow-md will-change-transform sm:gap-x-4 sm:p-4 sm:pl-0"
    v-bind="navbarAttrs"
  >
    <router-link
      :to="{ name: 'Home' }"
      class="p-1.5 sm:p-0 group -my-1 -ml-1 sm:ml-0 sm:-my-4 border-r border-slate-400 outline-none hover:bg-slate-400 active:bg-slate-200"
    >
      <GlobeAltIcon class="m-1 sm:m-4 sm:h-10 sm:w-10 h-7 w-7 rounded group-focus:ring-2 group-focus:ring-primary-500" />
    </router-link>
    <slot><div class="flex-grow"></div></slot>
    <Button primary type="button" :disabled="mainProgress > 0" @click.prevent="onSignOut">Sign-out</Button>
  </div>
</template>
