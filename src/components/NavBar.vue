<script setup lang="ts">
import type { AuthFlowCreateRequest, AuthFlowCreateResponse, AuthSignoutResponse } from "@/types"

import { onUnmounted, ref, inject } from "vue"
import { useRouter } from "vue-router"
import { browserSupportsWebAuthn } from "@simplewebauthn/browser"
import { GlobeAltIcon } from "@heroicons/vue/24/outline"
import Button from "@/components/Button.vue"
import { useNavbar } from "@/navbar"
import { deleteURL, postURL } from "@/api"
import { progressKey } from "@/progress"
import { redirectServerSide } from "@/utils"
import me from "@/me"

const { ref: navbar, attrs: navbarAttrs } = useNavbar()

const router = useRouter()

const mainProgress = inject(progressKey, ref(0))

const abortController = new AbortController()

onUnmounted(() => {
  abortController.abort()
})

async function onSignOut() {
  if (abortController.signal.aborted) {
    return
  }

  mainProgress.value += 1
  try {
    const response = await deleteURL<AuthSignoutResponse>(router.apiResolve({ name: "Auth" }).href, abortController.signal, mainProgress)
    if (abortController.signal.aborted) {
      return
    }

    redirectServerSide(response.url, response.replace, mainProgress)

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

async function onSignIn() {
  if (abortController.signal.aborted) {
    return
  }

  mainProgress.value += 1
  try {
    const payload: AuthFlowCreateRequest = {
      // We remove origin prefix from full URL to get absolute URL.
      location: document.location.href.slice(document.location.origin.length),
    }
    const url = router.apiResolve({
      name: "AuthFlowCreate",
    }).href

    const response = await postURL<AuthFlowCreateResponse>(url, payload, abortController.signal, mainProgress)
    if (abortController.signal.aborted) {
      return
    }
    if ("error" in response && ["alreadyAuthenticated"].includes(response.error)) {
      // We reload the page to get new "me" state.
      // TODO: Can we update "me" state reactively?
      document.location.reload()
      return
    }
    if ("id" in response) {
      router.push({ name: "AuthFlow", params: { id: response.id } })
      return
    }
    throw new Error("unexpected response")
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    // TODO: Can we do something better?
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
    <Button v-if="me.success" primary type="button" :disabled="mainProgress > 0" @click.prevent="onSignOut">Sign-out</Button>
    <Button v-else primary type="button" :disabled="mainProgress > 0" @click.prevent="onSignIn">Sign-in or sign-up</Button>
  </div>
</template>
