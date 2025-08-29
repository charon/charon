<script setup lang="ts">
import type { AuthSignoutRequest, AuthSignoutResponse } from "@/types"

import { onBeforeUnmount } from "vue"
import { useRouter } from "vue-router"
import { useI18n } from "vue-i18n"
import { browserSupportsWebAuthn } from "@simplewebauthn/browser"
import { GlobeAltIcon } from "@heroicons/vue/24/outline"
import Button from "@/components/Button.vue"
import { useNavbar } from "@/navbar"
import { postJSON } from "@/api"
import { injectProgress } from "@/progress"
import { currentAbsoluteURL, redirectServerSide } from "@/utils"
import { accessToken, signIn, isSignedIn } from "@/auth"

const { t } = useI18n({ useScope: "global" })
const router = useRouter()
const progress = injectProgress()
const { ref: navbar, attrs: navbarAttrs } = useNavbar()

const abortController = new AbortController()

onBeforeUnmount(() => {
  abortController.abort()
})

async function onSignOut() {
  if (abortController.signal.aborted) {
    return
  }

  progress.value += 1
  try {
    const payload: AuthSignoutRequest = {
      location: currentAbsoluteURL(),
    }
    const url = router.apiResolve({
      name: "AuthSignout",
    }).href

    const response = await postJSON<AuthSignoutResponse>(url, payload, abortController.signal, progress)
    if (abortController.signal.aborted) {
      return
    }

    if ("location" in response) {
      if (browserSupportsWebAuthn()) {
        navigator.credentials.preventSilentAccess()
      }

      accessToken.value = ""

      redirectServerSide(response.location, true, progress)

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
    progress.value -= 1
  }
}

async function onSignIn() {
  await signIn(progress)
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
    <Button v-if="isSignedIn()" primary type="button" :progress="progress" @click.prevent="onSignOut">{{ t("common.buttons.signOut") }}</Button>
    <Button v-else primary type="button" :progress="progress" @click.prevent="onSignIn">{{ t("common.buttons.signIn") }}</Button>
  </div>
</template>
