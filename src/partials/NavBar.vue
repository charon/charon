<script setup lang="ts">
import type { AuthSignoutRequest, AuthSignoutResponse } from "@/types"

import { GlobeAltIcon } from "@heroicons/vue/24/outline"
import { browserSupportsWebAuthn } from "@simplewebauthn/browser"
import { onBeforeUnmount } from "vue"
import { useI18n } from "vue-i18n"
import { useRouter } from "vue-router"

import { postJSON } from "@/api"
import { accessToken, currentIdentityId, isSignedIn, signIn } from "@/auth"
import Button from "@/components/Button.vue"
import { useNavbar } from "@/navbar"
import { useProgress } from "@/progress"
import { currentAbsoluteURL, redirectServerSide } from "@/utils"

const { t } = useI18n({ useScope: "global" })
const router = useRouter()
const progress = useProgress()

const { attrs: navbarAttrs } = useNavbar()

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
      // We do not call preventSilentAccess during E2E_TESTS because of the issues with headless Chromium.
      // See: https://gitlab.com/charon/charon/-/merge_requests/37#note_2975752650
      // See: https://issues.chromium.org/issues/474377389
      if (browserSupportsWebAuthn() && !import.meta.env.VITE_E2E_TESTS) {
        await navigator.credentials.preventSilentAccess()
      }

      try {
        redirectServerSide(response.location, true, progress)
      } finally {
        // We set these just in case that redirect fails for any reason.
        if (!import.meta.env.VITE_E2E_TESTS) {
          // During testing we do not clear these variables to not trigger reactive effects which can then trigger
          // further logic, e.g., fetching from the backend, which can then, when signout redirect happens, fail and
          // log to the console, which fails tests.
          accessToken.value = ""
          currentIdentityId.value = ""
        }
      }

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
  if (abortController.signal.aborted) {
    return
  }

  await signIn(progress)
}
</script>

<template>
  <!-- useNavbar uses a template ref named "navbar". -->
  <div
    ref="navbar"
    class="z-30 flex min-h-12 w-full grow gap-x-1 border-b border-slate-400 bg-slate-300 p-1 shadow-md will-change-transform sm:gap-x-4 sm:p-4 sm:pl-0"
    v-bind="navbarAttrs"
  >
    <router-link
      id="navbar-link-home"
      :to="{ name: 'Home' }"
      class="group -my-1 -ml-1 border-r border-slate-400 p-1.5 outline-none hover:bg-slate-400 active:bg-slate-200 sm:-my-4 sm:ml-0 sm:p-0"
    >
      <GlobeAltIcon class="m-1 h-7 w-7 rounded-sm group-focus:ring-2 group-focus:ring-primary-500 sm:m-4 sm:h-10 sm:w-10" />
    </router-link>
    <slot><div class="grow"></div></slot>
    <Button v-if="isSignedIn()" id="navbar-button-signout" primary type="button" :progress="progress" @click.prevent="onSignOut">{{
      t("common.buttons.signOut")
    }}</Button>
    <Button v-else id="navbar-button-signin" primary type="button" :progress="progress" @click.prevent="onSignIn">{{ t("common.buttons.signIn") }}</Button>
  </div>
</template>
