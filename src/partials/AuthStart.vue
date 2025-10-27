<script setup lang="ts">
import type { Flow } from "@/types"

import { browserSupportsWebAuthn } from "@simplewebauthn/browser"
import { computed, getCurrentInstance, onBeforeUnmount, onMounted, ref, watch } from "vue"
import { useI18n } from "vue-i18n"
import { useRouter } from "vue-router"

import { startPassword } from "@/api"
import Button from "@/components/Button.vue"
import InputText from "@/components/InputText.vue"
import siteContext from "@/context"
import { getThirdPartyProvider } from "@/flow"
import { injectProgress } from "@/progress"
import { isEmail } from "@/utils"

const props = defineProps<{
  flow: Flow
}>()

const { t } = useI18n({ useScope: "global" })
const router = useRouter()
const progress = injectProgress()

const abortController = new AbortController()
const passwordError = ref("")
const unexpectedError = ref("")

function resetOnInteraction() {
  // We reset errors on interaction.
  passwordError.value = ""
  unexpectedError.value = ""
}

watch(() => props.flow.getEmailOrUsername(), resetOnInteraction)

// A proxy so that we can pass it as v-model.
const emailOrUsernameProxy = computed({
  get() {
    return props.flow.getEmailOrUsername()
  },
  set(v: string) {
    if (abortController.signal.aborted) {
      return
    }

    // We do not call resetOnInteraction here because we are using watch to
    // watch props.emailOrUsername which does so, which is the same pattern
    // we are using elsewhere (even when not using writable computed refs).

    props.flow.setEmailOrUsername(v)
  },
})

// Define transition hooks to be called by the parent component.
// See: https://github.com/vuejs/rfcs/discussions/613
onMounted(() => {
  const vm = getCurrentInstance()!
  vm.vnode.el!.__vue_exposed = vm.exposeProxy
})

defineExpose({
  onAfterEnter,
  onBeforeLeave,
})

onBeforeUnmount(onBeforeLeave)

function onAfterEnter() {
  document.getElementById("email")?.focus()
}

function onBeforeLeave() {
  abortController.abort()
}

async function onNext() {
  if (abortController.signal.aborted) {
    return
  }

  resetOnInteraction()

  progress.value += 1
  try {
    const response = await startPassword(router, props.flow, abortController, progress, progress)
    if (abortController.signal.aborted || !response) {
      return
    }
    if ("error" in response) {
      passwordError.value = response.error
      return
    }

    props.flow.setPublicKey(response.publicKey)
    props.flow.setDeriveOptions(response.deriveOptions)
    props.flow.setEncryptOptions(response.encryptOptions)
    props.flow.forward("password")
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("AuthStart.onBeforeLeave", error)
    unexpectedError.value = `${error}`
  } finally {
    progress.value -= 1
  }
}

async function onPasskey() {
  if (abortController.signal.aborted) {
    return
  }

  props.flow.forward("passkeySignin")
}

async function onThirdPartyProvider(provider: string) {
  if (abortController.signal.aborted) {
    return
  }

  const p = getThirdPartyProvider([provider])
  if (!p) {
    // This should not happen.
    throw new Error(`unknown third party provider: ${provider}`)
  }
  props.flow.setThirdPartyProvider(p)
  props.flow.forward("thirdPartyProvider")
}
</script>

<template>
  <div class="flex flex-col rounded-xs border border-gray-200 bg-white p-4 shadow-sm w-full">
    <div class="flex flex-col">
      <label for="authstart-input-email" class="mb-1">{{ t("partials.AuthStart.emailOrUsernameLabel") }}</label>
      <!--
        We set novalidate because we do not UA to show hints.
        We show them ourselves when we want them.
      -->
      <form class="flex flex-row gap-4" novalidate @submit.prevent="onNext">
        <InputText
          id="authstart-input-email"
          v-model="emailOrUsernameProxy"
          name="email"
          class="grow flex-auto min-w-0"
          :progress="progress"
          :invalid="!!passwordError"
          autocomplete="username"
          autocorrect="off"
          autocapitalize="none"
          spellcheck="false"
          type="email"
          minlength="3"
          required
        />
        <!--
          Here we enable button when emailOrUsername is not empty because we do not tell users
          what is expected upfront. If they try a too short emailOrUsername we will tell them.
          We prefer this so that they do not wonder why the button is not enabled.
          We also prefer this because we do not want to do full emailOrUsername normalization on the
          client side so we might be counting characters differently here, leading to confusion.
          Button is on purpose not disabled on unexpectedError so that user can retry.
        -->
        <Button id="authstart-button-next" primary type="submit" :disabled="!flow.getEmailOrUsername().trim() || !!passwordError" :progress="progress">{{
          t("common.buttons.next")
        }}</Button>
      </form>
      <div v-if="passwordError === 'invalidEmailOrUsername'" class="mt-4 text-error-600">
        {{ isEmail(flow.getEmailOrUsername()) ? t("common.errors.invalidEmailOrUsername.email") : t("common.errors.invalidEmailOrUsername.username") }}
      </div>
      <div v-else-if="passwordError === 'shortEmailOrUsername'" class="mt-4 text-error-600">
        {{ isEmail(flow.getEmailOrUsername()) ? t("common.errors.shortEmailOrUsername.email") : t("common.errors.shortEmailOrUsername.username") }}
      </div>
      <div v-else-if="unexpectedError" class="mt-4 text-error-600">{{ t("common.errors.unexpected") }}</div>
    </div>
    <h2 class="text-center m-4 text-xl font-bold uppercase">{{ t("partials.AuthStart.orUse") }}</h2>
    <Button primary type="button" :disabled="!browserSupportsWebAuthn()" :progress="progress" @click.prevent="onPasskey">Passkey</Button>
    <Button v-for="p in siteContext.providers" :key="p.key" primary type="button" class="mt-4" :progress="progress" @click.prevent="onThirdPartyProvider(p.key)">{{
      p.name
    }}</Button>
  </div>
</template>
