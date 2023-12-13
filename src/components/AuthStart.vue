<script setup lang="ts">
import type { DeriveOptions, EncryptOptions, Providers } from "@/types"
import { ref, computed, watch, onUnmounted, onMounted, getCurrentInstance, inject } from "vue"
import { useRouter } from "vue-router"
import { browserSupportsWebAuthn } from "@simplewebauthn/browser"
import Button from "@/components/Button.vue"
import InputText from "@/components/InputText.vue"
import { startPassword } from "@/api"
import { flowKey } from "@/utils"

const props = defineProps<{
  id: string
  providers: Providers
  emailOrUsername: string
  publicKey: Uint8Array
  deriveOptions: DeriveOptions
  encryptOptions: EncryptOptions
  provider: string
}>()

const router = useRouter()

const flow = inject(flowKey)

const abortController = new AbortController()
const mainProgress = ref(0)
const passwordError = ref("")

const isEmail = computed(() => {
  return props.emailOrUsername.indexOf("@") >= 0
})

watch(
  () => props.emailOrUsername,
  () => {
    // We reset the error when input box value changes.
    passwordError.value = ""
  },
)

// A proxy so that we can pass it as v-model.
const emailOrUsernameProxy = computed({
  get() {
    return props.emailOrUsername
  },
  set(v: string) {
    flow!.updateEmailOrUsername(v)
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

onUnmounted(onBeforeLeave)

function onAfterEnter() {
  document.getElementById("email-or-username")?.focus()
}

function onBeforeLeave() {
  abortController.abort()
}

async function onNext() {
  if (abortController.signal.aborted) {
    return
  }

  mainProgress.value += 1
  try {
    const response = await startPassword(router, props.id, props.emailOrUsername, flow!, abortController.signal, mainProgress, mainProgress)
    if (abortController.signal.aborted) {
      return
    }
    if (response === null) {
      return
    }
    if ("error" in response) {
      passwordError.value = response.error
      return
    }

    flow!.updateEmailOrUsername(response.emailOrUsername)
    flow!.updatePublicKey(response.publicKey)
    flow!.updateDeriveOptions(response.deriveOptions)
    flow!.updateEncryptOptions(response.encryptOptions)
    flow!.forward("password")
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    throw error
  } finally {
    mainProgress.value -= 1
  }
}

async function onPasskey() {
  if (abortController.signal.aborted) {
    return
  }

  flow!.forward("passkeySignin")
}

async function onOIDCProvider(provider: string) {
  if (abortController.signal.aborted) {
    return
  }

  flow!.updateProvider(provider)
  flow!.forward("oidcProvider")
}
</script>

<template>
  <div class="flex flex-col rounded border bg-white p-4 shadow w-full float-left first:ml-0 ml-[-100%]">
    <h2 class="text-center mx-4 mb-4 text-xl font-bold uppercase">Sign-in or sign-up</h2>
    <div class="flex flex-col">
      <label for="email-or-username" class="mb-1">Enter Charon username or your e-mail address</label>
      <!--
        We set novalidate because we do not UA to show hints.
        We show them ourselves when we want them.
      -->
      <form class="flex flex-row" novalidate @submit.prevent="onNext">
        <InputText
          id="email-or-username"
          v-model="emailOrUsernameProxy"
          class="flex-grow flex-auto min-w-0"
          :readonly="mainProgress > 0"
          :invalid="!!passwordError"
          autocomplete="username"
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
        -->
        <Button primary type="submit" class="ml-4" :disabled="emailOrUsername.trim().length === 0 || mainProgress > 0 || !!passwordError">Next</Button>
      </form>
      <div v-if="passwordError === 'invalidEmailOrUsername' && isEmail" class="mt-4 text-error-600">Invalid e-mail address.</div>
      <div v-else-if="passwordError === 'invalidEmailOrUsername' && !isEmail" class="mt-4 text-error-600">Invalid username.</div>
      <div v-if="passwordError === 'shortEmailOrUsername' && isEmail" class="mt-4 text-error-600">E-mail address should be at least 3 characters.</div>
      <div v-else-if="passwordError === 'shortEmailOrUsername' && !isEmail" class="mt-4 text-error-600">Username should be at least 3 characters.</div>
    </div>
    <h2 class="text-center m-4 text-xl font-bold uppercase">Or use</h2>
    <Button primary type="button" :disabled="!browserSupportsWebAuthn() || mainProgress > 0" @click.prevent="onPasskey">Passkey</Button>
    <Button v-for="p of providers" :key="p.key" primary type="button" class="mt-4" :disabled="mainProgress > 0" @click.prevent="onOIDCProvider(p.key)">{{
      p.name
    }}</Button>
  </div>
</template>
