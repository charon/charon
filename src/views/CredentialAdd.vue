<script setup lang="ts">
import {
  addEmailCredential,
  addUsernameCredential,
  completeAddPasskeyCredential,
  completeAddPasswordCredential,
  FetchError,
  postJSON,
  startAddPasskeyCredential,
  startAddPasswordCredential,
} from "@/api"
import { isSignedIn } from "@/auth"
import Button from "@/components/Button.vue"
import InputText from "@/components/InputText.vue"
import RadioButton from "@/components/RadioButton.vue"
import siteContext from "@/context"
import Footer from "@/partials/Footer.vue"
import NavBar from "@/partials/NavBar.vue"
import { injectProgress } from "@/progress"
import { browserSupportsWebAuthn, startRegistration } from "@simplewebauthn/browser"
import { computed, onBeforeMount, onBeforeUnmount, ref, watch } from "vue"
import { useI18n } from "vue-i18n"
import { useRouter } from "vue-router"

const { t } = useI18n({ useScope: "global" })
const router = useRouter()
const progress = injectProgress()
const availableProviders = siteContext.providers

const abortController = new AbortController()
const credentialType = ref<"email" | "username" | "password" | "passkey" | "thirdParty" | null>(null)
const error = ref("")

const email = ref("")
const username = ref("")
const password = ref("")
const passwordLabel = ref("")

interface CredentialTypeOption {
  key: string
  label: string
}

function resetOnInteraction() {
  // We reset the error on interaction.
  error.value = ""
}

watch([email, username, password, passwordLabel, credentialType], resetOnInteraction)

function resetForm() {
  credentialType.value = null
  email.value = ""
  username.value = ""
  password.value = ""
  passwordLabel.value = ""
}

onBeforeMount(() => {
  if (!isSignedIn()) {
    router.push({ name: "CredentialList" })
  }
})

onBeforeUnmount(() => {
  abortController.abort()
})

async function addEmail() {
  if (abortController.signal.aborted) {
    return
  }

  error.value = ""

  try {
    const result = await addEmailCredential(router, email.value, abortController, progress)
    if (abortController.signal.aborted) {
      return
    }

    if (result?.success) {
      await router.push({ name: "CredentialList" })
    } else {
      error.value = t("common.errors.unexpected")
    }
  } catch (err) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("CredentialAdd.addEmail", err)
    if (err instanceof FetchError) {
      error.value = err.body || t("common.errors.unexpected")
    } else {
      error.value = `${err}`
    }
  }
}

async function addUsername() {
  if (abortController.signal.aborted) {
    return
  }

  error.value = ""

  try {
    const result = await addUsernameCredential(router, username.value, abortController, progress)
    if (abortController.signal.aborted) {
      return
    }

    if (result?.success) {
      await router.push({ name: "CredentialList" })
    } else {
      error.value = t("common.errors.unexpected")
    }
  } catch (err) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("CredentialAdd.addUsername", err)
    if (err instanceof FetchError) {
      error.value = err.body || t("common.errors.unexpected")
    } else {
      error.value = `${err}`
    }
  }
}

async function addPassword() {
  if (abortController.signal.aborted) {
    return
  }

  error.value = ""

  try {
    const startResponse = await startAddPasswordCredential(router, abortController, progress)
    if (abortController.signal.aborted || !startResponse) {
      return
    }

    const deriveOptions = startResponse.deriveOptions
    const encryptOptions = startResponse.encryptOptions
    const publicKeyBase64 = startResponse.publicKey

    if (!publicKeyBase64 || !deriveOptions || !encryptOptions) {
      throw new Error("missing encryption parameters")
    }

    const publicKeyBytes = Uint8Array.from(atob(publicKeyBase64), (c) => c.charCodeAt(0))
    const remotePublicKey = await crypto.subtle.importKey("raw", publicKeyBytes, deriveOptions, false, [])
    if (abortController.signal.aborted) {
      return null
    }

    const keyPair = await crypto.subtle.generateKey(deriveOptions, false, ["deriveKey"])
    if (abortController.signal.aborted) {
      return null
    }
    const encryptAlgorithm = { name: encryptOptions.name, length: encryptOptions.length }
    const iv = Uint8Array.from(atob(encryptOptions.iv), (c) => c.charCodeAt(0))
    const encryptParams = { name: encryptOptions.name, iv: iv, tagLength: encryptOptions.tagLength }

    const secret = await crypto.subtle.deriveKey({ ...deriveOptions, public: remotePublicKey }, keyPair.privateKey, encryptAlgorithm, false, ["encrypt"])
    if (abortController.signal.aborted) {
      return null
    }

    const encoder = new TextEncoder()
    const ciphertext = await crypto.subtle.encrypt(encryptParams, secret, encoder.encode(password.value))
    if (abortController.signal.aborted) {
      return null
    }

    const publicKeyExport = await crypto.subtle.exportKey("raw", keyPair.publicKey)
    if (abortController.signal.aborted) {
      return null
    }

    const result = await completeAddPasswordCredential(
      router,
      {
        sessionKey: startResponse.sessionKey,
        publicKey: Array.from(new Uint8Array(publicKeyExport)),
        password: Array.from(new Uint8Array(ciphertext)),
        label: passwordLabel.value,
      },
      abortController,
      progress,
    )

    if (abortController.signal.aborted) {
      return
    }

    if (result?.success) {
      await router.push({ name: "CredentialList" })
    } else {
      error.value = t("common.errors.unexpected")
    }
  } catch (err) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("CredentialAdd.addPassword", err)
    if (err instanceof FetchError) {
      error.value = err.body || t("common.errors.unexpected")
    } else {
      error.value = `${err}`
    }
  }
}

async function addPasskey() {
  if (abortController.signal.aborted) {
    return
  }

  error.value = ""

  try {
    if (!browserSupportsWebAuthn()) {
      error.value = t("views.CredentialAdd.passkeyNotSupported")
      return
    }

    const start = await startAddPasskeyCredential(router, abortController, progress)
    if (abortController.signal.aborted || !start) {
      return
    }

    const regResponse = await startRegistration(start.createOptions.publicKey)
    if (abortController.signal.aborted) {
      return
    }

    const result = await completeAddPasskeyCredential(
      router,
      {
        sessionKey: start.sessionKey,
        createResponse: regResponse,
      },
      abortController,
      progress,
    )

    if (abortController.signal.aborted) {
      return
    }

    if (result?.success) {
      await router.push({ name: "CredentialList" })
    } else {
      error.value = t("common.errors.unexpected")
    }
  } catch (err) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("CredentialAdd.addPasskey", err)
    if (err instanceof FetchError) {
      error.value = err.body || t("common.errors.unexpected")
    } else {
      error.value = `${err}`
    }
  }
}

const builtInCredentialTypes = computed<CredentialTypeOption[]>(() => {
  const types: CredentialTypeOption[] = [
    { key: "email", label: t("common.fields.email") },
    { key: "username", label: t("common.fields.username") },
    { key: "password", label: t("views.CredentialList.password") },
  ]

  if (browserSupportsWebAuthn()) {
    types.push({ key: "passkey", label: t("views.CredentialList.passkey") })
  }

  return types
})

const allCredentialTypes = computed<CredentialTypeOption[]>(() => {
  return [...builtInCredentialTypes.value, ...availableProviders.map((p) => ({ key: p.key, label: p.name }))]
})

async function startThirdPartyProvider(providerKey: string) {
  if (abortController.signal.aborted) {
    return
  }

  error.value = ""

  try {
    progress.value += 1

    const url = router.apiResolve({
      name: "CredentialAddThirdPartyProviderStart",
      params: { provider: providerKey },
    }).href

    const response = await postJSON<{ location: string }>(url, {}, abortController.signal, progress)
    if (abortController.signal.aborted) {
      progress.value -= 1
      return
    }

    if (response.location) {
      window.location.href = response.location
    } else {
      error.value = t("common.errors.unexpected")
      progress.value -= 1
    }
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("CredentialAdd.startThirdPartyProvider", error)
    progress.value -= 1
  }
}
</script>

<template>
  <Teleport to="header">
    <NavBar></NavBar>
  </Teleport>
  <div class="w-full flex flex-col items-center mt-12 sm:mt-[4.5rem] border-t border-transparent">
    <div class="grid auto-rows-auto grid-cols-[minmax(0,_65ch)] m-1 sm:m-4 gap-1 sm:gap-4">
      <div class="w-full rounded border bg-white p-4 shadow flex flex-col gap-4">
        <div class="flex flex-row items-center">
          <h1 class="text-2xl font-bold">{{ t("views.CredentialAdd.addCredential") }}</h1>
        </div>
      </div>

      <!-- Credential Type Selection -->
      <div class="w-full rounded border bg-white p-4 shadow">
        <h2 class="text-lg font-semibold mb-4">{{ t("views.CredentialAdd.availableOptions") }}</h2>
        <fieldset>
          <legend class="sr-only">{{ t("views.CredentialAdd.credentialTypes") }}</legend>
          <div class="flex flex-col gap-3">
            <div v-for="type in allCredentialTypes" :key="type.key" class="flex items-center">
              <RadioButton :id="`credential-type-${type.key}`" v-model="credentialType" :value="type.key" :progress="progress" class="mx-2" />
              <label :for="`credential-type-${type.key}`" :class="progress > 0 ? 'cursor-not-allowed text-gray-600' : 'cursor-pointer'">
                {{ type.label }}
              </label>
            </div>
          </div>
        </fieldset>
        <!-- Email Form -->
        <form v-if="credentialType === 'email'" class="flex flex-col mt-6" @submit.prevent="addEmail">
          <label for="email" class="mb-1">{{ t("common.fields.email") }}</label>
          <InputText id="credential-input-email" v-model="email" class="flex-grow flex-auto min-w-0" type="email" :progress="progress" required />
          <div v-if="error" class="mt-4 text-error-600">{{ error }}</div>
          <div class="flex flex-row justify-end gap-4 mt-4">
            <Button type="button" secondary @click="resetForm">{{ t("common.buttons.cancel") }}</Button>
            <Button type="submit" primary :progress="progress">{{ t("common.buttons.add") }}</Button>
          </div>
        </form>
        <!-- Username Form -->
        <form v-if="credentialType === 'username'" class="flex flex-col mt-6" @submit.prevent="addUsername">
          <label for="username" class="mb-1">{{ t("common.fields.username") }}</label>
          <InputText id="credential-input-username" v-model="username" class="flex-grow flex-auto min-w-0" type="text" :progress="progress" required />
          <div v-if="error" class="mt-4 text-error-600">{{ error }}</div>
          <div class="flex flex-row justify-end gap-4 mt-4">
            <Button type="button" secondary @click="resetForm">{{ t("common.buttons.cancel") }}</Button>
            <Button type="submit" primary :progress="progress">{{ t("common.buttons.add") }}</Button>
          </div>
        </form>
        <!-- Password Form -->
        <form v-if="credentialType === 'password'" class="flex flex-col mt-6" @submit.prevent="addPassword">
          <label for="password" class="mb-1">{{ t("views.CredentialList.password") }}</label>
          <InputText id="credential-input-password" v-model="password" class="flex-grow flex-auto min-w-0" type="password" :progress="progress" required />
          <label for="password-label" class="mb-1 mt-4"
            >{{ t("views.CredentialAdd.label") }}<span class="text-neutral-500 italic text-sm">{{ t("common.labels.optional") }}</span></label
          >
          <InputText id="credential-input-passwordlabel" v-model="passwordLabel" class="flex flex-row gap-4 mt-2" type="text" :progress="progress" />
          <div v-if="error" class="mt-4 text-error-600">{{ error }}</div>
          <div class="flex flex-row justify-end gap-4 mt-4">
            <Button type="button" secondary @click="resetForm">{{ t("common.buttons.cancel") }}</Button>
            <Button type="submit" primary :progress="progress">{{ t("common.buttons.add") }}</Button>
          </div>
        </form>
        <!-- Passkey Form -->
        <form v-if="credentialType === 'passkey'" class="flex flex-col mt-6" @submit.prevent="addPasskey">
          <p class="mb-4 mt-2">{{ t("views.CredentialAdd.passkeyInstructions") }}</p>
          <div v-if="error" class="mt-4 text-error-600">{{ error }}</div>
          <div class="flex flex-row justify-end gap-4">
            <Button type="button" secondary @click="resetForm">{{ t("common.buttons.cancel") }}</Button>
            <Button type="submit" primary :progress="progress">{{ t("views.CredentialAdd.addPasskeyButton") }}</Button>
          </div>
        </form>

        <!-- Third-Party Provider Form -->
        <form v-if="availableProviders.some((p) => p.key === credentialType)" class="mt-6" @submit.prevent="startThirdPartyProvider(credentialType!)">
          <div v-if="error" class="mt-4 text-error-600">{{ error }}</div>
          <div class="flex flex-row justify-end gap-4 mt-4">
            <Button type="button" secondary @click="resetForm">
              {{ t("common.buttons.cancel") }}
            </Button>
            <Button type="submit" primary :progress="progress">
              {{ t("common.buttons.add") }}
            </Button>
          </div>
        </form>
      </div>
    </div>
  </div>
  <Teleport to="footer">
    <Footer />
  </Teleport>
</template>
