<script setup lang="ts">
import {
  addEmailCredential,
  addUsernameCredential,
  completeAddPasskeyCredential,
  completeAddPasswordCredential,
  startAddPasskeyCredential,
  startAddPasswordCredential,
} from "@/api"
import { isSignedIn } from "@/auth"
import Button from "@/components/Button.vue"
import InputText from "@/components/InputText.vue"
import RadioButton from "@/components/RadioButton.vue"
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

const abortController = new AbortController()
const credentialType = ref<"email" | "username" | "password" | "passkey" | null>(null)
const error = ref("")

const email = ref("")
const username = ref("")
const password = ref("")
const passwordLabel = ref("")

interface CredentialTypeOption {
  key: string
  label: string
}

function getErrorMessage(errorCode: string) {
  switch (errorCode) {
    case "invalidEmailOrUsername":
      if (credentialType.value === "email") {
        return t("common.errors.invalidEmailOrUsername.email")
      } else if (credentialType.value === "username") {
        return t("common.errors.invalidEmailOrUsername.username")
      }
      return t("common.errors.unexpected")
    case "shortEmailOrUsername":
      if (credentialType.value === "email") {
        return t("common.errors.shortEmailOrUsername.email")
      } else if (credentialType.value === "username") {
        return t("common.errors.shortEmailOrUsername.username")
      }
      return t("common.errors.unexpected")
    case "credentialAlreadyUsed":
      return t("common.errors.credentialAlreadyUsed")
    case "credentialAlreadyExists":
      return t("common.errors.credentialAlreadyExists")
    case "shortPassword":
      return t("common.errors.shortPassword")
    default:
      if (errorCode) {
        console.warn("Unknown error code:", errorCode)
      }
      return t("common.errors.unexpected")
  }
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

  resetOnInteraction()

  try {
    const result = await addEmailCredential(router, email.value, abortController, progress)
    if (abortController.signal.aborted) {
      return
    }

    if (!result) {
      return
    }
    if (!result.success) {
      error.value = getErrorMessage(result.error)
      return
    }

    await router.push({ name: "CredentialList" })
  } catch (err) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("CredentialAdd.addEmail", err)
    error.value = t("common.errors.unexpected")
  }
}

async function addUsername() {
  if (abortController.signal.aborted) {
    return
  }

  resetOnInteraction()

  try {
    const result = await addUsernameCredential(router, username.value, abortController, progress)
    if (abortController.signal.aborted) {
      return
    }

    if (!result) {
      return
    }

    if (!result.success) {
      error.value = getErrorMessage(result.error)
      return
    }

    await router.push({ name: "CredentialList" })
  } catch (err) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("CredentialAdd.addUsername", err)
    error.value = t("common.errors.unexpected")
  }
}

async function addPassword() {
  if (abortController.signal.aborted) {
    return
  }

  resetOnInteraction()

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

    if (!result) {
      return
    }

    if (!result.success) {
      error.value = getErrorMessage(result.error)
      return
    }

    await router.push({ name: "CredentialList" })
  } catch (err) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("CredentialAdd.addPassword", err)
    error.value = t("common.errors.unexpected")
  }
}

async function addPasskey() {
  if (abortController.signal.aborted) {
    return
  }

  resetOnInteraction()

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

    if (!result) {
      return
    }

    if (!result.success) {
      error.value = getErrorMessage(result.error)
      return
    }

    await router.push({ name: "CredentialList" })
  } catch (err) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("CredentialAdd.addPasskey", err)
    error.value = t("common.errors.unexpected")
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
</script>

<template>
  <Teleport to="header">
    <NavBar></NavBar>
  </Teleport>
  <div class="mt-12 flex w-full flex-col items-center border-t border-transparent sm:mt-[4.5rem]">
    <div class="m-1 grid auto-rows-auto grid-cols-[minmax(0,_65ch)] gap-1 sm:m-4 sm:gap-4">
      <div class="flex w-full flex-col gap-4 rounded-sm border border-gray-200 bg-white p-4 shadow-sm">
        <div class="flex flex-row items-center justify-between gap-4">
          <h1 class="text-2xl font-bold">{{ t("views.CredentialAdd.addCredential") }}</h1>
        </div>
      </div>
      <!-- Credential Type Selection -->
      <div class="w-full rounded-sm border border-gray-200 bg-white p-4 shadow-sm">
        <h2 class="mb-4 text-lg font-semibold">{{ t("views.CredentialAdd.availableOptions") }}</h2>
        <fieldset>
          <legend class="sr-only">{{ t("views.CredentialAdd.credentialTypes") }}</legend>
          <div class="flex flex-col gap-3">
            <div v-for="type in builtInCredentialTypes" :key="type.key" class="flex items-center">
              <RadioButton :id="`credentialadd-radio-${type.key}`" v-model="credentialType" :value="type.key" :progress="progress" class="mx-2" />
              <label :for="`credential-type-${type.key}`" :class="progress > 0 ? 'cursor-not-allowed text-gray-600' : 'cursor-pointer'">
                {{ type.label }}
              </label>
            </div>
          </div>
        </fieldset>
        <!-- Email Form -->
        <form v-if="credentialType === 'email'" class="mt-6 flex flex-col" novalidate @submit.prevent="addEmail">
          <label for="credentialadd-input-email" class="mb-1"> {{ t("common.fields.email") }} </label>
          <InputText
            id="credentialadd-input-email"
            v-model="email"
            name="email"
            class="min-w-0 flex-auto grow"
            :progress="progress"
            :invalid="!!error"
            autocomplete="username"
            autocorrect="off"
            autocapitalize="none"
            spellcheck="false"
            type="email"
            minlength="3"
            required
          />
          <div v-if="error" class="mt-4 text-error-600">
            {{ error }}
          </div>
          <div class="mt-4 flex flex-row justify-end gap-4">
            <Button type="button" secondary @click="resetForm">{{ t("common.buttons.cancel") }}</Button>
            <Button type="submit" primary :progress="progress">{{ t("common.buttons.add") }}</Button>
          </div>
        </form>
        <!-- Username Form -->
        <form v-if="credentialType === 'username'" class="mt-6 flex flex-col" novalidate @submit.prevent="addUsername">
          <label for="username" class="mb-1">{{ t("common.fields.username") }}</label>
          <InputText id="credentialadd-input-username" v-model="username" class="min-w-0 flex-auto flex-grow" type="text" :progress="progress" required />
          <div v-if="error" class="mt-4 text-error-600">
            {{ error }}
          </div>
          <div class="mt-4 flex flex-row justify-end gap-4">
            <Button type="button" secondary @click="resetForm">{{ t("common.buttons.cancel") }}</Button>
            <Button type="submit" primary :progress="progress">{{ t("common.buttons.add") }}</Button>
          </div>
        </form>
        <!-- Password Form -->
        <form v-if="credentialType === 'password'" class="mt-6 flex flex-col" novalidate @submit.prevent="addPassword">
          <label for="password" class="mb-1">{{ t("views.CredentialList.password") }}</label>
          <InputText id="credentialadd-input-password" v-model="password" class="min-w-0 flex-auto flex-grow" type="password" :progress="progress" required />
          <label for="password-label" class="mt-4 mb-1"
            >{{ t("views.CredentialAdd.label") }}<span class="text-sm text-neutral-500 italic">{{ t("common.labels.optional") }}</span></label
          >
          <InputText
            id="credentialadd-input-passwordlabel"
            v-model="passwordLabel"
            name="new-password"
            autocomplete="new-password"
            class="mt-2 flex flex-row gap-4"
            type="text"
            :progress="progress"
          />
          <div v-if="error" class="mt-4 text-error-600">
            {{ error }}
          </div>
          <div class="mt-4 flex flex-row justify-end gap-4">
            <Button type="button" secondary @click="resetForm">{{ t("common.buttons.cancel") }}</Button>
            <Button type="submit" primary :progress="progress">{{ t("common.buttons.add") }}</Button>
          </div>
        </form>
        <!-- Passkey Form -->
        <form v-if="credentialType === 'passkey'" class="mt-6 flex flex-col" novalidate @submit.prevent="addPasskey">
          <p class="mt-2 mb-4">{{ t("views.CredentialAdd.passkeyInstructions") }}</p>
          <div v-if="error" class="mt-4 text-error-600">
            {{ error }}
          </div>
          <div class="flex flex-row justify-end gap-4">
            <Button type="button" secondary @click="resetForm">{{ t("common.buttons.cancel") }}</Button>
            <Button type="submit" primary :progress="progress">{{ t("views.CredentialAdd.addPasskeyButton") }}</Button>
          </div>
        </form>
      </div>
    </div>
  </div>
  <Teleport to="footer">
    <Footer />
  </Teleport>
</template>
