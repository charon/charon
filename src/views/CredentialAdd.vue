<script setup lang="ts">
import { computed, onBeforeMount, onBeforeUnmount, Ref, ref, watch } from "vue"
import { useI18n } from "vue-i18n"

import { isSignedIn } from "@/auth.ts"
import RadioButton from "@/components/RadioButton.vue"
import CredentialAddEmail from "@/partials/credentials/CredentialAddEmail.vue"
import CredentialAddPasskey from "@/partials/credentials/CredentialAddPasskey.vue"
import CredentialAddPassword from "@/partials/credentials/CredentialAddPassword.vue"
import CredentialAddUsername from "@/partials/credentials/CredentialAddUsername.vue"
import Footer from "@/partials/Footer.vue"
import NavBar from "@/partials/NavBar.vue"
import { injectProgress } from "@/progress"
import { browserSupportsWebAuthn } from "@simplewebauthn/browser"

const { t } = useI18n({ useScope: "global" })
const progress = injectProgress()

const abortController = new AbortController()
const credentialType = ref<"email" | "username" | "password" | "passkey" | null>(null)
const unexpectedError = ref("")

const credentialTypeObject = {
  email: CredentialAddEmail,
  username: CredentialAddUsername,
  password: CredentialAddPassword,
  passkey: CredentialAddPasskey,
}

const credentialTypeComponent = computed(() => {
  if (!credentialType.value) {
    return null
  }
  return credentialTypeObject[credentialType.value]
})

interface CredentialTypeOption {
  key: string
  label: string
}

function resetOnInteraction() {
  // We reset the error on interaction.
  unexpectedError.value = ""
}

watch([credentialType], resetOnInteraction)

onBeforeUnmount(() => {
  abortController.abort()
})

onBeforeMount(async () => {
  progress.value += 1
  if (!isSignedIn()) {
    unexpectedError.value = t("common.errors.unexpected")
  }
  progress.value -= 1
})

const types: Ref<CredentialTypeOption[]> = ref([
  { key: "email", label: t("common.providers.emailTitle") },
  { key: "username", label: t("common.providers.usernameTitle") },
  { key: "password", label: t("common.providers.passwordTitle") },
])

const builtInCredentialTypes = computed<CredentialTypeOption[]>(() => {
  const clone = [...types.value]

  if (browserSupportsWebAuthn()) {
    clone.push({ key: "passkey", label: t("common.providers.passkeyTitle") })
  }

  return clone
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
      <div v-if="unexpectedError" class="w-full rounded-sm border border-gray-200 bg-white p-4 text-error-600 shadow-sm">{{ t("common.errors.unexpected") }}</div>
      <!-- Credential Type Selection -->
      <div v-else class="w-full rounded-sm border border-gray-200 bg-white p-4 shadow-sm">
        <h2 class="mb-4 text-lg font-semibold">{{ t("views.CredentialAdd.availableOptions") }}</h2>
        <fieldset>
          <legend class="sr-only">{{ t("views.CredentialAdd.credentialTypes") }}</legend>
          <div class="flex flex-col gap-3">
            <div v-for="type in builtInCredentialTypes" :key="type.key" class="flex items-center">
              <RadioButton :id="`credentialadd-radio-${type.key}`" v-model="credentialType" :value="type.key" :progress="progress" class="mx-2" />
              <label :for="`credentialadd-radio-${type.key}`" :class="progress > 0 ? 'cursor-not-allowed text-gray-600' : 'cursor-pointer'">
                {{ type.label }}
              </label>
            </div>
          </div>
        </fieldset>
      </div>
      <div v-if="credentialType" class="flex w-full flex-col gap-4 rounded-sm border border-gray-200 bg-white p-4 shadow-sm">
        <component :is="credentialTypeComponent" v-if="credentialTypeComponent"></component>
      </div>
    </div>
  </div>
  <Teleport to="footer">
    <Footer />
  </Teleport>
</template>
