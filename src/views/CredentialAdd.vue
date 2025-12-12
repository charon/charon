<script setup lang="ts">
import type { Component } from "vue"

import { browserSupportsWebAuthn } from "@simplewebauthn/browser"
import { ref } from "vue"
import { useI18n } from "vue-i18n"

import RadioButton from "@/components/RadioButton.vue"
import CredentialAddEmail from "@/partials/credentials/CredentialAddEmail.vue"
import CredentialAddPasskey from "@/partials/credentials/CredentialAddPasskey.vue"
import CredentialAddPassword from "@/partials/credentials/CredentialAddPassword.vue"
import CredentialAddUsername from "@/partials/credentials/CredentialAddUsername.vue"
import Footer from "@/partials/Footer.vue"
import NavBar from "@/partials/NavBar.vue"
import { useProgress } from "@/progress"

const { t } = useI18n({ useScope: "global" })
const progress = useProgress()

const credentials = [
  { key: "email", label: t("common.providers.emailTitle"), component: CredentialAddEmail },
  { key: "username", label: t("common.providers.usernameTitle"), component: CredentialAddUsername },
  { key: "password", label: t("common.providers.passwordTitle"), component: CredentialAddPassword },
]

if (browserSupportsWebAuthn()) {
  credentials.push({ key: "passkey", label: t("common.providers.passkeyTitle"), component: CredentialAddPasskey })
}

const credentialType = ref<string | null>(null)

function getComponent(key: string): Component {
  return credentials.find((c) => c.key === key)!.component
}
</script>

<template>
  <Teleport to="header">
    <NavBar></NavBar>
  </Teleport>
  <div class="mt-12 flex w-full flex-col items-center border-t border-transparent sm:mt-[4.5rem]">
    <div class="m-1 grid auto-rows-auto grid-cols-[minmax(0,65ch)] gap-1 sm:m-4 sm:gap-4">
      <div class="flex w-full flex-col gap-4 rounded-sm border border-gray-200 bg-white p-4 shadow-sm">
        <div class="flex flex-row items-center justify-between gap-4">
          <h1 class="text-2xl font-bold">{{ t("views.CredentialAdd.addCredential") }}</h1>
        </div>
      </div>
      <!-- Credential type selection. -->
      <div class="w-full rounded-sm border border-gray-200 bg-white p-4 shadow-sm">
        <fieldset>
          <legend class="mb-1">{{ t("views.CredentialAdd.availableOptions") }}</legend>
          <div class="grid auto-rows-auto grid-cols-[max-content_auto] gap-x-1">
            <template v-for="type in credentials" :key="type.key">
              <RadioButton :id="`credentialadd-radio-${type.key}`" v-model="credentialType" :value="type.key" :progress="progress" class="mx-2" />
              <label :for="`credentialadd-radio-${type.key}`" :class="progress > 0 ? 'cursor-not-allowed text-gray-600' : 'cursor-pointer'">{{ type.label }}</label>
            </template>
          </div>
        </fieldset>
      </div>
      <div v-if="credentialType" class="w-full rounded-sm border border-gray-200 bg-white p-4 shadow-sm">
        <component :is="getComponent(credentialType)" />
      </div>
    </div>
  </div>
  <Teleport to="footer">
    <Footer />
  </Teleport>
</template>
