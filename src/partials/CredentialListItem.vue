<script setup lang="ts">
import type { DeepReadonly } from "vue"

import type { CredentialInfo } from "@/types"

import Button from "@/components/Button.vue"
import { injectProgress } from "@/progress"
import { useI18n } from "vue-i18n"

const { t } = useI18n({ useScope: "global" })
const progress = injectProgress()

defineProps<{
  credential: CredentialInfo | DeepReadonly<CredentialInfo>
  removing: boolean
}>()

const emit = defineEmits<{
  remove: [credentialId: string]
}>()

function getProviderDisplayName(provider: string): string {
  switch (provider) {
    case "email":
      return t("common.fields.email")
    case "username":
      return t("common.fields.username")
    case "password":
      return t("views.CredentialList.password")
    case "passkey":
      return t("views.CredentialList.passkey")
    default:
      return provider
  }
}

function getCredentialDisplay(credential: CredentialInfo): string {
  if (credential.provider === "password") {
    return credential.label || t("views.CredentialList.passwordDefault")
  }
  return credential.displayName
}
</script>

<template>
  <div class="w-full rounded border border-gray-200 bg-white p-4 shadow">
    <div class="flex flex-row justify-between items-center gap-4">
      <div class="flex-grow">
        <h2
          v-if="credential.provider !== 'email' && credential.provider != 'username' && credential.provider != 'password' && credential.provider != 'passkey'"
          class="text-lg font-semibold"
        >
          {{ t("views.CredentialList.thirdPartyProviders") }}
        </h2>
        <h2 v-else class="text-lg font-semibold">{{ getProviderDisplayName(credential.provider) }}</h2>
        <div v-if="credential.provider === 'email'" class="mt-2">
          <div class="font-medium">
            {{ credential.displayName }}
            <span class="inline-block border border-gray-600 px-2 ml-1">
              {{ credential.verified ? t("views.CredentialList.verified") : t("views.CredentialList.notVerified") }}
            </span>
          </div>
        </div>
        <div
          v-else-if="credential.provider !== 'email' && credential.provider !== 'username' && credential.provider !== 'password' && credential.provider !== 'passkey'"
          class="mt-2"
        >
          <div>{{ credential.provider }}</div>
          <div>{{ getCredentialDisplay(credential) }}</div>
        </div>
        <div v-else class="mt-2">
          <div class="font-medium">{{ getCredentialDisplay(credential) }}</div>
        </div>
      </div>
      <div class="flex gap-2">
        <Button v-if="credential.provider === 'email'" type="button" secondary disabled class="text-sm">
          {{ t("views.CredentialList.verify") }}
        </Button>
        <Button type="button" :progress="progress" :disabled="removing" class="text-error-600 hover:text-error-700" @click="emit('remove', credential.id)">
          {{ t("common.buttons.remove") }}
        </Button>
      </div>
    </div>
  </div>
</template>
