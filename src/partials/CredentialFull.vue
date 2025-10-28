<script setup lang="ts">
import type { DeepReadonly } from "vue"

import type { CredentialInfo } from "@/types"

import { computed } from "vue"
import { useI18n } from "vue-i18n"

const props = defineProps<{
  credential: CredentialInfo | DeepReadonly<CredentialInfo>
  url?: string
}>()

const { t } = useI18n({ useScope: "global" })

const isBuiltInProvider = computed(() => ["email", "username", "password", "passkey"].includes(props.credential.provider))

const providerDisplayName = computed(() => {
  const map: Record<string, string> = {
    email: t("common.fields.email"),
    username: t("common.fields.username"),
    password: t("views.CredentialList.password"),
    passkey: t("views.CredentialList.passkey"),
  }
  return map[props.credential.provider] || props.credential.provider
})

const credentialDisplay = computed(() => {
  if (props.credential.provider === "password") {
    return props.credential.label || t("views.CredentialList.passwordDefault")
  }
  return props.credential.displayName
})
</script>

<template>
  <div class="flex flex-row items-center justify-between gap-4" :data-url="url">
    <div class="flex-grow">
      <h2 v-if="!isBuiltInProvider" :id="`credentialfull-provider-${credential.id}`" class="text-xl font-semibold">
        {{ t("views.CredentialList.thirdPartyProviders") }}
      </h2>
      <h2 v-else :id="`credentialfull-provider-${credential.id}`" class="text-xl font-semibold">
        {{ providerDisplayName }}
      </h2>

      <!-- Email with verification. -->
      <div v-if="credential.provider === 'email'" class="mt-2">
        <div :id="`credentialfull-display-${credential.id}`" class="font-medium">
          {{ credential.displayName }}
          <span :id="`credentialfull-verified-${credential.id}`" class="ml-1 inline-block border border-gray-600 px-2">
            {{ credential.verified ? t("views.CredentialList.verified") : t("views.CredentialList.notVerified") }}
          </span>
        </div>
      </div>

      <!-- Third-party providers. -->
      <div v-else-if="!isBuiltInProvider" class="mt-2">
        <div :id="`credentialfull-providerkey-${credential.id}`">{{ credential.provider }}</div>
        <div :id="`credentialfull-display-${credential.id}`">{{ credentialDisplay }}</div>
      </div>

      <!-- Built-in providers. -->
      <div v-else class="mt-2">
        <div :id="`credentialfull-display-${credential.id}`" class="font-medium">{{ credentialDisplay }}</div>
      </div>
    </div>

    <div class="flex gap-2">
      <slot :credential="credential" />
    </div>
  </div>
</template>
