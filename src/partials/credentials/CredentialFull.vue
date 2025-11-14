<script setup lang="ts">
import type { DeepReadonly } from "vue"

import { useI18n } from "vue-i18n"

import { getBuiltInProviderTitleName, getThirdPartyProvider } from "@/flow.ts"
import type { CredentialInfo } from "@/types"

defineProps<{
  credential: CredentialInfo | DeepReadonly<CredentialInfo>
  url?: string
}>()

const { t } = useI18n({ useScope: "global" })

</script>

<template>
  <div class="flex flex-row items-center justify-between gap-4" :data-url="url">
    <div class="grow">
      <h2 v-if="getThirdPartyProvider([credential.provider])" :id="`credentialfull-provider-${credential.id}`" class="text-xl font-semibold">
        {{ t("partials.CredentialFull.thirdPartyProviders") }}
      </h2>
      <h2 v-else-if="credential.provider == 'email' || credential.provider == 'passkey'" :id="`credentialfull-provider-${credential.id}`" class="text-xl font-semibold">
        {{ getBuiltInProviderTitleName(t, credential.provider) }}
      </h2>
      <h2 v-else :id="`credentialfull-provider-${credential.id}`" class="text-xl">
        {{ getBuiltInProviderTitleName(t, credential.provider) }}
      </h2>

      <!-- Email with verification. -->
      <div v-if="credential.provider === 'email'" class="mt-2">
        <div :id="`credentialfull-display-${credential.id}`" class="font-medium">
          {{ credential.displayName }}
          <span :id="`credentialfull-verified-${credential.id}`" class="rounded-xs bg-slate-100 px-1.5 py-0.5 text-sm leading-none text-gray-600 shadow-xs">
            {{ credential.verified ? t("common.labels.verified") : t("common.labels.notVerified") }}
          </span>
        </div>
      </div>

      <!-- Built-in providers. -->
      <div v-else-if="!getThirdPartyProvider([credential.provider])" class="mt-2">
        <div :id="`credentialfull-display-${credential.id}`" class="font-medium">{{ credential.displayName }}</div>
      </div>

      <!-- Third-party providers. -->
      <div v-else class="mt-2">
        <div :id="`credentialfull-providerkey-${credential.id}`">{{ credential.provider }}</div>
        <div :id="`credentialfull-display-${credential.id}`">{{ credential.displayName }}</div>
      </div>
    </div>

    <div class="flex gap-2">
      <slot :credential="credential" />
    </div>
  </div>
</template>
