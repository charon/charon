<script setup lang="ts">
import type { DeepReadonly } from "vue"

import { useI18n } from "vue-i18n"

import type { CredentialInfo } from "@/types"

import { getProviderNameTitle } from "@/flow.ts"

defineProps<{
  credential: CredentialInfo | DeepReadonly<CredentialInfo>
  url?: string
}>()

const { t } = useI18n({ useScope: "global" })
</script>

<template>
  <div class="flex flex-row items-center justify-between gap-4" :data-url="url">
    <div class="grow">
      <h2 :id="`credentialfull-provider-${credential.id}`" class="text-xl">{{ getProviderNameTitle(t, credential.provider) }}</h2>
      <div class="mt-1 flex flex-row items-center gap-1">
        <span>{{ credential.displayName }}</span>
        <span v-if="credential.verified" class="rounded-xs bg-slate-100 px-1.5 py-0.5 text-sm leading-none text-gray-600 shadow-xs">{{
          t("common.labels.verified")
        }}</span>
      </div>
    </div>
    <slot :credential="credential" />
  </div>
</template>
