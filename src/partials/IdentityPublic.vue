<script setup lang="ts">
import type { DeepReadonly } from "vue"

import type { IdentityPublic } from "@/types"

import { useI18n } from "vue-i18n"

defineProps<{
  identity: IdentityPublic | DeepReadonly<IdentityPublic>
  url?: string
  isCurrent?: boolean
  canUpdate?: boolean
  labels?: string[]
}>()

const { t } = useI18n({ useScope: "global" })
</script>

<template>
  <div class="flex flex-row gap-4" :data-url="url">
    <div v-if="identity.pictureUrl" class="flex-none">
      <img :src="identity.pictureUrl" :alt="t('common.accessibility.picture')" class="h-20 w-20 rounded-xs ring-2 ring-white" />
    </div>
    <div class="flex grow flex-col">
      <!--
        This should be similar in what is show as main piece of information in getIdentityDisplayName utility function.
        Keep it in sync with to IdentityFull component, too.
      -->
      <h2 v-if="identity.username" class="text-xl">
        <ul v-if="canUpdate || isCurrent || labels?.length" class="float-right flex flex-row flex-wrap content-start items-start gap-1 text-sm">
          <li v-for="label in labels || []" :key="label" class="rounded-xs bg-slate-100 px-1.5 py-0.5 text-sm leading-none text-gray-600 shadow-xs">{{ label }}</li>
          <li v-if="isCurrent" class="rounded-xs bg-slate-100 px-1.5 py-0.5 leading-none text-gray-600 shadow-xs">{{ t("common.labels.current") }}</li>
          <li v-if="canUpdate" class="rounded-xs bg-slate-100 px-1.5 py-0.5 leading-none text-gray-600 shadow-xs">{{ t("common.labels.admin") }}</li>
        </ul>
        {{ identity.username }}
        <span v-if="identity.email"> ({{ identity.email }})</span>
      </h2>
      <h2 v-else-if="identity.email" class="text-xl">
        <ul v-if="canUpdate || isCurrent || labels?.length" class="float-right flex flex-row flex-wrap content-start items-start gap-1 text-sm">
          <li v-for="label in labels || []" :key="label" class="rounded-xs bg-slate-100 px-1.5 py-0.5 text-sm leading-none text-gray-600 shadow-xs">{{ label }}</li>
          <li v-if="isCurrent" class="rounded-xs bg-slate-100 px-1.5 py-0.5 leading-none text-gray-600 shadow-xs">{{ t("common.labels.current") }}</li>
          <li v-if="canUpdate" class="rounded-xs bg-slate-100 px-1.5 py-0.5 leading-none text-gray-600 shadow-xs">{{ t("common.labels.admin") }}</li>
        </ul>
        {{ identity.email }}
      </h2>
      <h2 v-else-if="identity.givenName" class="text-xl">
        <ul v-if="canUpdate || isCurrent || labels?.length" class="float-right flex flex-row flex-wrap content-start items-start gap-1 text-sm">
          <li v-for="label in labels || []" :key="label" class="rounded-xs bg-slate-100 px-1.5 py-0.5 text-sm leading-none text-gray-600 shadow-xs">{{ label }}</li>
          <li v-if="isCurrent" class="rounded-xs bg-slate-100 px-1.5 py-0.5 leading-none text-gray-600 shadow-xs">{{ t("common.labels.current") }}</li>
          <li v-if="canUpdate" class="rounded-xs bg-slate-100 px-1.5 py-0.5 leading-none text-gray-600 shadow-xs">{{ t("common.labels.admin") }}</li>
        </ul>
        {{ identity.givenName }}
        <span v-if="identity.fullName"> ({{ identity.fullName }})</span>
      </h2>
      <h2 v-else-if="identity.fullName" class="text-xl">
        <ul v-if="canUpdate || isCurrent || labels?.length" class="float-right flex flex-row flex-wrap content-start items-start gap-1 text-sm">
          <li v-for="label in labels || []" :key="label" class="rounded-xs bg-slate-100 px-1.5 py-0.5 text-sm leading-none text-gray-600 shadow-xs">{{ label }}</li>
          <li v-if="isCurrent" class="rounded-xs bg-slate-100 px-1.5 py-0.5 leading-none text-gray-600 shadow-xs">{{ t("common.labels.current") }}</li>
          <li v-if="canUpdate" class="rounded-xs bg-slate-100 px-1.5 py-0.5 leading-none text-gray-600 shadow-xs">{{ t("common.labels.admin") }}</li>
        </ul>
        {{ identity.fullName }}
      </h2>
      <div v-else-if="canUpdate || isCurrent || labels?.length">
        <ul class="float-right flex flex-row flex-wrap content-start items-start gap-1 text-sm">
          <li v-for="label in labels || []" :key="label" class="rounded-xs bg-slate-100 px-1.5 py-0.5 text-sm leading-none text-gray-600 shadow-xs">{{ label }}</li>
          <li v-if="isCurrent" class="rounded-xs bg-slate-100 px-1.5 py-0.5 leading-none text-gray-600 shadow-xs">{{ t("common.labels.current") }}</li>
          <li v-if="canUpdate" class="rounded-xs bg-slate-100 px-1.5 py-0.5 leading-none text-gray-600 shadow-xs">{{ t("common.labels.admin") }}</li>
        </ul>
      </div>
      <div v-if="identity.givenName && (identity.username || identity.email)" class="mt-1">
        {{ identity.givenName }}
        <span v-if="identity.fullName"> ({{ identity.fullName }})</span>
      </div>
      <div v-else-if="identity.fullName && (identity.username || identity.email)" class="mt-1">
        {{ identity.fullName }}
      </div>
    </div>
    <slot :identity="identity" :is-current="isCurrent" :can-update="canUpdate"></slot>
  </div>
</template>
