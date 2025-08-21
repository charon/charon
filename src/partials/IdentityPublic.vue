<script setup lang="ts">
import type { IdentityPublic } from "@/types"
import type { DeepReadonly } from "vue"

import { useI18n } from "vue-i18n"

const { t } = useI18n({ useScope: 'global' })

defineProps<{
  identity: IdentityPublic | DeepReadonly<IdentityPublic>
  url?: string
  isCurrent?: boolean
  canUpdate?: boolean
  labels?: string[]
}>()
</script>

<template>
  <div class="flex flex-row gap-4" :data-url="url">
    <div v-if="identity.pictureUrl" class="flex-none">
      <img :src="identity.pictureUrl" alt="picture" class="h-20 w-20 ring-2 ring-white rounded" />
    </div>
    <div class="flex-grow flex flex-col">
      <h2 v-if="identity.username" class="text-xl">
        <ul v-if="canUpdate || isCurrent || labels?.length" class="flex flex-row flex-wrap content-start items-start gap-1 text-sm float-right">
          <li v-for="label in labels || []" :key="label" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm text-sm leading-none">{{ label }}</li>
          <li v-if="isCurrent" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm leading-none">{{ t("labels.current") }}</li>
          <li v-if="canUpdate" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm leading-none">{{ t("labels.admin") }}</li>
        </ul>
        {{ identity.username }}
        <span v-if="identity.email"> ({{ identity.email }})</span>
      </h2>
      <h2 v-else-if="identity.email" class="text-xl">
        <ul v-if="canUpdate || isCurrent || labels?.length" class="flex flex-row flex-wrap content-start items-start gap-1 text-sm float-right">
          <li v-for="label in labels || []" :key="label" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm text-sm leading-none">{{ label }}</li>
          <li v-if="isCurrent" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm leading-none">{{ t("labels.current") }}</li>
          <li v-if="canUpdate" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm leading-none">{{ t("labels.admin") }}</li>
        </ul>
        {{ identity.email }}
      </h2>
      <h2 v-else-if="identity.givenName" class="text-xl">
        <ul v-if="canUpdate || isCurrent || labels?.length" class="flex flex-row flex-wrap content-start items-start gap-1 text-sm float-right">
          <li v-for="label in labels || []" :key="label" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm text-sm leading-none">{{ label }}</li>
          <li v-if="isCurrent" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm leading-none">{{ t("labels.current") }}</li>
          <li v-if="canUpdate" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm leading-none">{{ t("labels.admin") }}</li>
        </ul>
        {{ identity.givenName }}
        <span v-if="identity.fullName"> ({{ identity.fullName }})</span>
      </h2>
      <h2 v-else-if="identity.fullName" class="text-xl">
        <ul v-if="canUpdate || isCurrent || labels?.length" class="flex flex-row flex-wrap content-start items-start gap-1 text-sm float-right">
          <li v-for="label in labels || []" :key="label" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm text-sm leading-none">{{ label }}</li>
          <li v-if="isCurrent" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm leading-none">{{ t("labels.current") }}</li>
          <li v-if="canUpdate" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm leading-none">{{ t("labels.admin") }}</li>
        </ul>
        {{ identity.fullName }}
      </h2>
      <div v-else-if="canUpdate || isCurrent || labels?.length">
        <ul class="flex flex-row flex-wrap content-start items-start gap-1 text-sm float-right">
          <li v-for="label in labels || []" :key="label" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm text-sm leading-none">{{ label }}</li>
          <li v-if="isCurrent" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm leading-none">{{ t("labels.current") }}</li>
          <li v-if="canUpdate" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm leading-none">{{ t("labels.admin") }}</li>
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
