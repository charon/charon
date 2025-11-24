<script setup lang="ts">
import type { DeepReadonly } from "vue"

import type { Identity } from "@/types"

import { computed } from "vue"
import { useI18n } from "vue-i18n"

const props = defineProps<{
  identity: Identity | DeepReadonly<Identity>
  url?: string
  isCurrent?: boolean
  canUpdate?: boolean
  labels?: string[]
}>()

const isShared = computed(() => props.identity.admins.length + (props.identity.users?.length || 0) > 1)

const { t } = useI18n({ useScope: "global" })
</script>

<template>
  <div class="flex flex-row gap-4" :data-url="url">
    <div v-if="identity.pictureUrl" class="flex-none">
      <router-link :to="{ name: 'IdentityGet', params: { id: identity.id } }" class="link">
        <img :src="identity.pictureUrl" :alt="t('common.accessibility.picture')" class="h-20 w-20 rounded-sm ring-2 ring-white" />
      </router-link>
    </div>
    <div class="flex grow flex-col">
      <!--
        This should be similar in what is show as main piece of information in getIdentityDisplayName utility function.
        Keep it in sync with to IdentityPublic component, too.
      -->
      <h2 v-if="identity.username" class="text-xl">
        <ul class="float-right flex flex-row flex-wrap content-start items-start gap-1 text-sm">
          <li v-for="label in labels || []" :key="label" class="rounded-xs bg-slate-100 px-1.5 py-0.5 text-sm leading-none text-gray-600 shadow-xs">{{ label }}</li>
          <li v-if="isCurrent" class="rounded-xs bg-slate-100 px-1.5 py-0.5 leading-none text-gray-600 shadow-xs">{{ t("common.labels.current") }}</li>
          <li v-if="isShared" class="rounded-xs bg-slate-100 px-1.5 py-0.5 leading-none text-gray-600 shadow-xs">{{ t("common.labels.shared") }}</li>
          <li v-else class="rounded-xs bg-slate-100 px-1.5 py-0.5 leading-none text-gray-600 shadow-xs">{{ t("common.labels.individual") }}</li>
          <li v-if="canUpdate" class="rounded-xs bg-slate-100 px-1.5 py-0.5 leading-none text-gray-600 shadow-xs">{{ t("common.labels.admin") }}</li>
        </ul>
        <router-link :to="{ name: 'IdentityGet', params: { id: identity.id } }" class="link">{{ identity.username }}</router-link>
        <span v-if="identity.email"> ({{ identity.email }})</span>
      </h2>
      <h2 v-else-if="identity.email" class="text-xl">
        <ul class="float-right flex flex-row flex-wrap content-start items-start gap-1 text-sm">
          <li v-for="label in labels || []" :key="label" class="rounded-xs bg-slate-100 px-1.5 py-0.5 text-sm leading-none text-gray-600 shadow-xs">{{ label }}</li>
          <li v-if="isCurrent" class="rounded-xs bg-slate-100 px-1.5 py-0.5 leading-none text-gray-600 shadow-xs">{{ t("common.labels.current") }}</li>
          <li v-if="isShared" class="rounded-xs bg-slate-100 px-1.5 py-0.5 leading-none text-gray-600 shadow-xs">{{ t("common.labels.shared") }}</li>
          <li v-else class="rounded-xs bg-slate-100 px-1.5 py-0.5 leading-none text-gray-600 shadow-xs">{{ t("common.labels.individual") }}</li>
          <li v-if="canUpdate" class="rounded-xs bg-slate-100 px-1.5 py-0.5 leading-none text-gray-600 shadow-xs">{{ t("common.labels.admin") }}</li>
        </ul>
        <router-link :to="{ name: 'IdentityGet', params: { id: identity.id } }" class="link">{{ identity.email }}</router-link>
      </h2>
      <h2 v-else-if="identity.givenName" class="text-xl">
        <ul class="float-right flex flex-row flex-wrap content-start items-start gap-1 text-sm">
          <li v-for="label in labels || []" :key="label" class="rounded-xs bg-slate-100 px-1.5 py-0.5 text-sm leading-none text-gray-600 shadow-xs">{{ label }}</li>
          <li v-if="isCurrent" class="rounded-xs bg-slate-100 px-1.5 py-0.5 leading-none text-gray-600 shadow-xs">{{ t("common.labels.current") }}</li>
          <li v-if="isShared" class="rounded-xs bg-slate-100 px-1.5 py-0.5 leading-none text-gray-600 shadow-xs">{{ t("common.labels.shared") }}</li>
          <li v-else class="rounded-xs bg-slate-100 px-1.5 py-0.5 leading-none text-gray-600 shadow-xs">{{ t("common.labels.individual") }}</li>
          <li v-if="canUpdate" class="rounded-xs bg-slate-100 px-1.5 py-0.5 leading-none text-gray-600 shadow-xs">{{ t("common.labels.admin") }}</li>
        </ul>
        <router-link :to="{ name: 'IdentityGet', params: { id: identity.id } }" class="link">{{ identity.givenName }}</router-link>
        <span v-if="identity.fullName"> ({{ identity.fullName }})</span>
      </h2>
      <h2 v-else-if="identity.fullName" class="text-xl">
        <ul class="float-right flex flex-row flex-wrap content-start items-start gap-1 text-sm">
          <li v-for="label in labels || []" :key="label" class="rounded-xs bg-slate-100 px-1.5 py-0.5 text-sm leading-none text-gray-600 shadow-xs">{{ label }}</li>
          <li v-if="isCurrent" class="rounded-xs bg-slate-100 px-1.5 py-0.5 leading-none text-gray-600 shadow-xs">{{ t("common.labels.current") }}</li>
          <li v-if="isShared" class="rounded-xs bg-slate-100 px-1.5 py-0.5 leading-none text-gray-600 shadow-xs">{{ t("common.labels.shared") }}</li>
          <li v-else class="rounded-xs bg-slate-100 px-1.5 py-0.5 leading-none text-gray-600 shadow-xs">{{ t("common.labels.individual") }}</li>
          <li v-if="canUpdate" class="rounded-xs bg-slate-100 px-1.5 py-0.5 leading-none text-gray-600 shadow-xs">{{ t("common.labels.admin") }}</li>
        </ul>
        <router-link :to="{ name: 'IdentityGet', params: { id: identity.id } }" class="link">{{ identity.fullName }}</router-link>
      </h2>
      <div v-else>
        <ul class="float-right flex flex-row flex-wrap content-start items-start gap-1 text-sm">
          <li v-for="label in labels || []" :key="label" class="rounded-xs bg-slate-100 px-1.5 py-0.5 text-sm leading-none text-gray-600 shadow-xs">{{ label }}</li>
          <li v-if="isCurrent" class="rounded-xs bg-slate-100 px-1.5 py-0.5 leading-none text-gray-600 shadow-xs">{{ t("common.labels.current") }}</li>
          <li v-if="isShared" class="rounded-xs bg-slate-100 px-1.5 py-0.5 leading-none text-gray-600 shadow-xs">{{ t("common.labels.shared") }}</li>
          <li v-else class="rounded-xs bg-slate-100 px-1.5 py-0.5 leading-none text-gray-600 shadow-xs">{{ t("common.labels.individual") }}</li>
          <li v-if="canUpdate" class="rounded-xs bg-slate-100 px-1.5 py-0.5 leading-none text-gray-600 shadow-xs">{{ t("common.labels.admin") }}</li>
        </ul>
      </div>
      <div v-if="identity.givenName && (identity.username || identity.email)" class="mt-1"
        >{{ identity.givenName }}
        <span v-if="identity.fullName"> ({{ identity.fullName }})</span>
      </div>
      <div v-else-if="identity.fullName && (identity.username || identity.email)" class="mt-1">{{ identity.fullName }}</div>
      <div v-if="identity.description" class="mt-1 whitespace-pre-line">{{ identity.description }}</div>
    </div>
    <slot :identity="identity" :is-current="isCurrent" :can-update="canUpdate" :is-shared="isShared"></slot>
  </div>
</template>
