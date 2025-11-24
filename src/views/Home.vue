<script setup lang="ts">
import { useI18n } from "vue-i18n"

import { isSignedIn } from "@/auth"
import ButtonLink from "@/components/ButtonLink.vue"
import Footer from "@/partials/Footer.vue"
import NavBar from "@/partials/NavBar.vue"

const { t } = useI18n({ useScope: "global" })
</script>

<template>
  <Teleport to="header">
    <NavBar></NavBar>
  </Teleport>
  <div class="mt-12 flex w-full flex-col items-center border-t border-transparent sm:mt-[4.5rem]">
    <div class="m-1 grid auto-rows-auto grid-cols-[minmax(0,65ch)] gap-1 sm:m-4 sm:gap-4">
      <div class="flex w-full flex-col gap-4 rounded-sm border border-gray-200 bg-white p-4 shadow-sm">
        <ButtonLink v-if="isSignedIn()" id="menu-list-identities" :to="{ name: 'IdentityList' }" primary>{{ t("common.entities.identities") }}</ButtonLink>
        <ButtonLink id="menu-list-applicationTemplates" :to="{ name: 'ApplicationTemplateList' }" primary>{{ t("common.entities.applicationTemplates") }}</ButtonLink>
        <ButtonLink id="menu-list-organizations" :to="{ name: 'OrganizationList' }" primary>{{ t("common.entities.organizations") }}</ButtonLink>
        <ButtonLink v-if="isSignedIn()" id="menu-list-activity" :to="{ name: 'ActivityList' }" primary>{{ t("common.entities.activity") }}</ButtonLink>
      </div>
    </div>
  </div>
  <Teleport to="footer">
    <Footer />
  </Teleport>
</template>
