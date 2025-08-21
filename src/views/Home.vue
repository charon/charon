<script setup lang="ts">
import { useI18n } from "vue-i18n"
import ButtonLink from "@/components/ButtonLink.vue"
import NavBar from "@/partials/NavBar.vue"
import Footer from "@/partials/Footer.vue"
import { isSignedIn } from "@/auth"

const { t } = useI18n({ useScope: "global" })
</script>

<template>
  <Teleport to="header">
    <NavBar></NavBar>
  </Teleport>
  <div class="w-full flex flex-col items-center mt-12 sm:mt-[4.5rem] border-t border-transparent">
    <div class="grid auto-rows-auto grid-cols-[minmax(0,_65ch)] m-1 sm:m-4 gap-1 sm:gap-4">
      <div class="w-full rounded border bg-white p-4 shadow flex flex-col gap-4">
        <ButtonLink v-if="isSignedIn()" :to="{ name: 'IdentityList' }" primary>{{ t("views.Home.identities") }}</ButtonLink>
        <ButtonLink :to="{ name: 'ApplicationTemplateList' }" primary>{{ t("views.Home.applicationTemplates") }}</ButtonLink>
        <ButtonLink :to="{ name: 'OrganizationList' }" primary>{{ t("views.Home.organizations") }}</ButtonLink>
      </div>
    </div>
  </div>
  <Teleport to="footer">
    <Footer />
  </Teleport>
</template>
