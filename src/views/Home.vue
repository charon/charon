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
  <div class="w-full flex flex-col items-center mt-12 sm:mt-[4.5rem] border-t border-transparent">
    <div class="grid auto-rows-auto grid-cols-[minmax(0,_65ch)] m-1 sm:m-4 gap-1 sm:gap-4">
      <div class="w-full rounded-xs border bg-white p-4 shadow-sm flex flex-col gap-4">
        <ButtonLink v-if="isSignedIn()" id="menu-list-identities" :to="{ name: 'IdentityList' }" primary>
          {{ t("common.entities.identities") }}
        </ButtonLink>
        <ButtonLink id="menu-list-application_templates" :to="{ name: 'ApplicationTemplateList' }" primary>
          {{ t("common.entities.applicationTemplates") }}
        </ButtonLink>
        <ButtonLink id="menu-list-organizations" :to="{ name: 'OrganizationList' }" primary>
          {{ t("common.entities.organizations") }}
        </ButtonLink>
        <ButtonLink v-if="isSignedIn()" id="menu-list-activity" :to="{ name: 'ActivityList' }" primary>
          {{ t("common.entities.activity") }}
        </ButtonLink>
      </div>
    </div>
  </div>
  <Teleport to="footer">
    <Footer />
  </Teleport>
</template>
