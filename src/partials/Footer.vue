<script setup lang="ts">
import { useI18n } from "vue-i18n"

import siteContext from "@/context"

const { t } = useI18n({ useScope: "global" })
</script>

<template>
  <div class="flex justify-between gap-x-2 p-2 leading-none sm:gap-x-4 sm:p-4">
    <ul class="flex gap-x-2 sm:gap-x-4">
      <li v-if="siteContext.termsOfService">
        ><router-link :to="{ name: 'TermsOfService' }" class="link">{{ t("views.Footer.terms") }}</router-link></li
      >
      <li v-if="siteContext.privacyPolicy"
        ><router-link :to="{ name: 'PrivacyPolicy' }" class="link">{{ t("views.Footer.privacy") }}</router-link></li
      >
    </ul>
    <ul class="flex gap-x-2 sm:gap-x-4">
      <li class="text-neutral-500">
        <i18n-t keypath="partials.Footer.poweredBy" scope="global">
          <template #linkName>
            <a href="https://gitlab.com/charon/charon" class="link">Charon</a>
          </template>
        </i18n-t>
      </li>
    </ul>
  </div>
</template>
