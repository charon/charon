<script setup lang="ts">
import type { IdentityRef } from "@/types"

import { useRouter } from "vue-router"
import { useI18n } from "vue-i18n"
import IdentityCreate from "@/partials/IdentityCreate.vue"
import NavBar from "@/partials/NavBar.vue"
import Footer from "@/partials/Footer.vue"

const { t } = useI18n({ useScope: "global" })
const router = useRouter()

function onCreated(identity: IdentityRef) {
  router.push({ name: "IdentityGet", params: { id: identity.id } })
}
</script>

<template>
  <Teleport to="header">
    <NavBar></NavBar>
  </Teleport>
  <div class="w-full flex flex-col items-center mt-12 sm:mt-[4.5rem] border-t border-transparent">
    <div class="grid auto-rows-auto grid-cols-[minmax(0,_65ch)] m-1 sm:m-4 gap-1 sm:gap-4">
      <div class="w-full rounded border bg-white p-4 shadow flex flex-col gap-4">
        <div class="flex flex-row items-center">
          <h1 class="text-2xl font-bold">{{ t("views.IdentityGet.createIdentity") }}</h1>
        </div>
        <IdentityCreate @created="onCreated" />
      </div>
    </div>
  </div>
  <Teleport to="footer">
    <Footer />
  </Teleport>
</template>
