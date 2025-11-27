<script setup lang="ts">
import Footer from "@/partials/Footer.vue"
import NavBar from "@/partials/NavBar.vue"
import WithIdentityPublicDocument from "@/partials/WithIdentityPublicDocument.vue"

defineProps<{
  id: string
  identityId: string
}>()
</script>

<template>
  <Teleport to="header">
    <NavBar></NavBar>
  </Teleport>
  <div class="mt-12 flex w-full flex-col items-center border-t border-transparent sm:mt-[4.5rem]">
    <div class="m-1 grid auto-rows-auto grid-cols-[minmax(0,65ch)] gap-1 sm:m-4 sm:gap-4">
      <div class="flex w-full flex-col gap-4 rounded-sm border border-gray-200 bg-white p-4 shadow-sm">
        <WithIdentityPublicDocument :item="{ id: identityId }" :organization-id="id"></WithIdentityPublicDocument>
      </div>
    </div>
  </div>
  <Teleport to="footer">
    <Footer />
  </Teleport>
</template>
