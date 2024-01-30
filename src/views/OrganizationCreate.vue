<script setup lang="ts">
import type { OrganizationCreate, OrganizationRef } from "@/types"

import { onUnmounted, ref } from "vue"
import { useRouter } from "vue-router"
import InputText from "@/components/InputText.vue"
import Button from "@/components/Button.vue"
import NavBar from "@/components/NavBar.vue"
import Footer from "@/components/Footer.vue"
import { postURL } from "@/api"

const router = useRouter()

const mainProgress = ref(0)
const abortController = new AbortController()
const unexpectedError = ref("")
const name = ref("")

onUnmounted(() => {
  abortController.abort()
})

async function onSubmit() {
  mainProgress.value += 1
  try {
    unexpectedError.value = ""
    const payload: OrganizationCreate = {
      name: name.value,
    }
    const url = router.apiResolve({
      name: "OrganizationCreate",
    }).href

    const organization = await postURL<OrganizationRef>(url, payload, abortController.signal, mainProgress)

    router.push({ name: "Organization", params: { id: organization.id } })
    // We increase the progress and never decrease it to wait for browser to do the redirect.
    mainProgress.value += 1
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error(error)
    unexpectedError.value = `${error}`
  } finally {
    mainProgress.value -= 1
  }
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
          <h1 class="text-2xl font-bold">Create organization</h1>
        </div>
        <form class="flex flex-col" novalidate @submit.prevent="onSubmit">
          <label for="name" class="mb-1">Organization name</label>
          <InputText id="name" v-model="name" class="flex-grow flex-auto min-w-0" :readonly="mainProgress > 0" required />
          <div v-if="unexpectedError" class="mt-4 text-error-600">Unexpected error. Please try again.</div>
          <div v-else class="mt-4">Pick a name. You will be able to configure the organization after it is created.</div>
          <div class="mt-4 flex flex-row justify-end">
            <!--
              Button is on purpose not disabled on unexpectedError so that user can retry.
            -->
            <Button type="submit" primary :disabled="name.length === 0 || mainProgress > 0">Create</Button>
          </div>
        </form>
      </div>
    </div>
  </div>
  <Teleport to="footer">
    <Footer />
  </Teleport>
</template>
