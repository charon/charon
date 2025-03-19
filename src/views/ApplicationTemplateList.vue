<script setup lang="ts">
import type { ApplicationTemplates } from "@/types"

import { onBeforeMount, onBeforeUnmount, ref } from "vue"
import { useRouter } from "vue-router"
import ButtonLink from "@/components/ButtonLink.vue"
import ApplicationTemplateListItem from "@/partials/ApplicationTemplateListItem.vue"
import NavBar from "@/partials/NavBar.vue"
import Footer from "@/partials/Footer.vue"
import { getURL } from "@/api"
import { injectProgress } from "@/progress"
import { isSignedIn } from "@/auth"

const router = useRouter()

const progress = injectProgress()

const abortController = new AbortController()
const dataLoading = ref(true)
const dataLoadingError = ref("")
const applicationTemplates = ref<ApplicationTemplates>([])

onBeforeUnmount(() => {
  abortController.abort()
})

onBeforeMount(async () => {
  progress.value += 1
  try {
    const url = router.apiResolve({
      name: "ApplicationTemplateList",
    }).href

    const response = await getURL<ApplicationTemplates>(url, null, abortController.signal, progress)
    if (abortController.signal.aborted) {
      return
    }

    applicationTemplates.value = response.doc
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("ApplicationTemplateList.onBeforeMount", error)
    dataLoadingError.value = `${error}`
  } finally {
    dataLoading.value = false
    progress.value -= 1
  }
})
</script>

<template>
  <Teleport to="header">
    <NavBar></NavBar>
  </Teleport>
  <div class="w-full flex flex-col items-center mt-12 sm:mt-[4.5rem] border-t border-transparent">
    <div class="grid auto-rows-auto grid-cols-[minmax(0,_65ch)] m-1 sm:m-4 gap-1 sm:gap-4">
      <div class="w-full rounded border bg-white p-4 shadow flex flex-col gap-4">
        <div class="flex flex-row justify-between items-center gap-4">
          <h1 class="text-2xl font-bold">Application templates</h1>
          <ButtonLink v-if="isSignedIn()" :to="{ name: 'ApplicationTemplateCreate' }" :progress="progress" primary>Create</ButtonLink>
        </div>
      </div>
      <div v-if="dataLoading" class="w-full rounded border bg-white p-4 shadow">Loading...</div>
      <div v-else-if="dataLoadingError" class="w-full rounded border bg-white p-4 shadow text-error-600">Unexpected error. Please try again.</div>
      <template v-else>
        <div v-if="!applicationTemplates.length" class="w-full rounded border bg-white p-4 shadow grid grid-cols-1 gap-4 italic">
          There are no application templates. {{ isSignedIn() ? "Create the first one." : "Sign-in or sign-up to create the first one." }}
        </div>
        <div v-for="applicationTemplate of applicationTemplates" :key="applicationTemplate.id" class="w-full rounded border bg-white p-4 shadow grid grid-cols-1">
          <ApplicationTemplateListItem :item="applicationTemplate" />
        </div>
      </template>
    </div>
  </div>
  <Teleport to="footer">
    <Footer />
  </Teleport>
</template>
