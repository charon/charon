<script setup lang="ts">
import type { Application, Applications } from "@/types"

import { onBeforeMount, onUnmounted, ref } from "vue"
import { useRouter } from "vue-router"
import ButtonLink from "@/components/ButtonLink.vue"
import WithDocument from "@/components/WithDocument.vue"
import Footer from "@/components/Footer.vue"
import { getURL } from "@/api"

const router = useRouter()

const mainProgress = ref(0)
const abortController = new AbortController()
const dataLoading = ref(true)
const dataLoadingError = ref("")
const applications = ref<Applications>([])

onUnmounted(() => {
  abortController.abort()
})

onBeforeMount(async () => {
  mainProgress.value += 1
  try {
    const url = router.apiResolve({
      name: "Applications",
    }).href
    applications.value = (await getURL<Applications>(url, null, abortController.signal, mainProgress)).doc
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error(error)
    dataLoadingError.value = `${error}`
  } finally {
    dataLoading.value = false
    mainProgress.value -= 1
  }
})

const WithApplicationDocument = WithDocument<Application>
</script>

<template>
  <div class="w-full flex flex-col items-center">
    <div class="grid auto-rows-auto grid-cols-[minmax(0,_65ch)] m-1 sm:m-4 gap-1 sm:gap-4">
      <div class="w-full rounded border bg-white p-4 shadow flex flex-col gap-4">
        <div class="flex flex-row justify-between items-center gap-4">
          <h1 class="text-2xl font-bold">Applications</h1>
          <ButtonLink :to="{ name: 'ApplicationCreate' }" :disabled="mainProgress > 0" primary>Create</ButtonLink>
        </div>
      </div>
      <div v-if="dataLoading" class="w-full rounded border bg-white p-4 shadow">Loading...</div>
      <div v-else-if="dataLoadingError" class="w-full rounded border bg-white p-4 shadow text-error-600">Unexpected error. Please try again.</div>
      <template v-else>
        <div v-for="application of applications" :key="application.id" class="w-full rounded border bg-white p-4 shadow grid grid-cols-1 gap-4">
          <WithApplicationDocument :id="application.id" name="Application">
            <template #default="{ doc, metadata, url }">
              <h2 class="text-xl flex flex-row items-center gap-1">
                <router-link :to="{ name: 'Application', params: { id: application.id } }" :data-url="url" class="link">{{ doc.name }}</router-link>
                <span v-if="metadata.can_update" class="rounded-sm bg-slate-100 py-0.5 px-1.5 text-gray-600 shadow-sm text-sm leading-none">admin</span>
              </h2>
            </template>
          </WithApplicationDocument>
        </div>
      </template>
    </div>
  </div>
  <Teleport to="footer">
    <Footer />
  </Teleport>
</template>
