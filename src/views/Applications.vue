<script setup lang="ts">
import { onBeforeMount, onUnmounted, ref } from "vue"
import { useRouter } from "vue-router"
import ButtonLink from "@/components/ButtonLink.vue"
import WithDocument from "@/components/WithDocument.vue"
import Footer from "@/components/Footer.vue"
import { getURL } from "@/api"
import { Application, Applications } from "@/types"

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
    applications.value = (await getURL(url, null, abortController.signal, mainProgress)) as Applications
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
</script>

<template>
  <div class="w-full flex flex-col items-center">
    <div class="grid auto-rows-auto grid-cols-[minmax(0,_65ch)] m-1 sm:m-4 gap-1 sm:gap-4">
      <div class="w-full rounded border bg-white p-4 shadow flex flex-col gap-4">
        <div class="flex flex-row justify-between items-center gap-4">
          <span class="font-bold">Applications</span><ButtonLink :to="{ name: 'ApplicationCreate' }" :disabled="mainProgress > 0" primary>Create</ButtonLink>
        </div>
      </div>
      <div v-if="dataLoading" class="w-full rounded border bg-white p-4 shadow">Loading...</div>
      <div v-else-if="dataLoadingError" class="w-full rounded border bg-white p-4 shadow text-error-600">Unexpected error. Please try again.</div>
      <template v-else>
        <div v-for="application of applications" :key="application.id" class="w-full rounded border bg-white p-4 shadow">
          <WithDocument :id="application.id" name="Application">
            <template #default="{ doc, url }">
              <!-- TODO: How to make it be just "doc.name" and not "(doc as Application).name"? -->
              <router-link :to="{ name: 'Application', params: { id: application.id } }" :data-url="url" class="link">{{ (doc as Application).name }}</router-link>
            </template>
          </WithDocument>
        </div>
      </template>
    </div>
  </div>
  <Teleport to="footer">
    <Footer />
  </Teleport>
</template>
