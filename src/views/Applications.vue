<script setup lang="ts">
import { onBeforeMount, onUnmounted, ref } from "vue"
import { useRouter } from "vue-router"
import ButtonLink from "@/components/ButtonLink.vue"
import Footer from "@/components/Footer.vue"
import { FetchError } from "@/api"
import { ApplicationsResponse } from "@/types"

const router = useRouter()

const mainProgress = ref(0)
const abortController = new AbortController()
const dataLoading = ref(true)
const unexpectedError = ref("")
const applications = ref<ApplicationsResponse>([])

onUnmounted(() => {
  abortController.abort()
})

onBeforeMount(async () => {
  try {
    const url = router.apiResolve({
      name: "Applications",
    }).href
    const response = await fetch(url, {
      method: "GET",
      // Mode and credentials match crossorigin=anonymous in link preload header.
      mode: "cors",
      credentials: "same-origin",
      referrer: document.location.href,
      referrerPolicy: "strict-origin-when-cross-origin",
    })
    const contentType = response.headers.get("Content-Type")
    if (!contentType || !contentType.includes("application/json")) {
      const body = await response.text()
      throw new FetchError(`fetch GET error ${response.status}: ${body}`, {
        status: response.status,
        body,
        url,
        requestID: response.headers.get("Request-ID"),
      })
    }
    applications.value = await response.json()
  } catch (error) {
    console.error(error)
    unexpectedError.value = `${error}`
  } finally {
    dataLoading.value = false
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
      <div v-else-if="unexpectedError" class="w-full rounded border bg-white p-4 shadow text-error-600">Unexpected error. Please try again.</div>
      <template v-else>
        <div v-for="application of applications" :key="application.id" class="w-full rounded border bg-white p-4 shadow">
          <router-link :to="{ name: 'Application', params: { id: application.id } }" class="link">{{ application.id }}</router-link>
        </div>
      </template>
    </div>
  </div>
  <Teleport to="footer">
    <Footer />
  </Teleport>
</template>
