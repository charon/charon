<script setup lang="ts">
import { onBeforeMount, onBeforeUnmount, ref } from "vue"
import { useRouter } from "vue-router"

import { getHTML } from "@/api"
import Footer from "@/partials/Footer.vue"
import NavBar from "@/partials/NavBar.vue"
import { useProgress } from "@/progress"

const router = useRouter()
const progress = useProgress()
const abortController = new AbortController()

const termsOfService = ref("")

onBeforeUnmount(() => {
  abortController.abort()
})

onBeforeMount(async () => {
  progress.value += 1
  try {
    const url = router.apiResolve({
      name: "TermsOfService",
    }).href

    const html = await getHTML(url, abortController.signal, progress)
    if (abortController.signal.aborted) {
      return
    }
    termsOfService.value = html
  } catch (err) {
    if (abortController.signal.aborted) {
      return
    }
    // TODO: Show some error to the user.
    console.error("TermsOfService.onBeforeMount", err)
  } finally {
    progress.value -= 1
  }
})
</script>

<template>
  <Teleport to="header">
    <NavBar />
  </Teleport>
  <div class="mt-12 flex w-full flex-col items-center border-t border-transparent sm:mt-[4.5rem]">
    <div class="m-1 grid auto-rows-auto grid-cols-[minmax(0,65ch)] gap-1 sm:m-4 sm:gap-4">
      <div class="prose w-full rounded-sm border border-gray-200 bg-white p-4 shadow-sm" v-html="termsOfService" />
    </div>
  </div>
  <Teleport to="footer">
    <Footer />
  </Teleport>
</template>
