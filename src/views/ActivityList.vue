<script setup lang="ts">
import type { Activities } from "@/types"

import { onBeforeMount, onBeforeUnmount, ref } from "vue"
import { useI18n } from "vue-i18n"
import { useRouter } from "vue-router"

import { getURL } from "@/api"
import ActivityListItem from "@/partials/ActivityListItem.vue"
import Footer from "@/partials/Footer.vue"
import NavBar from "@/partials/NavBar.vue"
import { injectProgress } from "@/progress"

const { t } = useI18n({ useScope: "global" })
const router = useRouter()

const progress = injectProgress()

const abortController = new AbortController()
const dataLoading = ref(true)
const dataLoadingError = ref("")
const activities = ref<Activities>([])

onBeforeUnmount(() => {
  abortController.abort()
})

onBeforeMount(async () => {
  progress.value += 1
  try {
    const url = router.apiResolve({
      name: "ActivityList",
    }).href

    const response = await getURL<Activities>(url, null, abortController.signal, progress)
    if (abortController.signal.aborted) {
      return
    }

    activities.value = response.doc
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("ActivityList.onBeforeMount", error)
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
          <h1 class="text-2xl font-bold">{{ t("common.entities.activity") }}</h1>
        </div>
      </div>
      <div v-if="dataLoading" class="w-full rounded border bg-white p-4 shadow">{{ t("common.data.dataLoading") }}</div>
      <div v-else-if="dataLoadingError" class="w-full rounded border bg-white p-4 shadow text-error-600">{{ t("common.errors.unexpected") }}</div>
      <template v-else>
        <div v-if="!activities.length" class="w-full rounded border bg-white p-4 shadow italic">
          {{ t("views.ActivityList.noActivities") }}
        </div>
        <div v-for="activity in activities" :key="activity.id" class="w-full rounded border bg-white p-4 shadow">
          <ActivityListItem :item="activity" />
        </div>
      </template>
    </div>
  </div>
  <Teleport to="footer">
    <Footer />
  </Teleport>
</template>
