<script setup lang="ts">
import type { Activities } from "@/types"

import { onBeforeMount, onBeforeUnmount, ref } from "vue"
import { useI18n } from "vue-i18n"
import { useRouter } from "vue-router"

import { getURL } from "@/api"
import ActivityListItem from "@/partials/ActivityListItem.vue"
import Footer from "@/partials/Footer.vue"
import NavBar from "@/partials/NavBar.vue"
import OrganizationListItem from "@/partials/OrganizationListItem.vue"
import { injectProgress } from "@/progress"

const props = defineProps<{
  id: string
}>()

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

// TODO: If user is not signed-in, this will show "unexpected error".

onBeforeMount(async () => {
  progress.value += 1
  try {
    const activitiesURL = router.apiResolve({
      name: "OrganizationActivity",
      params: {
        id: props.id,
      },
    }).href

    const response = await getURL<Activities>(activitiesURL, null, abortController.signal, progress)
    if (abortController.signal.aborted) {
      return
    }

    activities.value = response.doc
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("OrganizationActivity.onBeforeMount", error)
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
      <div class="w-full rounded border bg-white p-4 shadow-sm flex flex-col gap-4">
        <div class="flex flex-col gap-4">
          <h1 class="text-2xl font-bold">{{ t("views.OrganizationActivity.organizationActivity") }}</h1>
          <div>
            <OrganizationListItem :item="{ id }" />
          </div>
        </div>
      </div>
      <div v-if="dataLoading" class="w-full rounded border bg-white p-4 shadow-sm">{{ t("common.data.dataLoading") }}</div>
      <div v-else-if="dataLoadingError" class="w-full rounded border bg-white p-4 shadow-sm text-error-600">{{ t("common.errors.unexpected") }}</div>
      <template v-else>
        <div v-if="!activities.length" class="w-full rounded border bg-white p-4 shadow-sm italic">
          {{ t("views.OrganizationActivity.noActivities") }}
        </div>
        <div v-for="activity in activities" :key="activity.id" class="w-full rounded border bg-white p-4 shadow-sm">
          <ActivityListItem :item="activity" :organization="{ id }" />
        </div>
      </template>
    </div>
  </div>
  <Teleport to="footer">
    <Footer />
  </Teleport>
</template>
