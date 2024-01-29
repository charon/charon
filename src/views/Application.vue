<script setup lang="ts">
import type { Application, Metadata } from "@/types"

import { computed, onBeforeMount, onUnmounted, ref, watch } from "vue"
import { useRouter } from "vue-router"
import InputText from "@/components/InputText.vue"
import Button from "@/components/Button.vue"
import Footer from "@/components/Footer.vue"
import { getURL, postURL } from "@/api"

const props = defineProps<{
  id: string
}>()

const router = useRouter()

const mainProgress = ref(0)
const abortController = new AbortController()
const dataLoading = ref(true)
const dataLoadingError = ref("")
const unexpectedError = ref("")
const updated = ref(false)
const application = ref<Application | null>(null)
const metadata = ref<Metadata>({})
const name = ref("")
const redirectPaths = ref<string[]>([])

// TODO: Support managing all redirect paths.
const firstRedirectPath = computed({
  get() {
    return redirectPaths.value[0]
  },
  set(value) {
    return redirectPaths.value.splice(0, 1, value)
  },
})

function resetOnInteraction() {
  // We reset flags and errors on interaction.
  updated.value = false
  unexpectedError.value = ""
  // dataLoading and dataLoadingError are not listed here on
  // purpose because they are used only on mount.
}

watch([name, redirectPaths], resetOnInteraction)

onUnmounted(() => {
  abortController.abort()
})

async function loadData(init: boolean) {
  mainProgress.value += 1
  try {
    const url = router.apiResolve({
      name: "Application",
      params: {
        id: props.id,
      },
    }).href
    const data = await getURL<Application>(url, null, abortController.signal, mainProgress)
    application.value = data.doc
    metadata.value = data.metadata

    if (init) {
      name.value = data.doc.name
      // We have to make a copy of the array so that data.doc.redirectPaths
      // is not changed when redirectPaths changes.
      redirectPaths.value = [...data.doc.redirectPaths]
    }
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    // TODO: 404 should be shown differently, but probably in the same way for all 404.
    console.error(error)
    dataLoadingError.value = `${error}`
  } finally {
    dataLoading.value = false
    mainProgress.value -= 1
  }
}

onBeforeMount(async () => {
  await loadData(true)
})

async function onSubmit() {
  resetOnInteraction()

  mainProgress.value += 1
  try {
    try {
      const payload: Application = {
        id: props.id,
        name: name.value,
        redirectPaths: redirectPaths.value,
      }
      const url = router.apiResolve({
        name: "ApplicationUpdate",
        params: {
          id: props.id,
        },
      }).href

      await postURL(url, payload, abortController.signal, mainProgress)

      updated.value = true
    } catch (error) {
      if (abortController.signal.aborted) {
        return
      }
      console.error(error)
      unexpectedError.value = `${error}`
    } finally {
      // We update state even on errors.
      await loadData(false)
    }
  } finally {
    mainProgress.value -= 1
  }
}
</script>

<template>
  <div class="w-full flex flex-col items-center">
    <div class="grid auto-rows-auto grid-cols-[minmax(0,_65ch)] m-1 sm:m-4 gap-1 sm:gap-4">
      <div class="w-full rounded border bg-white p-4 shadow flex flex-col gap-4">
        <div class="flex flex-row items-center">
          <h1 class="text-2xl font-bold">Application</h1>
        </div>
        <div v-if="dataLoading">Loading...</div>
        <div v-else-if="dataLoadingError" class="text-error-600">Unexpected error. Please try again.</div>
        <form v-else class="flex flex-col" novalidate @submit.prevent="onSubmit">
          <label for="name" class="mb-1">Application name</label>
          <InputText id="name" v-model="name" class="flex-grow flex-auto min-w-0" :readonly="mainProgress > 0 || !metadata.can_update" required />
          <label for="name" class="mb-1 mt-4">OpenID Connect redirect path</label>
          <InputText id="name" v-model="firstRedirectPath" class="flex-grow flex-auto min-w-0" :readonly="mainProgress > 0 || !metadata.can_update" required />
          <div v-if="unexpectedError" class="mt-4 text-error-600">Unexpected error. Please try again.</div>
          <div v-else-if="updated" class="mt-4 text-success-600">Application updated successfully.</div>
          <div v-if="metadata.can_update" class="mt-4 flex flex-row justify-end">
            <!--
              Button is on purpose not disabled on unexpectedError so that user can retry.
            -->
            <Button
              type="submit"
              primary
              :disabled="
                name.length === 0 ||
                firstRedirectPath.length === 0 ||
                (application!.name === name && application!.redirectPaths[0] === firstRedirectPath) ||
                mainProgress > 0
              "
              >Update</Button
            >
          </div>
        </form>
      </div>
    </div>
  </div>
  <Teleport to="footer">
    <Footer />
  </Teleport>
</template>
