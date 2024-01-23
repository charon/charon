<script setup lang="ts">
import { onBeforeMount, onUnmounted, ref, watch } from "vue"
import { useRouter } from "vue-router"
import InputText from "@/components/InputText.vue"
import Button from "@/components/Button.vue"
import Footer from "@/components/Footer.vue"
import { getURL, postURL } from "@/api"
import { Application } from "@/types"

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
const name = ref("")
const redirectPath = ref("")

watch(name, () => {
  // We reset updated flag when input box value changes.
  updated.value = false
})

watch(redirectPath, () => {
  // We reset updated flag when input box value changes.
  updated.value = false
})

onUnmounted(() => {
  abortController.abort()
})

onBeforeMount(async () => {
  mainProgress.value += 1
  try {
    const url = router.apiResolve({
      name: "Application",
      params: {
        id: props.id,
      },
    }).href
    application.value = (await getURL(url, null, abortController.signal, mainProgress)) as Application
    name.value = application.value!.name
    redirectPath.value = application.value!.redirectPath
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
})

async function onSubmit() {
  mainProgress.value += 1
  try {
    unexpectedError.value = ""
    const payload: Application = {
      id: props.id,
      name: name.value,
      redirectPath: redirectPath.value,
    }
    const url = router.apiResolve({
      name: "ApplicationUpdate",
      params: {
        id: props.id,
      },
    }).href

    await postURL(url, payload, abortController.signal, mainProgress)

    // We update application document state so that we can detect further changes.
    application.value!.name = payload.name
    application.value!.redirectPath = payload.redirectPath

    updated.value = true
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
  <div class="w-full flex flex-col items-center">
    <div class="grid auto-rows-auto grid-cols-[minmax(0,_65ch)] m-1 sm:m-4 gap-1 sm:gap-4">
      <div class="w-full rounded border bg-white p-4 shadow flex flex-col gap-4">
        <div class="flex flex-row items-center">
          <span class="font-bold">Application</span>
        </div>
        <div v-if="dataLoading">Loading...</div>
        <div v-else-if="dataLoadingError" class="text-error-600">Unexpected error. Please try again.</div>
        <form v-else class="flex flex-col" novalidate @submit.prevent="onSubmit">
          <label for="name" class="mb-1">Application name</label>
          <InputText id="name" v-model="name" class="flex-grow flex-auto min-w-0" :readonly="mainProgress > 0" required />
          <label for="name" class="mb-1 mt-4">OpenID Connect redirect path</label>
          <InputText id="name" v-model="redirectPath" class="flex-grow flex-auto min-w-0" :readonly="mainProgress > 0" required />
          <div v-if="unexpectedError" class="mt-4 text-error-600">Unexpected error. Please try again.</div>
          <div v-else-if="updated" class="mt-4 text-success-600">Application updated successfully.</div>
          <div class="mt-4 flex flex-row justify-end">
            <!--
              Button is on purpose not disabled on unexpectedError so that user can retry.
            -->
            <Button
              type="submit"
              primary
              :disabled="name.length === 0 || redirectPath.length === 0 || (application!.name === name && application!.redirectPath === redirectPath) || mainProgress > 0"
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
