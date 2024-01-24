<script setup lang="ts">
import { onBeforeMount, onUnmounted, ref, watch } from "vue"
import { useRouter } from "vue-router"
import InputText from "@/components/InputText.vue"
import Button from "@/components/Button.vue"
import Footer from "@/components/Footer.vue"
import { getURL, postURL } from "@/api"
import { Organization, Metadata } from "@/types"

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
const organization = ref<Organization | null>(null)
const metadata = ref<Metadata>({})
const name = ref("")

watch(name, () => {
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
      name: "Organization",
      params: {
        id: props.id,
      },
    }).href
    const data = await getURL<Organization>(url, null, abortController.signal, mainProgress)
    organization.value = data.doc
    metadata.value = data.metadata
    name.value = data.doc.name
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
    const payload: Organization = {
      id: props.id,
      name: name.value,
    }
    const url = router.apiResolve({
      name: "OrganizationUpdate",
      params: {
        id: props.id,
      },
    }).href

    await postURL(url, payload, abortController.signal, mainProgress)

    // We update organization document state so that we can detect further changes.
    organization.value!.name = payload.name

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
          <span class="font-bold">Organization</span>
        </div>
        <div v-if="dataLoading">Loading...</div>
        <div v-else-if="dataLoadingError" class="text-error-600">Unexpected error. Please try again.</div>
        <form v-else class="flex flex-col" novalidate @submit.prevent="onSubmit">
          <label for="name" class="mb-1">Organization name</label>
          <InputText id="name" v-model="name" class="flex-grow flex-auto min-w-0" :readonly="mainProgress > 0 || !metadata.can_update" required />
          <div v-if="unexpectedError" class="mt-4 text-error-600">Unexpected error. Please try again.</div>
          <div v-else-if="updated" class="mt-4 text-success-600">Organization updated successfully.</div>
          <div v-if="metadata.can_update" class="mt-4 flex flex-row justify-end">
            <!--
              Button is on purpose not disabled on unexpectedError so that user can retry.
            -->
            <Button type="submit" primary :disabled="name.length === 0 || organization!.name === name || mainProgress > 0">Update</Button>
          </div>
        </form>
      </div>
    </div>
  </div>
  <Teleport to="footer">
    <Footer />
  </Teleport>
</template>
