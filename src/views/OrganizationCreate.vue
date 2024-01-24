<script setup lang="ts">
import { onUnmounted, ref } from "vue"
import { useRouter } from "vue-router"
import InputText from "@/components/InputText.vue"
import Button from "@/components/Button.vue"
import Footer from "@/components/Footer.vue"
import { OrganizationCreate } from "@/types"
import { postURL } from "@/api"

const router = useRouter()

const mainProgress = ref(0)
const abortController = new AbortController()
const unexpectedError = ref("")
const name = ref("")

onUnmounted(() => {
  abortController.abort()
})

async function onSubmit() {
  mainProgress.value += 1
  try {
    unexpectedError.value = ""
    const payload: OrganizationCreate = {
      name: name.value,
    }
    const url = router.apiResolve({
      name: "OrganizationCreate",
    }).href

    await postURL(url, payload, abortController.signal, mainProgress)

    // TODO: We should somehow inform the user that creation was successful.
    router.push({ name: "Organizations" })
    // We increase the progress and never decrease it to wait for browser to do the redirect.
    mainProgress.value += 1
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
          <span class="font-bold">Create organization</span>
        </div>
        <form class="flex flex-col" novalidate @submit.prevent="onSubmit">
          <label for="name" class="mb-1">Organization name</label>
          <InputText id="name" v-model="name" class="flex-grow flex-auto min-w-0" :readonly="mainProgress > 0" required />
          <div class="mt-4 flex flex-row justify-end">
            <!--
              Button is on purpose not disabled on unexpectedError so that user can retry.
            -->
            <Button type="submit" primary :disabled="name.length === 0 || mainProgress > 0">Create</Button>
          </div>
        </form>
      </div>
    </div>
  </div>
  <Teleport to="footer">
    <Footer />
  </Teleport>
</template>
