<script setup lang="ts">
import { computed, onUnmounted, ref } from "vue"
import { useRouter } from "vue-router"
import InputText from "@/components/InputText.vue"
import Button from "@/components/Button.vue"
import Footer from "@/components/Footer.vue"
import { ApplicationCreate } from "@/types"
import { postURL } from "@/api"

const router = useRouter()

const mainProgress = ref(0)
const abortController = new AbortController()
const unexpectedError = ref("")
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

onUnmounted(() => {
  abortController.abort()
})

async function onSubmit() {
  mainProgress.value += 1
  try {
    unexpectedError.value = ""
    const payload: ApplicationCreate = {
      name: name.value,
      redirectPaths: redirectPaths.value,
    }
    const url = router.apiResolve({
      name: "ApplicationCreate",
    }).href

    await postURL(url, payload, abortController.signal, mainProgress)

    // TODO: We should somehow inform the user that creation was successful.
    router.push({ name: "Applications" })
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
          <h1 class="text-2xl font-bold">Create application</h1>
        </div>
        <form class="flex flex-col" novalidate @submit.prevent="onSubmit">
          <label for="name" class="mb-1">Application name</label>
          <InputText id="name" v-model="name" class="flex-grow flex-auto min-w-0" :readonly="mainProgress > 0" required />
          <label for="name" class="mb-1 mt-4">OpenID Connect redirect path</label>
          <InputText id="name" v-model="firstRedirectPath" class="flex-grow flex-auto min-w-0" :readonly="mainProgress > 0" required />
          <div v-if="unexpectedError" class="mt-4 text-error-600">Unexpected error. Please try again.</div>
          <div class="mt-4 flex flex-row justify-end">
            <!--
              Button is on purpose not disabled on unexpectedError so that user can retry.
            -->
            <Button type="submit" primary :disabled="name.length === 0 || firstRedirectPath.length === 0 || mainProgress > 0">Create</Button>
          </div>
        </form>
      </div>
    </div>
  </div>
  <Teleport to="footer">
    <Footer />
  </Teleport>
</template>
