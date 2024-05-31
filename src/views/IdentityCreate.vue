<script setup lang="ts">
import type { IdentityCreate, IdentityRef } from "@/types"

import { onMounted, onBeforeUnmount, ref, watch } from "vue"
import { useRouter } from "vue-router"
import InputText from "@/components/InputText.vue"
import TextArea from "@/components/TextArea.vue"
import Button from "@/components/Button.vue"
import NavBar from "@/partials/NavBar.vue"
import Footer from "@/partials/Footer.vue"
import { postJSON } from "@/api"
import { injectProgress } from "@/progress"

const router = useRouter()

const progress = injectProgress()

const abortController = new AbortController()

const unexpectedError = ref("")
const username = ref("")
const email = ref("")
const givenName = ref("")
const fullName = ref("")
const pictureUrl = ref("")
const description = ref("")

function resetOnInteraction() {
  // We reset the error on interaction.
  unexpectedError.value = ""
}

watch([username, email, givenName, fullName, pictureUrl, description], resetOnInteraction)

onBeforeUnmount(() => {
  abortController.abort()
})

onMounted(() => {
  document.getElementById("username")?.focus()
})

async function onSubmit() {
  if (abortController.signal.aborted) {
    return
  }

  resetOnInteraction()

  progress.value += 1
  try {
    const payload: IdentityCreate = {
      username: username.value,
      email: email.value,
      givenName: givenName.value,
      fullName: fullName.value,
      pictureUrl: pictureUrl.value,
      description: description.value,
    }
    const url = router.apiResolve({
      name: "IdentityCreate",
    }).href

    const identity = await postJSON<IdentityRef>(url, payload, abortController.signal, progress)
    if (abortController.signal.aborted) {
      return
    }

    router.push({ name: "IdentityGet", params: { id: identity.id } })
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("IdentityCreate.onSubmit", error)
    unexpectedError.value = `${error}`
  } finally {
    progress.value -= 1
  }
}
</script>

<template>
  <Teleport to="header">
    <NavBar></NavBar>
  </Teleport>
  <div class="w-full flex flex-col items-center mt-12 sm:mt-[4.5rem] border-t border-transparent">
    <div class="grid auto-rows-auto grid-cols-[minmax(0,_65ch)] m-1 sm:m-4 gap-1 sm:gap-4">
      <div class="w-full rounded border bg-white p-4 shadow flex flex-col gap-4">
        <div class="flex flex-row items-center">
          <h1 class="text-2xl font-bold">Create identity</h1>
        </div>
        <form class="flex flex-col" novalidate @submit.prevent="onSubmit">
          <label for="username" class="mb-1">Username<span class="text-neutral-500 italic text-sm"> (optional)</span></label>
          <InputText id="username" v-model="username" class="flex-grow flex-auto min-w-0" :progress="progress" />
          <label for="email" class="mb-1 mt-4">E-mail<span class="text-neutral-500 italic text-sm"> (optional)</span></label>
          <InputText id="email" v-model="email" class="flex-grow flex-auto min-w-0" :progress="progress" />
          <label for="givenName" class="mb-1 mt-4">Given name<span class="text-neutral-500 italic text-sm"> (optional)</span></label>
          <InputText id="givenName" v-model="givenName" class="flex-grow flex-auto min-w-0" :progress="progress" />
          <label for="fullName" class="mb-1 mt-4">Full name<span class="text-neutral-500 italic text-sm"> (optional)</span></label>
          <InputText id="fullName" v-model="fullName" class="flex-grow flex-auto min-w-0" :progress="progress" />
          <label for="pictureUrl" class="mb-1 mt-4">Picture URL<span class="text-neutral-500 italic text-sm"> (optional)</span></label>
          <InputText id="pictureUrl" v-model="pictureUrl" class="flex-grow flex-auto min-w-0" :progress="progress" />
          <label for="description" class="mb-1 mt-4">Description<span class="text-neutral-500 italic text-sm"> (optional)</span></label>
          <TextArea id="description" v-model="description" class="flex-grow flex-auto min-w-0" :progress="progress" />
          <div v-if="unexpectedError" class="mt-4 text-error-600">Unexpected error. Please try again.</div>
          <div class="mt-4 flex flex-row justify-end">
            <!--
              Button is on purpose not disabled on unexpectedError so that user can retry.
            -->
            <!-- At least something is required. -->
            <Button type="submit" primary :disabled="!username && !email && !givenName && !fullName && !pictureUrl" :progress="progress">Create</Button>
          </div>
        </form>
      </div>
    </div>
  </div>
  <Teleport to="footer">
    <Footer />
  </Teleport>
</template>
