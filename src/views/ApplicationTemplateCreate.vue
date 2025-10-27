<script setup lang="ts">
import type { ApplicationTemplateCreate, ApplicationTemplateRef } from "@/types"

import { onBeforeUnmount, onMounted, ref, watch } from "vue"
import { useI18n } from "vue-i18n"
import { useRouter } from "vue-router"

import { postJSON } from "@/api"
import Button from "@/components/Button.vue"
import InputText from "@/components/InputText.vue"
import Footer from "@/partials/Footer.vue"
import NavBar from "@/partials/NavBar.vue"
import { injectProgress } from "@/progress"

const { t } = useI18n({ useScope: "global" })
const router = useRouter()
const progress = injectProgress()

const abortController = new AbortController()
const unexpectedError = ref("")
const name = ref("")

function resetOnInteraction() {
  // We reset the error on interaction.
  unexpectedError.value = ""
}

watch([name], resetOnInteraction)

onBeforeUnmount(() => {
  abortController.abort()
})

onMounted(() => {
  document.getElementById("name")?.focus()
})

async function onSubmit() {
  if (abortController.signal.aborted) {
    return
  }

  resetOnInteraction()

  progress.value += 1
  try {
    const payload: ApplicationTemplateCreate = {
      name: name.value,
      idScopes: ["openid"],
    }
    const url = router.apiResolve({
      name: "ApplicationTemplateCreate",
    }).href

    const applicationTemplate = await postJSON<ApplicationTemplateRef>(url, payload, abortController.signal, progress)
    if (abortController.signal.aborted) {
      return
    }

    router.push({ name: "ApplicationTemplateGet", params: { id: applicationTemplate.id } })
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("ApplicationTemplateCreate.onSubmit", error)
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
      <div class="w-full rounded border bg-white p-4 shadow-sm flex flex-col gap-4">
        <div class="flex flex-row items-center">
          <h1 class="text-2xl font-bold">{{ t("views.ApplicationTemplateCreate.createApplicationTemplate") }}</h1>
        </div>
        <form class="flex flex-col" novalidate @submit.prevent="onSubmit">
          <label for="name" class="mb-1">{{ t("views.ApplicationTemplateCreate.applicationTemplateName") }}</label>
          <InputText id="name" v-model="name" class="flex-grow flex-auto min-w-0" :progress="progress" required />
          <div v-if="unexpectedError" class="mt-4 text-error-600">{{ t("common.errors.unexpected") }}</div>
          <div v-else class="mt-4">{{ t("views.ApplicationTemplateCreate.chooseApplicationTemplateName") }}</div>
          <div class="mt-4 flex flex-row justify-end">
            <!--
              Button is on purpose not disabled on unexpectedError so that user can retry.
            -->
            <Button type="submit" primary :disabled="!name" :progress="progress">{{ t("common.buttons.create") }}</Button>
          </div>
        </form>
      </div>
    </div>
  </div>
  <Teleport to="footer">
    <Footer />
  </Teleport>
</template>
