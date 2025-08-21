<script setup lang="ts">
import type { OrganizationCreate, OrganizationRef } from "@/types"

import { onMounted, onBeforeUnmount, ref, watch } from "vue"
import { useI18n } from "vue-i18n"
import { useRouter } from "vue-router"
import InputText from "@/components/InputText.vue"
import Button from "@/components/Button.vue"
import NavBar from "@/partials/NavBar.vue"
import Footer from "@/partials/Footer.vue"
import { postJSON } from "@/api"
import { injectProgress } from "@/progress"

const { t } = useI18n()
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
    const payload: OrganizationCreate = {
      name: name.value,
    }
    const url = router.apiResolve({
      name: "OrganizationCreate",
    }).href

    const organization = await postJSON<OrganizationRef>(url, payload, abortController.signal, progress)
    if (abortController.signal.aborted) {
      return
    }

    router.push({ name: "OrganizationGet", params: { id: organization.id } })
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("OrganizationCreate.onSubmit", error)
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
          <h1 class="text-2xl font-bold">{{ t("titles.createOrganization") }}</h1>
        </div>
        <form class="flex flex-col" novalidate @submit.prevent="onSubmit">
          <label for="name" class="mb-1">{{ t("labels.organizationName") }}</label>
          <InputText id="name" v-model="name" class="flex-grow flex-auto min-w-0" :progress="progress" required />
          <div v-if="unexpectedError" class="mt-4 text-error-600">{{ t("common.errors.unexpected") }}</div>
          <div v-else class="mt-4">Choose a name. You will be able to configure the organization after it is created.</div>
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
