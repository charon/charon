<script setup lang="ts">
import type { OrganizationCreate, OrganizationRef } from "@/types"

import { onBeforeUnmount, onMounted, ref, watch } from "vue"
import { useI18n } from "vue-i18n"
import { useRouter } from "vue-router"

import { postJSON } from "@/api"
import Button from "@/components/Button.vue"
import InputText from "@/components/InputText.vue"
import Footer from "@/partials/Footer.vue"
import NavBar from "@/partials/NavBar.vue"
import { useProgress } from "@/progress"

const { t } = useI18n({ useScope: "global" })
const router = useRouter()
const progress = useProgress()

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

function canSubmit(): boolean {
  // Submission is on purpose not disabled on unexpectedError so that user can retry.

  // Required fields.
  return !!name.value
}

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

    await router.push({ name: "OrganizationGet", params: { id: organization.id } })
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("OrganizationCreate.onSubmit", error)
    // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
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
  <div class="mt-12 flex w-full flex-col items-center border-t border-transparent sm:mt-[4.5rem]">
    <div class="m-1 grid auto-rows-auto grid-cols-[minmax(0,65ch)] gap-1 sm:m-4 sm:gap-4">
      <div class="flex w-full flex-col gap-4 rounded-sm border border-gray-200 bg-white p-4 shadow-sm">
        <div class="flex flex-row items-center">
          <h1 class="text-2xl font-bold">{{ t("views.OrganizationCreate.createOrganization") }}</h1>
        </div>
        <form class="flex flex-col" novalidate @submit.prevent="onSubmit">
          <label for="name" class="mb-1">{{ t("views.OrganizationCreate.organizationName") }}</label>
          <InputText id="name" v-model="name" class="min-w-0 flex-auto grow" :progress="progress" required />
          <div v-if="unexpectedError" class="mt-4 text-error-600">{{ t("common.errors.unexpected") }}</div>
          <div v-else class="mt-4">{{ t("views.OrganizationCreate.chooseOrganizationName") }}</div>
          <div class="mt-4 flex flex-row justify-end">
            <Button type="submit" primary :disabled="!canSubmit()" :progress="progress">{{ t("common.buttons.create") }}</Button>
          </div>
        </form>
      </div>
    </div>
  </div>
  <Teleport to="footer">
    <Footer />
  </Teleport>
</template>
