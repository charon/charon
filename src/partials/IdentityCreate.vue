<script setup lang="ts">
import type { IdentityCreate, IdentityRef } from "@/types"

import { onBeforeUnmount, onMounted, ref, watch } from "vue"
import { useI18n } from "vue-i18n"
import { useRouter } from "vue-router"

import { postJSON } from "@/api"
import Button from "@/components/Button.vue"
import InputText from "@/components/InputText.vue"
import TextArea from "@/components/TextArea.vue"
import { injectProgress } from "@/progress"
import { encodeQuery } from "@/utils"

const props = defineProps<{
  flowId?: string
}>()

const $emit = defineEmits<{
  created: [identity: IdentityRef]
}>()

const { t } = useI18n({ useScope: "global" })
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
      query: props.flowId
        ? encodeQuery({
            flow: props.flowId,
          })
        : undefined,
    }).href

    const identity = await postJSON<IdentityRef>(url, payload, abortController.signal, progress)
    if (abortController.signal.aborted) {
      return
    }

    $emit("created", identity)
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
  <form class="flex flex-col" novalidate @submit.prevent="onSubmit">
    <label for="username" class="mb-1"
      >{{ t("common.fields.username") }} <span class="text-sm text-neutral-500 italic">{{ t("common.labels.optional") }}</span></label
    >
    <InputText id="username" v-model="username" class="min-w-0 flex-auto grow" :progress="progress" />
    <label for="email" class="mt-4 mb-1"
      >{{ t("common.fields.email") }} <span class="text-sm text-neutral-500 italic">{{ t("common.labels.optional") }}</span></label
    >
    <InputText id="email" v-model="email" class="min-w-0 flex-auto grow" :progress="progress" />
    <label for="givenName" class="mt-4 mb-1"
      >{{ t("common.fields.givenName") }} <span class="text-sm text-neutral-500 italic">{{ t("common.labels.optional") }}</span></label
    >
    <InputText id="givenName" v-model="givenName" class="min-w-0 flex-auto grow" :progress="progress" />
    <label for="fullName" class="mt-4 mb-1"
      >{{ t("common.fields.fullName") }} <span class="text-sm text-neutral-500 italic">{{ t("common.labels.optional") }}</span></label
    >
    <InputText id="fullName" v-model="fullName" class="min-w-0 flex-auto grow" :progress="progress" />
    <label for="pictureUrl" class="mt-4 mb-1"
      >{{ t("common.fields.pictureUrl") }} <span class="text-sm text-neutral-500 italic">{{ t("common.labels.optional") }}</span></label
    >
    <InputText id="pictureUrl" v-model="pictureUrl" class="min-w-0 flex-auto grow" :progress="progress" />
    <label for="description" class="mt-4 mb-1"
      >{{ t("common.fields.description") }} <span class="text-sm text-neutral-500 italic">{{ t("common.labels.optional") }}</span></label
    >
    <TextArea id="description" v-model="description" class="min-w-0 flex-auto grow" :progress="progress" />
    <div v-if="unexpectedError" class="mt-4 text-error-600">{{ t("common.errors.unexpected") }}</div>
    <div class="mt-4 flex flex-row justify-end">
      <!--
        Button is on purpose not disabled on unexpectedError so that user can retry.
      -->
      <!-- At least something is required. -->
      <Button type="submit" primary :disabled="!username && !email && !givenName && !fullName && !pictureUrl" :progress="progress">{{
        t("common.buttons.create")
      }}</Button>
    </div>
  </form>
</template>
