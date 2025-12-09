<script setup lang="ts">
import type { DeepReadonly } from "vue"

import type { CredentialPublic, CredentialResponse } from "@/types"

import { nextTick, ref, watch } from "vue"
import { useI18n } from "vue-i18n"
import { useRouter } from "vue-router"

import { postJSON } from "@/api"
import Button from "@/components/Button.vue"
import InputText from "@/components/InputText.vue"
import { getProviderNameTitle } from "@/flow.ts"
import { injectProgress } from "@/progress"

const props = defineProps<{
  credential: CredentialPublic | DeepReadonly<CredentialPublic>
  url?: string
  isRenaming: boolean
}>()

const emit = defineEmits<{
  renamed: []
  canceled: []
}>()

const { t } = useI18n({ useScope: "global" })
const router = useRouter()

const abortController = new AbortController()
const progress = injectProgress()

const displayName = ref("")
const renameError = ref("")
const unexpectedError = ref("")

function getErrorMessage(errorCode: string) {
  switch (errorCode) {
    case "credentialDisplayNameMissing":
      return t("common.errors.credentialDisplayNameMissing")
    case "credentialDisplayNameInUse":
      return t("common.errors.credentialDisplayNameInUse")
    default:
      throw new Error(`unexpected error code: ${errorCode}`)
  }
}

function canSubmit(): boolean {
  // Required field.
  return !!displayName.value
}

function onCancel() {
  displayName.value = ""
  resetOnInteraction()
  emit("canceled")
}

async function onSubmit() {
  if (abortController.signal.aborted) {
    return
  }

  resetOnInteraction()

  progress.value += 1
  try {
    const url = router.apiResolve({
      name: "CredentialRename",
      params: { id: props.credential.id },
    }).href

    const response = await postJSON<CredentialResponse>(url, { displayName: displayName.value }, abortController.signal, progress)

    if (abortController.signal.aborted) {
      return
    }
    if (response.error) {
      // We check if it is an expected error code by trying to get the error message.
      getErrorMessage(response.error)
      renameError.value = response.error
      return
    }

    displayName.value = ""
    emit("renamed")
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("CredentialFull.onSubmit", error)
    unexpectedError.value = t("common.errors.unexpected")
  } finally {
    progress.value -= 1
  }
}

function resetOnInteraction() {
  // We reset the error on interaction.
  renameError.value = ""
  unexpectedError.value = ""
}

watch([displayName], resetOnInteraction)

watch(
  () => props.isRenaming,
  async (isRenaming) => {
    if (isRenaming) {
      displayName.value = props.credential.displayName
      resetOnInteraction()
      await nextTick(() => {
        document.getElementById(`credentialfull-input-${props.credential.id}`)?.focus()
      })
    } else {
      displayName.value = ""
      resetOnInteraction()
    }
  },
)
</script>

<template>
  <div v-if="!isRenaming" class="flex flex-row items-center justify-between gap-4">
    <div class="grow">
      <h2 :id="`credentialfull-provider-${credential.id}`" class="text-xl">{{ getProviderNameTitle(t, credential.provider) }}</h2>
      <div class="mt-1 flex flex-row items-center gap-1">
        <span>{{ credential.displayName }}</span>
        <span v-if="credential.verified" class="rounded-xs bg-slate-100 px-1.5 py-0.5 text-sm leading-none text-gray-600 shadow-xs">{{
          t("common.labels.verified")
        }}</span>
      </div>
    </div>
    <slot :credential="credential" />
  </div>
  <div v-else class="flex flex-row items-center justify-between gap-4">
    <div class="grow">
      <h2 :id="`credentialfull-provider-${credential.id}`" class="text-xl">{{ getProviderNameTitle(t, credential.provider) }}</h2>
      <form class="mt-1 flex flex-row items-center gap-4" novalidate @submit.prevent="onSubmit" @keyup.esc="onCancel">
        <InputText :id="`credentialfull-input-${credential.id}`" v-model="displayName" class="min-w-0 flex-auto grow" :progress="progress" required />
        <Button :id="`credentialfull-button-update-${credential.id}`" type="submit" primary :disabled="!canSubmit()" :progress="progress">{{
          t("common.buttons.rename")
        }}</Button>
        <Button :id="`credentialfull-button-cancel-${credential.id}`" type="button" :progress="progress" @click="onCancel">{{ t("common.buttons.cancel") }}</Button>
      </form>
    </div>
  </div>
  <div v-if="renameError" class="mt-4 text-error-600">{{ getErrorMessage(renameError) }}</div>
  <div v-else-if="unexpectedError" class="mt-4 text-error-600">{{ t("common.errors.unexpected") }}</div>
</template>
