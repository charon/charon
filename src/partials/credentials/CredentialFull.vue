<script setup lang="ts">
import type { DeepReadonly } from "vue"

import type { CredentialPublic, CredentialUpdateResponse } from "@/types"

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

function canSubmitUpdate(): boolean {
  // Required fields.
  return !!editedDisplayName
}

function onCancel() {
  editedDisplayName.value = ""
  resetOnInteraction()
  emit("canceled")
}

async function onSubmit() {
  if (abortController.signal.aborted) {
    return
  }

  resetOnInteraction()
  progress.value += 1

  progress.value += 1
  try {
    const url = router.apiResolve({
      name: "CredentialUpdateDisplayName",
      params: { id: props.credential.id },
    }).href

    const response = await postJSON<CredentialUpdateResponse>(url, { displayName: editedDisplayName.value }, abortController.signal, progress)
    if (abortController.signal.aborted) {
      return
    }
    if (response.error) {
      // We check if it is an expected error code by trying to get the error message.
      getErrorMessage(response.error)
      updateError.value = response.error
      return
    }

    editedDisplayName.value = ""
    emit("updated")
  } catch (error) {
    if (abortController.signal.aborted) {
      return
    }
    console.error("CredentialFull.submitUpdate", error)
    unexpectedError.value = t("common.errors.unexpected")
  } finally {
    progress.value -= 1
  }
}

function resetOnInteraction() {
  // We reset the error on interaction.
  updateError.value = ""
  unexpectedError.value = ""
}

watch([editedDisplayName], resetOnInteraction)

watch(
  () => props.isEditing,
  async (isEditing) => {
    if (isEditing) {
      editedDisplayName.value = props.credential.displayName
      resetOnInteraction()
      await nextTick(() => {
        document.getElementById(`credentialedit-input-${props.credential.id}`)?.focus()
      })
    } else {
      editedDisplayName.value = ""
      resetOnInteraction()
    }
  },
)
</script>

<template>
  <div class="flex flex-col" :data-url="url">
    <div v-if="!isEditing" class="flex flex-row items-start justify-between gap-4">
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
    <div v-else class="flex flex-row items-start justify-between gap-4">
      <div class="grow">
        <h2 :id="`credentialfull-provider-${credential.id}`" class="text-xl">{{ getProviderNameTitle(t, credential.provider) }}</h2>
        <div class="mt-1 flex flex-row items-center gap-4">
          <InputText :id="`credentialfull-input-${credential.id}`" v-model="editedDisplayName" class="min-w-0 flex-auto grow" :progress="progress" required />
          <Button :id="`credentialfull-button-update-${credential.id}`" type="button" :disabled="!canSubmitUpdate()" :progress="progress" @click="submitUpdate">{{
            t("common.buttons.rename")
          }}</Button>
          <Button :id="`credentialfull-button-cancel-${credential.id}`" type="button" :progress="progress" @click="cancelEdit">{{ t("common.buttons.cancel") }}</Button>
        </div>
      </div>
    </div>
    <div v-if="updateError" class="mt-4 text-error-600">{{ getErrorMessage(updateError) }}</div>
    <div v-else-if="unexpectedError" class="mt-4 text-error-600">{{ t("common.errors.unexpected") }}</div>
  </div>
</template>
